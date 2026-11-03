//! The interactive view: live codes, search, copy, QR, add, delete, sync.

use std::process::ExitCode;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use otpx_core::model::{Entry, Kind, sort_entries};
use ratatui::Frame;
use ratatui::layout::{Constraint, Layout, Rect};
use ratatui::style::{Modifier, Style, Stylize};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph};

use crate::cmd::group_code;
use crate::session::{self, Session};
use crate::{Ctx, clipboard, core_failure, exit, fail, now_ms, now_secs, ui};

enum Mode {
    Normal,
    Search,
    Add(String),
    Qr(String, String),
    ConfirmDelete(String),
}

struct App {
    session: Session,
    query: String,
    state: ListState,
    mode: Mode,
    status: Option<(String, Instant)>,
    show_next: bool,
    dirty: bool,
}

impl App {
    fn visible(&self) -> Vec<Entry> {
        let mut v: Vec<&Entry> = self
            .session
            .vault
            .data
            .entries
            .iter()
            .filter(|e| e.matches(&self.query))
            .collect();
        sort_entries(&mut v);
        v.into_iter().cloned().collect()
    }

    fn selected(&self) -> Option<Entry> {
        let v = self.visible();
        self.state.selected().and_then(|i| v.get(i).cloned())
    }

    fn flash(&mut self, msg: impl Into<String>) {
        self.status = Some((msg.into(), Instant::now()));
    }
}

/// Runs the interactive view.
pub fn run(ctx: &Ctx) -> anyhow::Result<ExitCode> {
    if !ui::interactive() {
        return Err(fail(
            exit::USAGE,
            "the interactive view needs a terminal (try `otpx ls`)",
        ));
    }
    let session = session::open(ctx)?;
    let mut app = App {
        session,
        query: String::new(),
        state: ListState::default(),
        mode: Mode::Normal,
        status: None,
        show_next: false,
        dirty: false,
    };
    app.state.select(Some(0));
    let mut terminal = ratatui::init();
    let res = event_loop(ctx, &mut terminal, &mut app);
    ratatui::restore();
    if app.dirty {
        session::save(ctx, &mut app.session)?;
    }
    res.map(|()| ExitCode::SUCCESS)
}

fn event_loop(
    ctx: &Ctx,
    terminal: &mut ratatui::DefaultTerminal,
    app: &mut App,
) -> anyhow::Result<()> {
    loop {
        terminal.draw(|f| draw(f, ctx, app))?;
        if !event::poll(Duration::from_millis(250))? {
            continue;
        }
        let Event::Key(key) = event::read()? else {
            continue;
        };
        if key.kind != KeyEventKind::Press {
            continue;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            return Ok(());
        }
        if handle(ctx, app, key)? {
            return Ok(());
        }
    }
}

/// Returns true to quit.
fn handle(ctx: &Ctx, app: &mut App, key: KeyEvent) -> anyhow::Result<bool> {
    let len = app.visible().len();
    match &mut app.mode {
        Mode::Search => match key.code {
            KeyCode::Esc => {
                app.query.clear();
                app.mode = Mode::Normal;
            }
            KeyCode::Enter => app.mode = Mode::Normal,
            KeyCode::Backspace => {
                app.query.pop();
            }
            KeyCode::Char(c) => {
                app.query.push(c);
                app.state.select(Some(0));
            }
            KeyCode::Down => app.state.select_next(),
            KeyCode::Up => app.state.select_previous(),
            _ => {}
        },
        Mode::Add(buf) => match key.code {
            KeyCode::Esc => app.mode = Mode::Normal,
            KeyCode::Backspace => {
                buf.pop();
            }
            KeyCode::Char(c) => buf.push(c),
            KeyCode::Enter => {
                let text = std::mem::take(buf);
                app.mode = Mode::Normal;
                match otpx_core::formats::import(
                    text.as_bytes(),
                    otpx_core::formats::Format::Uris,
                    None,
                ) {
                    Ok(got) if !got.entries.is_empty() => {
                        let device = ctx.config().device_id;
                        let mut n = 0;
                        for e in got.entries {
                            if app
                                .session
                                .vault
                                .data
                                .add_unique(e, now_ms(), &device)
                                .map_err(core_failure)?
                            {
                                n += 1;
                            }
                        }
                        app.dirty |= n > 0;
                        app.flash(format!("Added {n} account(s)"));
                    }
                    Ok(_) => app.flash("No otpauth:// URI in that text"),
                    Err(e) => app.flash(format!("Not added: {e}")),
                }
            }
            _ => {}
        },
        Mode::Qr(..) => app.mode = Mode::Normal,
        Mode::ConfirmDelete(id) => {
            let id = id.clone();
            app.mode = Mode::Normal;
            if key.code == KeyCode::Char('y') {
                let device = ctx.config().device_id;
                let e = app
                    .session
                    .vault
                    .data
                    .remove(&id, now_ms(), &device)
                    .map_err(core_failure)?;
                app.dirty = true;
                app.flash(format!(
                    "Deleted {} (undo: otpx backup restore 1 --only {})",
                    e.label(),
                    &id[..8]
                ));
            } else {
                app.flash("Kept");
            }
        }
        Mode::Normal => match key.code {
            KeyCode::Char('q') | KeyCode::Esc => {
                if !app.query.is_empty() && key.code == KeyCode::Esc {
                    app.query.clear();
                } else {
                    return Ok(true);
                }
            }
            KeyCode::Down | KeyCode::Char('j') => app.state.select_next(),
            KeyCode::Up | KeyCode::Char('k') => app.state.select_previous(),
            KeyCode::Home | KeyCode::Char('g') => app.state.select_first(),
            KeyCode::End | KeyCode::Char('G') => app.state.select(Some(len.saturating_sub(1))),
            KeyCode::Char('/') => app.mode = Mode::Search,
            KeyCode::Char('a') => app.mode = Mode::Add(String::new()),
            KeyCode::Char('n') => app.show_next = !app.show_next,
            KeyCode::Enter | KeyCode::Char('c') | KeyCode::Char('y') => {
                if let Some(e) = app.selected() {
                    let code = if e.kind == Kind::Hotp {
                        let device = ctx.config().device_id;
                        let c = e.code_at(0).code;
                        app.session
                            .vault
                            .data
                            .advance_counter(&e.id, now_ms(), &device)
                            .map_err(core_failure)?;
                        app.dirty = true;
                        c
                    } else {
                        e.code_at(now_secs()).code
                    };
                    let secs = u64::from(app.session.vault.data.settings.clipboard_clear_secs);
                    match clipboard::copy(&code, secs) {
                        Ok(()) => app.flash(format!("Copied {} (cleared in {secs}s)", e.label())),
                        Err(err) => app.flash(format!("Copy failed: {err}")),
                    }
                }
            }
            KeyCode::Char('Q') | KeyCode::Char('r') => {
                if let Some(e) = app.selected() {
                    match otpx_core::qr::terminal(&otpx_core::uri::to_uri(&e)) {
                        Ok(q) => app.mode = Mode::Qr(e.label(), q),
                        Err(err) => app.flash(format!("QR: {err}")),
                    }
                }
            }
            KeyCode::Char('f') => {
                if let Some(mut e) = app.selected() {
                    e.favorite = !e.favorite;
                    let device = ctx.config().device_id;
                    app.session
                        .vault
                        .data
                        .update(e, now_ms(), &device)
                        .map_err(core_failure)?;
                    app.dirty = true;
                }
            }
            KeyCode::Char('d') | KeyCode::Delete => {
                if let Some(e) = app.selected() {
                    app.mode = Mode::ConfirmDelete(e.id.clone());
                }
            }
            KeyCode::Char('s') => {
                if ctx.config().remotes.is_empty() {
                    app.flash("No remote: otpx sync setup …");
                } else {
                    app.flash("Syncing…");
                    match crate::sync::sync_all(ctx, &mut app.session, None) {
                        Ok(done) => {
                            app.dirty = false;
                            app.flash(format!("Synced with {} remote(s)", done.len()));
                        }
                        Err(e) => app.flash(format!("Sync failed: {e:#}")),
                    }
                }
            }
            KeyCode::Char('l') => {
                session::forget(ctx)?;
                return Ok(true);
            }
            _ => {}
        },
    }
    let len = app.visible().len();
    if len == 0 {
        app.state.select(None);
    } else if app.state.selected().is_none_or(|i| i >= len) {
        app.state.select(Some(len - 1));
    }
    Ok(false)
}

fn bar(remaining: u32, period: u32, width: usize) -> String {
    if period == 0 {
        return " ".repeat(width);
    }
    let filled = (remaining as usize * width)
        .div_ceil(period as usize)
        .min(width);
    format!("{}{}", "━".repeat(filled), "╌".repeat(width - filled))
}

fn draw(f: &mut Frame<'_>, ctx: &Ctx, app: &mut App) {
    let area = f.area();
    let [head, body, foot] = Layout::vertical([
        Constraint::Length(2),
        Constraint::Min(3),
        Constraint::Length(2),
    ])
    .areas(area);
    let n = app.session.vault.data.entries.len();
    let cfg = ctx.config();
    let sync = match cfg.remotes.iter().map(|r| r.last_sync).max() {
        None => "not synced: otpx sync setup".to_owned(),
        Some(0) => "never synced".to_owned(),
        Some(t) => format!(
            "synced {} ago",
            crate::human_duration(now_ms().saturating_sub(t) / 1000)
        ),
    };
    let search = match app.mode {
        Mode::Search => Span::styled(format!("  / {}▏", app.query), Style::new().bold()),
        _ if !app.query.is_empty() => Span::raw(format!("  / {}", app.query)),
        _ => Span::raw(""),
    };
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled("otpx", Style::new().bold()),
            Span::raw(format!("  {n} account(s) · {sync}")).dim(),
            search,
        ]))
        .block(
            Block::new()
                .borders(Borders::BOTTOM)
                .border_style(Style::new().dim()),
        ),
        head,
    );
    let now = now_secs();
    let entries = app.visible();
    let width = usize::from(body.width);
    let items: Vec<ListItem<'_>> = entries
        .iter()
        .map(|e| {
            let star = if e.favorite { "★ " } else { "  " };
            let (code, remaining, period) = if e.kind == Kind::Hotp {
                ("••• •••".to_owned(), 0, 0)
            } else {
                let c = e.code_at(now);
                (group_code(&c.code), c.remaining, c.period)
            };
            let next = if app.show_next && e.kind != Kind::Hotp {
                format!("  → {}", group_code(&e.next_code_at(now).code))
            } else {
                String::new()
            };
            let label_w = width.saturating_sub(34).max(10);
            let issuer = ui::clean(if e.issuer.is_empty() {
                &e.account
            } else {
                &e.issuer
            })
            .into_owned();
            let account = if e.issuer.is_empty() {
                String::new()
            } else {
                ui::clean(&e.account).into_owned()
            };
            let label: String = format!("{issuer}  {account}")
                .chars()
                .take(label_w)
                .collect();
            let pad = label_w.saturating_sub(label.chars().count());
            let urgent = period > 0 && remaining <= 5;
            let code_style = if urgent {
                Style::new().bold().add_modifier(Modifier::DIM)
            } else {
                Style::new().bold()
            };
            ListItem::new(Line::from(vec![
                Span::raw(star),
                Span::styled(
                    issuer.chars().take(label_w).collect::<String>(),
                    Style::new().bold(),
                ),
                Span::raw(
                    label
                        .chars()
                        .skip(issuer.chars().count().min(label_w))
                        .collect::<String>(),
                )
                .dim(),
                Span::raw(" ".repeat(pad)),
                Span::styled(format!("{code:>9}"), code_style),
                Span::raw("  "),
                Span::raw(if e.kind == Kind::Hotp {
                    "  hotp    ".to_owned()
                } else {
                    format!("{} {remaining:>2}s", bar(remaining, period, 6))
                })
                .dim(),
                Span::raw(next).dim(),
            ]))
        })
        .collect();
    let empty = items.is_empty();
    f.render_stateful_widget(
        List::new(items).highlight_style(Style::new().reversed()),
        body,
        &mut app.state,
    );
    if empty {
        let msg = if n == 0 {
            "No account yet. Press a to paste an otpauth:// URI, or run `otpx import`."
        } else {
            "No account matches."
        };
        f.render_widget(Paragraph::new(msg).dim(), body);
    }
    let keys = match app.mode {
        Mode::Normal => {
            "↑↓ move  ⏎ copy  / search  n next  r QR  a add  f favorite  d delete  s sync  l lock  q quit"
        }
        Mode::Search => "type to filter  ⏎ keep  esc clear",
        Mode::Add(_) => "paste an otpauth:// URI  ⏎ add  esc cancel",
        Mode::Qr(..) => "any key closes",
        Mode::ConfirmDelete(_) => "y delete  any other key keeps it",
    };
    let status = match &app.status {
        Some((m, t)) if t.elapsed() < Duration::from_secs(4) => m.clone(),
        _ => String::new(),
    };
    f.render_widget(
        Paragraph::new(vec![Line::from(status).bold(), Line::from(keys).dim()]),
        foot,
    );
    match &app.mode {
        Mode::Qr(label, q) => {
            let h = u16::try_from(q.lines().count() + 3)
                .unwrap_or(u16::MAX)
                .min(area.height);
            let w = u16::try_from(q.lines().next().map_or(0, |l| l.chars().count()) + 4)
                .unwrap_or(u16::MAX)
                .min(area.width);
            let r = centered(area, w, h);
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(q.as_str())
                    .block(Block::bordered().title(format!(" {} ", ui::clean(label)))),
                r,
            );
        }
        Mode::Add(buf) => {
            let r = centered(area, area.width.saturating_sub(4).min(90), 3);
            f.render_widget(Clear, r);
            let shown: String = buf
                .chars()
                .rev()
                .take(usize::from(r.width.saturating_sub(4)))
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            f.render_widget(
                Paragraph::new(format!("{shown}▏"))
                    .block(Block::bordered().title(" otpauth:// URI ")),
                r,
            );
        }
        Mode::ConfirmDelete(id) => {
            let label = app
                .session
                .vault
                .data
                .entries
                .iter()
                .find(|e| &e.id == id)
                .map(Entry::label)
                .unwrap_or_default();
            let r = centered(area, area.width.saturating_sub(4).min(70), 3);
            f.render_widget(Clear, r);
            f.render_widget(
                Paragraph::new(format!("Delete {}? (y/N)", ui::clean(&label)))
                    .block(Block::bordered()),
                r,
            );
        }
        _ => {}
    }
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    Rect {
        x: area.x + area.width.saturating_sub(w) / 2,
        y: area.y + area.height.saturating_sub(h) / 2,
        width: w.min(area.width),
        height: h.min(area.height),
    }
}
