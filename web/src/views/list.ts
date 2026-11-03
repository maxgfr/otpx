// The board: every account a tag, codes live, a tap copies.

import { copy } from '../clipboard';
import { groupCode, h, icon, mount } from '../dom';
import { t } from '../i18n';
import { app } from '../state';
import { eyelet, setEyelet, toast } from '../ui';
import { type Account, accounts, codes, message } from '../wasm';

export const search = { query: '' };

function matches(a: Account, q: string): boolean {
  const s = q.trim().toLowerCase();
  if (!s) return true;
  return [a.issuer, a.account, a.label, a.note, ...a.tags].some((x) => x.toLowerCase().includes(s));
}

export function clearSecs(): number {
  if (!app.vault) return 20;
  return (JSON.parse(app.vault.settings()) as { clipboard_clear_secs: number }).clipboard_clear_secs;
}

/** Copies the current code of `a`, or uses the next HOTP code. Returns the code. */
export async function copyCode(a: Account, tag?: HTMLElement): Promise<string | null> {
  const v = app.vault;
  if (!v) return null;
  let code: string;
  if (a.type === 'hotp') {
    try {
      code = v.useHotp(a.id, Date.now(), app.device.id);
      await app.save();
    } catch (e) {
      toast(message(e), 'error');
      return null;
    }
  } else {
    code = codes(v, Date.now() / 1000).get(a.id)?.code ?? '';
  }
  const secs = clearSecs();
  const ok = await copy(code, secs, () => {
    tag?.classList.remove('is-copied');
    toast(t('copied.cleared'));
  });
  if (!ok) {
    toast(t('copy.failed'), 'error');
    return code;
  }
  for (const el of document.querySelectorAll('.is-copied')) el.classList.remove('is-copied');
  tag?.classList.add('is-copied');
  toast(secs > 0 ? t('copied.clears', { s: secs }) : t('copied'));
  return code;
}

export function list(main: HTMLElement): () => void {
  const v = app.vault;
  if (!v) return () => {};
  const all = accounts(v);
  const ul = h('ul', { class: 'board', 'aria-label': t('nav.home') });
  const rows = new Map<
    string,
    {
      li: HTMLLIElement;
      code: HTMLElement;
      next: HTMLElement;
      eye: HTMLElement;
      secs: HTMLElement;
      a: Account;
    }
  >();
  const render = () => {
    const shown = all.filter((a) => matches(a, search.query));
    mount(ul);
    rows.clear();
    if (!all.length) {
      mount(
        main,
        h(
          'section',
          { class: 'empty' },
          h('h1', { tabindex: '-1' }, t('list.empty.title')),
          h('p', { class: 'lead' }, t('list.empty.lead')),
          h(
            'div',
            { class: 'actions' },
            h(
              'a',
              { class: 'btn btn-primary', href: '#/add' },
              icon('plus'),
              h('span', {}, t('list.empty.add')),
            ),
            h(
              'a',
              { class: 'btn btn-plain', href: '#/transfer' },
              icon('upload'),
              h('span', {}, t('list.empty.import')),
            ),
          ),
        ),
      );
      return;
    }
    for (const a of shown) {
      const eye = eyelet();
      const secs = h('span', { class: 'eyelet-secs' });
      eye.querySelector('.eyelet-hole')?.append(secs);
      const code = h('span', { class: 'code' });
      const next = h('span', { class: 'next' });
      const copiedMark = h('span', { class: 'copied-mark' }, icon('check'), h('span', {}, t('copied')));
      const li = h('li', { class: 'tag', 'data-id': a.id });
      const hit = h(
        'button',
        { type: 'button', class: 'tag-hit', 'aria-label': t('list.copy', { label: a.label }) },
        eye,
        h(
          'span',
          { class: 'tag-name' },
          h(
            'strong',
            {},
            a.favorite ? h('span', { class: 'fav' }, icon('star')) : null,
            a.issuer || a.account,
          ),
          a.issuer && a.account ? h('span', { class: 'tag-account' }, a.account) : null,
        ),
        h('span', { class: 'tag-code' }, code, next, copiedMark),
      );
      hit.addEventListener('click', () => void copyCode(a, li).then(() => tick()));
      li.append(
        hit,
        h(
          'a',
          { class: 'tag-open', href: `#/a/${a.id}`, 'aria-label': t('list.open', { label: a.label }) },
          icon('chevron'),
        ),
      );
      ul.append(li);
      rows.set(a.id, { li, code, next, eye, secs, a });
    }
    const body: Node[] = [ul];
    if (!shown.length) body.push(h('p', { class: 'nomatch' }, t('list.nomatch', { q: search.query })));
    mount(main, h('h1', { class: 'sr-only', tabindex: '-1' }, t('nav.home')), ...body);
    tick();
  };
  const tick = () => {
    const vault = app.vault;
    if (!vault) return;
    const now = Date.now() / 1000;
    const cs = codes(vault, now);
    for (const [id, r] of rows) {
      const c = cs.get(id);
      if (!c) continue;
      if (r.a.type === 'hotp') {
        r.code.textContent = '••• •••';
        r.next.textContent = t('list.hotp.hint');
        r.secs.textContent = '';
        setEyelet(r.eye, 0, 0);
        continue;
      }
      // Fractional seconds keep the rim moving smoothly between whole seconds.
      const exact = c.period - (now % c.period);
      const grouped = groupCode(c.code);
      if (r.code.textContent !== grouped) r.code.textContent = grouped;
      const nx = c.next ? t('list.next', { code: groupCode(c.next) }) : '';
      if (r.next.textContent !== nx) r.next.textContent = nx;
      r.secs.textContent = String(c.remaining);
      setEyelet(r.eye, exact, c.period);
    }
  };
  render();
  const timer = setInterval(tick, 250);
  const onSearch = () => render();
  document.addEventListener('otpx:search', onSearch);
  const onEnter = () => {
    const first = all.find((a) => matches(a, search.query));
    if (first) void copyCode(first, rows.get(first.id)?.li);
  };
  document.addEventListener('otpx:search-enter', onEnter);
  return () => {
    clearInterval(timer);
    document.removeEventListener('otpx:search', onSearch);
    document.removeEventListener('otpx:search-enter', onEnter);
  };
}
