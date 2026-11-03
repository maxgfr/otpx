// Adding accounts: camera, image, paste, manual entry.

import { type Scanner, scan } from '../camera';
import { h, icon, mount } from '../dom';
import { t } from '../i18n';
import { app } from '../state';
import { button, bytesOf, field, input, notice, pageHead, select, toast } from '../ui';
import { core, type ImportResult, message } from '../wasm';

type Tab = 'scan' | 'image' | 'paste' | 'manual';

/** Explains an import result in one notice. */
export function report(r: ImportResult): HTMLElement {
  const parts = [t('add.done', { added: r.added })];
  if (r.duplicates) parts.push(t('add.duplicates', { n: r.duplicates }));
  if (r.missing.length) parts.push(t('add.missing', { list: r.missing.map((i) => i + 1).join(', ') }));
  if (r.skipped.length) parts.push(t('add.skipped', { list: r.skipped.join('; ') }));
  return notice(
    parts.join(' '),
    r.added || r.duplicates ? (r.missing.length || r.skipped.length ? 'warn' : 'proof') : 'error',
  );
}

export function add(main: HTMLElement, initial: Tab = 'scan'): () => void {
  let tab: Tab = initial;
  let scanner: Scanner | null = null;
  const stop = () => {
    scanner?.stop();
    scanner = null;
  };
  const panel = h('div', { class: 'tab-panel', role: 'tabpanel' });
  const status = h('div', { class: 'form-status', 'aria-live': 'polite' });
  const tabs: [Tab, string, Parameters<typeof icon>[0]][] = [
    ['scan', t('add.scan'), 'camera'],
    ['image', t('add.image'), 'image'],
    ['paste', t('add.paste'), 'link'],
    ['manual', t('add.manual'), 'edit'],
  ];
  const bar = h('div', { class: 'tabs', role: 'tablist', 'aria-label': t('add.title') });
  const added = async (r: ImportResult) => {
    if (r.added) await app.save();
    mount(status, report(r));
  };
  const addText = async (text: string) => {
    const v = app.vault;
    if (!v) return;
    try {
      await added(JSON.parse(v.addText(text, Date.now(), app.device.id)) as ImportResult);
    } catch (e) {
      mount(status, notice(message(e), 'error'));
    }
  };
  const renderTabs = () => {
    mount(
      bar,
      ...tabs.map(([id, label, ic]) =>
        h(
          'button',
          {
            type: 'button',
            role: 'tab',
            class: 'tab',
            'aria-selected': String(id === tab),
            tabindex: id === tab ? '0' : '-1',
            onclick: (() => {
              tab = id;
              render();
            }) as EventListener,
          },
          icon(ic),
          h('span', {}, label),
        ),
      ),
    );
  };
  bar.addEventListener('keydown', (e) => {
    const i = tabs.findIndex(([id]) => id === tab);
    const d = e.key === 'ArrowRight' ? 1 : e.key === 'ArrowLeft' ? -1 : 0;
    if (!d) return;
    tab = tabs[(i + d + tabs.length) % tabs.length]?.[0] ?? tab;
    render();
    (bar.querySelector('[aria-selected="true"]') as HTMLElement | null)?.focus();
  });
  const render = () => {
    stop();
    mount(status);
    renderTabs();
    if (tab === 'scan') {
      const video = h('video', { class: 'scanner', 'aria-label': t('add.scan') });
      const frame = h(
        'div',
        { class: 'scanner-frame' },
        video,
        h('span', { class: 'scanner-aim', 'aria-hidden': 'true' }),
      );
      const start = button(
        t('add.scan.start'),
        async () => {
          try {
            scanner = await scan(video, (texts) => {
              const migration = texts.filter((x) => x.startsWith('otpauth-migration://'));
              void addText(texts.join('\n'));
              if (migration.length) toast(t('add.scan.found', { n: texts.length }));
            });
            frame.classList.add('is-live');
            mount(
              controls,
              button(
                t('add.scan.stop'),
                () => {
                  stop();
                  frame.classList.remove('is-live');
                  mount(controls, start);
                },
                { icon: 'close' },
              ),
            );
          } catch {
            mount(status, notice(t('add.scan.denied'), 'error'));
          }
        },
        { kind: 'primary', icon: 'camera' },
      );
      const controls = h('div', { class: 'actions' }, start);
      mount(panel, h('p', { class: 'lead' }, t('add.scan.lead')), frame, controls);
    } else if (tab === 'image') {
      const picker = h('input', { type: 'file', accept: 'image/*', multiple: true, class: 'file-input' });
      picker.addEventListener('change', async () => {
        const found: string[] = [];
        for (const f of picker.files ?? []) {
          try {
            found.push(...(JSON.parse(core.decodeQrImage(await bytesOf(f))) as string[]));
          } catch {
            /* not an image */
          }
        }
        if (!found.length) {
          mount(status, notice(t('add.image.none'), 'error'));
          return;
        }
        await addText(found.join('\n'));
      });
      mount(
        panel,
        h('p', { class: 'lead' }, t('add.image.lead')),
        h(
          'label',
          { class: 'btn btn-primary file-label' },
          icon('image'),
          h('span', {}, t('add.image.pick')),
          picker,
        ),
      );
    } else if (tab === 'paste') {
      const area = h('textarea', {
        rows: '4',
        spellcheck: 'false',
        autocomplete: 'off',
        placeholder: 'otpauth://totp/…',
      });
      mount(
        panel,
        h(
          'form',
          {
            class: 'form',
            onsubmit: ((e: Event) => {
              e.preventDefault();
              void addText(area.value);
            }) as EventListener,
          },
          h('p', { class: 'lead' }, t('add.paste.lead')),
          field(t('add.paste.label'), area),
          h(
            'div',
            { class: 'actions' },
            button(t('add.paste.submit'), () => {}, { kind: 'primary', type: 'submit', icon: 'plus' }),
          ),
        ),
      );
      area.focus();
    } else {
      const issuer = input({ required: true });
      const acct = input({});
      const secret = input({ required: true, autocapitalize: 'characters' });
      const type = select(
        [
          ['totp', 'TOTP'],
          ['hotp', 'HOTP'],
          ['steam', 'Steam'],
        ],
        'totp',
      );
      const digits = select(
        [
          ['6', '6'],
          ['8', '8'],
        ],
        '6',
      );
      const algo = select(
        [
          ['SHA1', 'SHA-1'],
          ['SHA256', 'SHA-256'],
          ['SHA512', 'SHA-512'],
        ],
        'SHA1',
      );
      const period = input({ type: 'number', value: '30', min: '1', inputmode: 'numeric' });
      mount(
        panel,
        h(
          'form',
          {
            class: 'form',
            onsubmit: (async (e: Event) => {
              e.preventDefault();
              const v = app.vault;
              if (!v) return;
              try {
                v.addManual(
                  JSON.stringify({
                    issuer: issuer.value,
                    account: acct.value,
                    secret: secret.value,
                    type: type.value,
                    digits: Number(digits.value),
                    algorithm: algo.value,
                    period: Number(period.value),
                  }),
                  Date.now(),
                  app.device.id,
                );
                await app.save();
                toast(t('add.done', { added: 1 }));
                location.hash = '#/';
              } catch (err) {
                mount(status, notice(message(err), 'error'));
              }
            }) as EventListener,
          },
          field(t('add.manual.issuer'), issuer),
          field(t('add.manual.account'), acct),
          field(t('add.manual.secret'), secret, t('add.manual.secret.hint')),
          h(
            'details',
            { class: 'advanced' },
            h('summary', {}, t('edit.advanced')),
            h(
              'div',
              { class: 'grid-2' },
              field(t('edit.type'), type),
              field(t('edit.digits'), digits),
              field(t('edit.algorithm'), algo),
              field(t('edit.period'), period),
            ),
          ),
          h(
            'div',
            { class: 'actions' },
            button(t('add.manual.submit'), () => {}, { kind: 'primary', type: 'submit', icon: 'plus' }),
          ),
        ),
      );
      issuer.focus();
    }
  };
  mount(
    main,
    h(
      'section',
      { class: 'narrow' },
      pageHead(t('add.title'), { href: '#/', label: t('nav.home') }),
      bar,
      panel,
      status,
    ),
  );
  render();
  return stop;
}
