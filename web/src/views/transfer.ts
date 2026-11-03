// Import from other apps, export to them, move to a phone.

import { h, icon, mount, rich, svgUrl } from '../dom';
import { t } from '../i18n';
import { app } from '../state';
import { button, bytesOf, download, field, input, notice, pageHead, select } from '../ui';
import { core, type ImportResult, message } from '../wasm';
import { report } from './add';

export function transfer(main: HTMLElement): void {
  const v = app.vault;
  if (!v) return;
  const importStatus = h('div', { class: 'form-status', 'aria-live': 'polite' });
  const picker = h('input', { type: 'file', multiple: true, class: 'file-input' });
  const importFiles = async (files: File[], password?: string) => {
    const results: HTMLElement[] = [];
    let changed = false;
    for (const f of files) {
      try {
        const r = JSON.parse(
          v.importBytes(await bytesOf(f), 'auto', password, Date.now(), app.device.id),
        ) as ImportResult;
        changed ||= r.added > 0;
        results.push(h('p', { class: 'file-name' }, f.name), report(r));
      } catch (e) {
        const m = message(e);
        if (m.startsWith('needs-password:')) {
          const fmt = m.slice('needs-password:'.length);
          const pw = input({ type: 'password', autocomplete: 'off', required: true });
          const form = h(
            'form',
            {
              class: 'form',
              onsubmit: ((ev: Event) => {
                ev.preventDefault();
                void importFiles([f], pw.value);
              }) as EventListener,
            },
            field(t('transfer.import.password', { format: fmt }), pw),
            h(
              'div',
              { class: 'actions' },
              button(t('transfer.import.submit'), () => {}, { kind: 'primary', type: 'submit' }),
            ),
          );
          results.push(h('p', { class: 'file-name' }, f.name), form);
          setTimeout(() => pw.focus(), 0);
        } else {
          results.push(h('p', { class: 'file-name' }, f.name), notice(m, 'error'));
        }
      }
    }
    if (changed) await app.save();
    mount(importStatus, ...results);
  };
  picker.addEventListener('change', () => void importFiles([...(picker.files ?? [])]));

  const formats = JSON.parse(core.exportFormats()) as [string, string][];
  const fmt = select(
    formats.map(([n, d]) => [n, d] as [string, string]),
    'aegis',
  );
  const pw = input({ type: 'password', autocomplete: 'new-password' });
  const exportStatus = h('div', { class: 'form-status', 'aria-live': 'polite' });
  const exportForm = h(
    'form',
    {
      class: 'form',
      onsubmit: ((e: Event) => {
        e.preventDefault();
        try {
          const name = fmt.value;
          const body = v.export(name, '', name === 'aegis' && pw.value ? pw.value : undefined, Date.now());
          const ext: Record<string, string> = {
            uris: 'txt',
            google: 'txt',
            aegis: 'json',
            '2fas': '2fas',
            andotp: 'json',
            bitwarden: 'json',
            csv: 'csv',
            paper: 'html',
          };
          download(`otpx-${name}.${ext[name] ?? 'txt'}`, body, name === 'paper' ? 'text/html' : 'text/plain');
          mount(exportStatus);
        } catch (err) {
          mount(exportStatus, notice(message(err), 'error'));
        }
      }) as EventListener,
    },
    field(t('transfer.export.format'), fmt),
    field(t('transfer.export.password'), pw),
    h(
      'div',
      { class: 'actions' },
      button(t('transfer.export.submit'), () => {}, { kind: 'primary', type: 'submit', icon: 'download' }),
    ),
  );

  const phone = h('div', { class: 'phone-out' });
  const showPhone = () => {
    const g = JSON.parse(v.googleTransfer('')) as { codes: string[]; left_out: string[] };
    let i = 0;
    const step = () => {
      const c = g.codes[i];
      if (!c) {
        mount(phone);
        return;
      }
      mount(
        phone,
        h('p', { class: 'meta' }, t('transfer.phone.step', { i: i + 1, n: g.codes.length })),
        h('img', {
          class: 'qr qr-large',
          alt: t('transfer.phone.step', { i: i + 1, n: g.codes.length }),
          src: svgUrl(core.qrSvg(c)),
          width: '320',
          height: '320',
        }),
        h(
          'div',
          { class: 'actions' },
          i + 1 < g.codes.length
            ? button(
                t('transfer.phone.next'),
                () => {
                  i += 1;
                  step();
                },
                { kind: 'primary' },
              )
            : button(t('close'), () => mount(phone), {}),
        ),
        g.left_out.length
          ? notice(t('transfer.phone.leftout', { list: g.left_out.join(', ') }), 'warn')
          : null,
      );
    };
    step();
  };

  mount(
    main,
    h(
      'section',
      { class: 'narrow' },
      pageHead(t('transfer.title'), { href: '#/', label: t('nav.home') }),
      h(
        'section',
        { class: 'block tag-plate' },
        h('h2', {}, t('transfer.import')),
        h('p', {}, t('transfer.import.lead')),
        h(
          'label',
          { class: 'btn btn-primary file-label' },
          icon('upload'),
          h('span', {}, t('transfer.import.pick')),
          picker,
        ),
        importStatus,
        h('p', { class: 'hint' }, rich(t('transfer.ms'))),
      ),
      h(
        'section',
        { class: 'block tag-plate' },
        h('h2', {}, t('transfer.export')),
        h('p', {}, t('transfer.export.lead')),
        exportForm,
        exportStatus,
      ),
      h(
        'section',
        { class: 'block tag-plate' },
        h('h2', {}, t('transfer.phone')),
        h('p', {}, t('transfer.phone.lead')),
        h('div', { class: 'actions' }, button(t('transfer.phone.start'), showPhone, { icon: 'qr' })),
        phone,
      ),
      h(
        'section',
        { class: 'block tag-plate' },
        h('h2', {}, t('transfer.vault')),
        h('p', {}, t('transfer.vault.lead')),
        h(
          'div',
          { class: 'actions' },
          button(t('transfer.vault'), () => download('vault.otpx', v.seal(), 'application/json'), {
            icon: 'download',
          }),
        ),
      ),
    ),
  );
}
