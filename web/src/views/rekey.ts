// The vault key changed on another device (password, recovery code or devices changed):
// unlock the remote copy with the current password; this browser's changes are kept.

import { h, mount } from '../dom';
import { t } from '../i18n';
import { app } from '../state';
import { button, field, input, notice, pageHead } from '../ui';
import { core } from '../wasm';

export function rekey(main: HTMLElement): void {
  const pending = app.rekey;
  if (!pending) {
    location.hash = '#/';
    return;
  }
  const pw = input({ type: 'password', autocomplete: 'current-password', required: true });
  const status = h('div', { class: 'form-status', 'aria-live': 'polite' });
  const submit = button(t('unlock.submit'), () => {}, { kind: 'primary', type: 'submit' });
  const form = h(
    'form',
    {
      class: 'form tag-plate',
      onsubmit: ((e: Event) => {
        e.preventDefault();
        submit.disabled = true;
        setTimeout(async () => {
          try {
            const newer = core.Vault.unlockPassword(pending.remote, pw.value);
            await app.adoptRekeyed(newer);
            location.hash = '#/';
          } catch {
            submit.disabled = false;
            mount(status, notice(t('unlock.wrong'), 'error'));
            pw.select();
          }
        }, 20);
      }) as EventListener,
    },
    field(t('rekey.password'), pw),
    status,
    h('div', { class: 'actions' }, submit),
  );
  mount(
    main,
    h(
      'section',
      { class: 'narrow' },
      pageHead(t('rekey.title')),
      h('p', { class: 'lead' }, t('rekey.lead', { name: pending.name })),
      form,
    ),
  );
  pw.focus();
}
