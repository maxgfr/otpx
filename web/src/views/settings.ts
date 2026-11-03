// Settings: auto-lock, clipboard, password, recovery, passkeys, PIN, device, language.

import { h, mount, rich } from '../dom';
import { getLang, setLang, t } from '../i18n';
import * as passkey from '../passkey';
import * as pin from '../pin';
import { app } from '../state';
import { button, field, input, notice, pageHead, select, toast } from '../ui';
import { message } from '../wasm';
import { FAST_KDF, weakness } from './start';

interface Slot {
  id: string;
  type: 'password' | 'recovery' | 'passkey';
  label: string;
  created: number;
}

export async function settings(main: HTMLElement, rerender: () => void): Promise<void> {
  const v = app.vault;
  if (!v) return;
  const s = JSON.parse(v.settings()) as { auto_lock_secs: number; clipboard_clear_secs: number };
  const saveSettings = async (patch: Partial<typeof s>) => {
    v.setSettings(JSON.stringify({ ...s, ...patch }), Date.now(), app.device.id);
    await app.save();
    app.touch();
    toast(t('saved'));
  };
  const autolock = select(
    [
      ['60', t('time.m', { n: 1 })],
      ['300', t('time.m', { n: 5 })],
      ['900', t('time.m', { n: 15 })],
      ['3600', t('time.h', { n: 1 })],
    ],
    String(s.auto_lock_secs),
  );
  autolock.addEventListener('change', () => void saveSettings({ auto_lock_secs: Number(autolock.value) }));
  const clip = select(
    [
      ['10', t('time.s', { n: 10 })],
      ['20', t('time.s', { n: 20 })],
      ['60', t('time.m', { n: 1 })],
      ['0', '—'],
    ],
    String(s.clipboard_clear_secs),
  );
  clip.addEventListener('change', () => void saveSettings({ clipboard_clear_secs: Number(clip.value) }));
  const hide = h('input', { type: 'checkbox', id: 'hidelock', checked: app.prefs.hideLock });
  hide.addEventListener('change', () => void app.savePrefs({ hideLock: hide.checked }));

  // Password.
  const pw = input({ type: 'password', autocomplete: 'new-password', required: true });
  const pwStatus = h('div', { class: 'form-status', 'aria-live': 'polite' });
  pw.addEventListener('input', () =>
    mount(pwStatus, pw.value && weakness(pw.value) ? notice(weakness(pw.value) ?? '', 'warn') : null),
  );
  const pwForm = h(
    'form',
    {
      class: 'form',
      onsubmit: (async (e: Event) => {
        e.preventDefault();
        try {
          v.setPassword(pw.value, Date.now(), FAST_KDF);
          await app.save();
          pw.value = '';
          mount(pwStatus, notice(t('settings.password.done')));
        } catch (err) {
          mount(pwStatus, notice(message(err), 'error'));
        }
      }) as EventListener,
    },
    field(t('settings.password.new'), pw),
    pwStatus,
    h(
      'div',
      { class: 'actions' },
      button(t('save'), () => {}, { kind: 'primary', type: 'submit' }),
    ),
  );

  // Recovery.
  const rcOut = h('div', {});
  const rcBlock = h(
    'div',
    { class: 'form' },
    h('p', {}, t('settings.recovery.lead')),
    h(
      'div',
      { class: 'actions' },
      button(t('settings.recovery.make'), async () => {
        try {
          const code = v.resetRecovery(Date.now());
          await app.save();
          mount(
            rcOut,
            h('div', { class: 'tag-plate recovery' }, h('p', { class: 'recovery-code' }, code)),
            notice(t('recovery.lead'), 'warn'),
          );
        } catch (err) {
          toast(message(err), 'error');
        }
      }),
    ),
    rcOut,
  );

  // Passkeys.
  const slots = (JSON.parse(v.slots()) as Slot[]).filter((x) => x.type === 'passkey');
  const pkList = h(
    'ul',
    { class: 'remotes' },
    ...(slots.length
      ? slots.map((sl) =>
          h(
            'li',
            { class: 'remote' },
            h(
              'span',
              { class: 'remote-text' },
              h('strong', {}, sl.label || 'passkey'),
              h('span', { class: 'hint' }, new Date(sl.created).toLocaleDateString(getLang())),
            ),
            button(
              t('remove'),
              async () => {
                v.removeSlot(sl.id);
                await app.save();
                rerender();
              },
              { kind: 'quiet' },
            ),
          ),
        )
      : [h('li', { class: 'hint' }, t('settings.passkeys.none'))]),
  );
  const addPasskey = button(
    t('settings.passkeys.add'),
    async () => {
      try {
        const r = await passkey.create(app.device.name);
        v.addPasskey(r.credential, r.salt, r.prf, app.device.name, Date.now());
        await app.save();
        toast(t('settings.passkeys.added'));
        rerender();
      } catch (err) {
        const m = message(err);
        if (m === 'prf-unsupported') toast(t('settings.passkeys.unsupported'), 'error');
        else if (m !== 'cancelled' && !/NotAllowed|abort/i.test(m)) toast(m, 'error');
      }
    },
    { icon: 'fingerprint', disabled: !passkey.available() },
  );

  // PIN.
  const pinSet = await pin.isSet(app.store, v.id());
  const pinInput = input({
    type: 'password',
    inputmode: 'numeric',
    autocomplete: 'off',
    pattern: '\\d{4,12}',
    required: true,
  });
  const pinStatus = h('div', { class: 'form-status', 'aria-live': 'polite' });
  const pinForm = h(
    'form',
    {
      class: 'form',
      onsubmit: (async (e: Event) => {
        e.preventDefault();
        if (!pin.valid(pinInput.value)) {
          mount(pinStatus, notice(t('settings.pin.invalid'), 'error'));
          return;
        }
        await pin.enable(app.store, v, pinInput.value, FAST_KDF);
        toast(t('settings.pin.done'));
        rerender();
      }) as EventListener,
    },
    field(t('settings.pin.new'), pinInput),
    pinStatus,
    h(
      'div',
      { class: 'actions' },
      button(t('settings.pin.set'), () => {}, { kind: 'primary', type: 'submit' }),
    ),
  );

  const devName = input({ value: app.device.name });
  devName.addEventListener('change', () => void app.saveDevice(devName.value).then(() => toast(t('saved'))));
  const lang = select(
    [
      ['en', 'English'],
      ['fr', 'Français'],
    ],
    getLang(),
  );
  lang.addEventListener('change', async () => {
    const l = lang.value === 'fr' ? 'fr' : 'en';
    await app.savePrefs({ lang: l });
    setLang(l);
    rerender();
  });

  mount(
    main,
    h(
      'section',
      { class: 'narrow' },
      pageHead(t('settings.title'), { href: '#/', label: t('nav.home') }),
      h(
        'section',
        { class: 'block tag-plate' },
        h('h2', {}, t('settings.security')),
        field(t('settings.autolock'), autolock, t('settings.autolock.hint')),
        h('label', { class: 'check', for: 'hidelock' }, hide, h('span', {}, t('settings.hidelock'))),
        field(t('settings.clipboard'), clip),
      ),
      h(
        'section',
        { class: 'block tag-plate' },
        h('h2', {}, t('settings.passkeys')),
        h('p', {}, t('settings.passkeys.lead')),
        pkList,
        h('div', { class: 'actions' }, addPasskey),
      ),
      h(
        'section',
        { class: 'block tag-plate' },
        h('h2', {}, t('settings.pin')),
        h('p', {}, t('settings.pin.lead')),
        pinSet
          ? h(
              'div',
              { class: 'actions' },
              button(
                t('settings.pin.remove'),
                async () => {
                  await pin.disable(app.store);
                  rerender();
                },
                { kind: 'quiet' },
              ),
            )
          : pinForm,
      ),
      h('section', { class: 'block tag-plate' }, h('h2', {}, t('settings.password')), pwForm),
      h('section', { class: 'block tag-plate' }, h('h2', {}, t('settings.recovery')), rcBlock),
      h(
        'section',
        { class: 'block tag-plate' },
        h('h2', {}, t('settings.device')),
        field(t('settings.device.name'), devName),
        field(t('settings.language'), lang),
      ),
      h(
        'section',
        { class: 'block tag-plate' },
        h('h2', {}, t('settings.about')),
        h('p', {}, t('settings.about.lead', { version: (await import('../wasm')).core.version() })),
        h('p', { class: 'hint' }, rich(t('settings.cli'))),
        h('p', { class: 'hint' }, rich(t('settings.origin'))),
        h(
          'p',
          {},
          h(
            'a',
            { href: 'https://github.com/maxgfr/otpx', target: '_blank', rel: 'noopener noreferrer' },
            'github.com/maxgfr/otpx',
          ),
        ),
      ),
      h(
        'details',
        { class: 'danger-zone' },
        h('summary', {}, t('settings.forget')),
        h('p', {}, t('unlock.forget.confirm')),
        button(t('settings.forget'), () => void app.forget().then(() => (location.hash = '#/')), {
          kind: 'danger',
          icon: 'trash',
        }),
      ),
    ),
  );
}
