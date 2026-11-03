// Before the vault is open: welcome, create, recovery code, unlock, fetch from GitHub, open a file or a link.

import { h, icon, mount } from '../dom';
import { t, tn } from '../i18n';
import * as passkey from '../passkey';
import * as pin from '../pin';
import { app } from '../state';
import { githubRepo } from '../sync';
import { button, field, input, notice, pageHead, toast } from '../ui';
import { core, message, type Vault } from '../wasm';

export const FAST_KDF =
  typeof location !== 'undefined' && new URLSearchParams(location.search).has('test-fast-kdf');

function choice(
  iconName: Parameters<typeof icon>[0],
  title: string,
  hint: string,
  href: string,
): HTMLLIElement {
  return h(
    'li',
    {},
    h(
      'a',
      { class: 'choice', href },
      icon(iconName),
      h('span', { class: 'choice-text' }, h('strong', {}, title), h('span', {}, hint)),
      icon('chevron'),
    ),
  );
}

export function welcome(main: HTMLElement): void {
  mount(
    main,
    h(
      'section',
      { class: 'start' },
      h('h1', { class: 'start-title', tabindex: '-1' }, t('app.tagline')),
      h('p', { class: 'lead' }, t('welcome.lead')),
      h(
        'ul',
        { class: 'choices' },
        choice('key', t('welcome.create'), t('welcome.create.hint'), '#/create'),
        choice('cloud', t('welcome.github'), t('welcome.github.hint'), '#/fetch'),
        choice('folder', t('welcome.file'), t('welcome.file.hint'), '#/open'),
        choice('link', t('welcome.link'), t('welcome.link.hint'), '#/link'),
      ),
      notice(t('welcome.proof')),
    ),
  );
}

export function weakness(pw: string): string | null {
  if (/^\d+$/.test(pw)) return t('create.weak.digits');
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  if ([...pw].length < 12 && classes < 3) return t('create.weak.short');
  return null;
}

export function create(main: HTMLElement, done: (v: Vault, recovery: string) => void): void {
  const pw = input({ type: 'password', autocomplete: 'new-password', required: true, minlength: '1' });
  const again = input({ type: 'password', autocomplete: 'new-password', required: true });
  const status = h('div', { class: 'form-status', 'aria-live': 'polite' });
  const submit = button(t('create.submit'), () => {}, { kind: 'primary', type: 'submit' });
  pw.addEventListener('input', () => {
    const w = pw.value ? weakness(pw.value) : null;
    mount(status, w ? notice(w, 'warn') : null);
  });
  const form = h(
    'form',
    {
      class: 'form tag-plate',
      onsubmit: ((e: Event) => {
        e.preventDefault();
        if (pw.value !== again.value) {
          mount(status, notice(t('create.mismatch'), 'error'));
          again.focus();
          return;
        }
        submit.disabled = true;
        submit.setAttribute('aria-busy', 'true');
        setTimeout(() => {
          try {
            const v = core.Vault.create(pw.value, Date.now(), FAST_KDF);
            const rc = v.takeRecoveryCode() ?? '';
            done(v, rc);
          } catch (err) {
            mount(status, notice(message(err), 'error'));
            submit.disabled = false;
            submit.removeAttribute('aria-busy');
          }
        }, 20);
      }) as EventListener,
    },
    field(t('create.password'), pw, t('create.hint')),
    field(t('create.repeat'), again),
    status,
    h('div', { class: 'actions' }, submit),
  );
  mount(
    main,
    h(
      'section',
      { class: 'narrow' },
      pageHead(t('create.title'), { href: '#/', label: t('nav.back') }),
      form,
    ),
  );
  pw.focus();
}

export function recovery(main: HTMLElement, code: string, next: () => void): void {
  const ok = h('input', { type: 'checkbox', id: 'rc-ok' });
  const go = button(t('recovery.continue'), next, { kind: 'primary', disabled: true });
  ok.addEventListener('change', () => {
    go.disabled = !ok.checked;
  });
  mount(
    main,
    h(
      'section',
      { class: 'narrow' },
      pageHead(t('recovery.title')),
      h('p', { class: 'lead' }, t('recovery.lead')),
      h(
        'div',
        { class: 'tag-plate recovery' },
        h('p', { class: 'recovery-code', 'aria-label': t('unlock.recovery.label') }, code),
        button(
          t('recovery.copy'),
          async () => {
            await navigator.clipboard.writeText(code).catch(() => undefined);
            toast(t('copied'));
          },
          { icon: 'copy' },
        ),
      ),
      h('label', { class: 'check', for: 'rc-ok' }, ok, h('span', {}, t('recovery.done'))),
      h('div', { class: 'actions' }, go),
    ),
  );
}

type Mode = 'password' | 'pin' | 'recovery';

export async function unlock(main: HTMLElement, opened: (v: Vault) => void): Promise<void> {
  const file = app.file;
  if (!file) return;
  const id = core.vaultId(file);
  const keys = JSON.parse(core.passkeys(file)) as [string, string][];
  const hasPin = await pin.isSet(app.store, id);
  let mode: Mode = hasPin ? 'pin' : 'password';
  const render = () => {
    const secret = input({
      type: 'password',
      autocomplete: mode === 'password' ? 'current-password' : 'off',
      inputmode: mode === 'pin' ? 'numeric' : 'text',
      required: true,
      name: mode === 'password' ? 'password' : mode,
    });
    if (mode === 'password') secret.setAttribute('autocomplete', 'current-password');
    const status = h('div', { class: 'form-status', 'aria-live': 'polite' });
    if (app.lockReason === 'auto') {
      mount(status, notice(t('locked.auto')));
      app.lockReason = null;
    }
    const submit = button(t('unlock.submit'), () => {}, { kind: 'primary', type: 'submit' });
    const label =
      mode === 'password'
        ? t('unlock.password')
        : mode === 'pin'
          ? t('unlock.pin.label')
          : t('unlock.recovery.label');
    const busy = (b: boolean) => {
      submit.disabled = b;
      submit.toggleAttribute('aria-busy', b);
      secret.disabled = b;
    };
    const form = h(
      'form',
      {
        class: 'form',
        onsubmit: ((e: Event) => {
          e.preventDefault();
          busy(true);
          mount(status, h('p', { class: 'hint' }, t('unlock.working')));
          setTimeout(async () => {
            try {
              if (mode === 'pin') {
                const r = await pin.unlock(app.store, file, secret.value);
                if (r === 'erased') {
                  mode = 'password';
                  render();
                  toast(t('unlock.pin.erased'), 'error');
                  return;
                }
                if ('left' in r) {
                  busy(false);
                  mount(status, notice(tn('unlock.wrong.pin', r.left), 'error'));
                  secret.select();
                  return;
                }
                opened(r.vault);
                return;
              }
              const v =
                mode === 'password'
                  ? core.Vault.unlockPassword(file, secret.value)
                  : core.Vault.unlockRecovery(file, secret.value);
              opened(v);
            } catch {
              busy(false);
              mount(
                status,
                notice(mode === 'recovery' ? t('unlock.wrong.recovery') : t('unlock.wrong'), 'error'),
              );
              secret.select();
            }
          }, 20);
        }) as EventListener,
      },
      field(label, secret),
      status,
      h('div', { class: 'actions' }, submit),
    );
    const alt: HTMLElement[] = [];
    if (keys.length && passkey.available()) {
      alt.push(
        button(
          t('unlock.touchid'),
          async () => {
            try {
              const r = await passkey.evaluate(keys);
              opened(core.Vault.unlockPasskey(file, r.credential, r.prf));
            } catch (err) {
              const m = message(err);
              if (m !== 'cancelled' && !/NotAllowed/i.test(m)) toast(m, 'error');
            }
          },
          { icon: 'fingerprint' },
        ),
      );
    }
    if (mode !== 'pin' && hasPin)
      alt.push(
        button(
          t('unlock.pin'),
          () => {
            mode = 'pin';
            render();
          },
          { kind: 'quiet' },
        ),
      );
    if (mode !== 'password')
      alt.push(
        button(
          t('unlock.password.instead'),
          () => {
            mode = 'password';
            render();
          },
          { kind: 'quiet' },
        ),
      );
    if (mode !== 'recovery')
      alt.push(
        button(
          t('unlock.recovery'),
          () => {
            mode = 'recovery';
            render();
          },
          { kind: 'quiet' },
        ),
      );
    mount(
      main,
      h(
        'section',
        { class: 'unlock' },
        h(
          'div',
          { class: 'tag-plate unlock-tag' },
          h(
            'span',
            { class: 'eyelet eyelet-still', 'aria-hidden': 'true' },
            h('span', { class: 'eyelet-hole' }),
          ),
          h('h1', { tabindex: '-1' }, t('unlock.title')),
          form,
        ),
        h('div', { class: 'alt' }, ...alt),
        h(
          'details',
          { class: 'danger-zone' },
          h('summary', {}, t('unlock.forget')),
          h('p', {}, t('unlock.forget.confirm')),
          button(t('unlock.forget'), () => void app.forget().then(() => (location.hash = '#/')), {
            kind: 'danger',
            icon: 'trash',
          }),
        ),
      ),
    );
    secret.focus();
  };
  render();
}

export function fetchGithub(main: HTMLElement): void {
  const repo = input({ placeholder: 'you/otpx-vault', required: true, pattern: '[^/\\s]+/[^/\\s]+' });
  const path = input({ value: 'vault.otpx', required: true });
  const branch = input({});
  const token = input({ type: 'password', autocomplete: 'off', required: true });
  const status = h('div', { class: 'form-status', 'aria-live': 'polite' });
  const submit = button(t('fetch.submit'), () => {}, { kind: 'primary', type: 'submit' });
  const form = h(
    'form',
    {
      class: 'form tag-plate',
      onsubmit: (async (e: Event) => {
        e.preventDefault();
        submit.disabled = true;
        mount(status);
        try {
          const b = githubRepo(token.value.trim(), repo.value.trim(), path.value.trim(), branch.value.trim());
          const got = await b.fetch();
          if (!got || !core.isVault(got.content)) {
            mount(status, notice(t('fetch.notfound'), 'error'));
            return;
          }
          app.pending = [
            {
              kind: 'github',
              name: 'github',
              repo: repo.value.trim(),
              path: path.value.trim(),
              branch: branch.value.trim(),
              token: token.value.trim(),
              lastSync: 0,
            },
          ];
          await app.setFile(got.content);
          toast(t('fetch.done'));
          location.hash = '#/';
        } catch (err) {
          mount(status, notice(message(err), 'error'));
        } finally {
          submit.disabled = false;
        }
      }) as EventListener,
    },
    field(t('sync.github.repo'), repo),
    field(t('sync.github.path'), path),
    field(t('sync.github.branch'), branch),
    field(t('sync.token'), token, t('sync.token.proof')),
    h(
      'p',
      {},
      h(
        'a',
        {
          href: 'https://github.com/settings/personal-access-tokens/new',
          target: '_blank',
          rel: 'noopener noreferrer',
        },
        t('sync.token.make'),
      ),
    ),
    status,
    h('div', { class: 'actions' }, submit),
  );
  mount(
    main,
    h(
      'section',
      { class: 'narrow' },
      pageHead(t('fetch.title'), { href: '#/', label: t('nav.back') }),
      h('p', { class: 'lead' }, t('sync.github.lead')),
      form,
    ),
  );
  repo.focus();
}

export function openFile(main: HTMLElement): void {
  const status = h('div', { class: 'form-status', 'aria-live': 'polite' });
  const picker = h('input', { type: 'file', accept: '.otpx,application/json,.json', class: 'file-input' });
  picker.addEventListener('change', async () => {
    const f = picker.files?.[0];
    if (!f) return;
    const text = await f.text();
    if (!core.isVault(text)) {
      mount(status, notice(t('file.notvault'), 'error'));
      return;
    }
    await app.setFile(text);
    location.hash = '#/';
  });
  mount(
    main,
    h(
      'section',
      { class: 'narrow' },
      pageHead(t('file.title'), { href: '#/', label: t('nav.back') }),
      h('p', { class: 'lead' }, t('welcome.file.hint')),
      h(
        'label',
        { class: 'btn btn-primary file-label' },
        icon('folder'),
        h('span', {}, t('welcome.file')),
        picker,
      ),
      status,
    ),
  );
}

export function openLink(main: HTMLElement, onLink: (link: string) => void): void {
  const link = h('textarea', { rows: '3', required: true, spellcheck: 'false', autocomplete: 'off' });
  const form = h(
    'form',
    {
      class: 'form tag-plate',
      onsubmit: ((e: Event) => {
        e.preventDefault();
        onLink(link.value.trim());
      }) as EventListener,
    },
    field(t('link.label'), link),
    h(
      'div',
      { class: 'actions' },
      button(t('link.submit'), () => {}, { kind: 'primary', type: 'submit' }),
    ),
  );
  mount(
    main,
    h('section', { class: 'narrow' }, pageHead(t('link.title'), { href: '#/', label: t('nav.back') }), form),
  );
  link.focus();
}
