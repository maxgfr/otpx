// One account: the tag at full size, QR, share, edit, delete.

import { groupCode, h, icon, mount, svgUrl } from '../dom';
import { t } from '../i18n';
import { app } from '../state';
import { button, eyelet, field, input, linkRow, notice, pageHead, select, setEyelet, toast } from '../ui';
import { type Account, accounts, codes, core, message } from '../wasm';
import { copyCode } from './list';

function find(id: string): Account | null {
  return app.vault ? (accounts(app.vault).find((a) => a.id === id) ?? null) : null;
}

const home = { href: '#/', label: t('nav.home') };

export function account(main: HTMLElement, id: string): () => void {
  const a = find(id);
  if (!a || !app.vault) {
    location.hash = '#/';
    return () => {};
  }
  const v = app.vault;
  const eye = eyelet();
  const secs = h('span', { class: 'eyelet-secs' });
  eye.querySelector('.eyelet-hole')?.append(secs);
  const code = h('p', { class: 'code code-big', 'aria-live': 'off' });
  const next = h('p', { class: 'next' });
  const qrBox = h('div', { class: 'qr-box' });
  const secretBox = h('div', { class: 'secret-box' });
  const tag = h(
    'div',
    { class: 'tag tag-big' },
    eye,
    h(
      'div',
      { class: 'tag-name' },
      h('strong', {}, a.issuer || a.account),
      a.issuer && a.account ? h('span', { class: 'tag-account' }, a.account) : null,
    ),
    code,
    next,
  );
  const details = [
    t('account.details', { type: a.type.toUpperCase(), algorithm: a.algorithm, digits: a.digits }),
    a.type === 'hotp' ? t('account.counter', { n: a.counter }) : t('account.period', { n: a.period }),
  ].join(' · ');
  mount(
    main,
    h(
      'section',
      { class: 'account' },
      h('div', { class: 'account-head' }, pageHead(a.label, home)),
      tag,
      h(
        'div',
        { class: 'actions actions-wrap' },
        button(t('account.copy'), () => void copyCode(a, tag).then(tick), { kind: 'primary', icon: 'copy' }),
        button(
          t('account.qr'),
          () => {
            if (qrBox.childElementCount) {
              mount(qrBox);
              return;
            }
            mount(
              qrBox,
              h('img', {
                class: 'qr',
                alt: t('account.qr'),
                src: svgUrl(core.qrSvg(v.uri(a.id))),
                width: '240',
                height: '240',
              }),
              notice(t('account.qr.lead'), 'warn'),
            );
          },
          { icon: 'qr' },
        ),
        h(
          'a',
          { class: 'btn btn-plain', href: `#/a/${a.id}/share` },
          icon('share'),
          h('span', {}, t('account.share')),
        ),
        h(
          'a',
          { class: 'btn btn-plain', href: `#/a/${a.id}/edit` },
          icon('edit'),
          h('span', {}, t('account.edit')),
        ),
      ),
      qrBox,
      h('p', { class: 'meta' }, details),
      a.tags.length
        ? h('p', { class: 'chips' }, ...a.tags.map((x) => h('span', { class: 'chip' }, x)))
        : null,
      a.note ? h('p', { class: 'note' }, a.note) : null,
      h(
        'div',
        { class: 'secret-row' },
        button(
          t('account.secret.show'),
          () => {
            if (secretBox.childElementCount) {
              mount(secretBox);
              return;
            }
            const s = v
              .secret(a.id)
              .replace(/(.{4})/g, '$1 ')
              .trim();
            mount(secretBox, h('p', { class: 'secret', 'aria-label': t('account.secret.label') }, s));
          },
          { kind: 'quiet', icon: 'eye' },
        ),
        secretBox,
      ),
      h(
        'details',
        { class: 'danger-zone' },
        h('summary', {}, t('account.delete')),
        h('p', {}, t('account.delete.confirm', { label: a.label })),
        button(
          t('account.delete.yes'),
          async () => {
            try {
              v.remove(a.id, Date.now(), app.device.id);
              await app.save();
              toast(t('account.deleted', { label: a.label }));
              location.hash = '#/';
            } catch (e) {
              toast(message(e), 'error');
            }
          },
          { kind: 'danger', icon: 'trash' },
        ),
      ),
    ),
  );
  const tick = () => {
    if (!app.vault) return;
    const now = Date.now() / 1000;
    const c = codes(app.vault, now).get(a.id);
    if (!c) return;
    if (a.type === 'hotp') {
      code.textContent = '••• •••';
      next.textContent = t('list.hotp.hint');
      setEyelet(eye, 0, 0);
      return;
    }
    code.textContent = groupCode(c.code);
    code.classList.toggle('code-8', c.code.length > 6);
    next.textContent = c.next ? t('list.next', { code: groupCode(c.next) }) : '';
    secs.textContent = String(c.remaining);
    setEyelet(eye, c.period - (now % c.period), c.period);
  };
  tick();
  const timer = setInterval(tick, 250);
  return () => clearInterval(timer);
}

export function edit(main: HTMLElement, id: string): void {
  const a = find(id);
  const v = app.vault;
  if (!a || !v) {
    location.hash = '#/';
    return;
  }
  const issuer = input({ value: a.issuer });
  const acct = input({ value: a.account });
  const tags = input({ value: a.tags.join(', ') });
  const note = h('textarea', { rows: '2' }, a.note);
  const fav = h('input', { type: 'checkbox', id: 'fav', checked: a.favorite });
  const type = select(
    [
      ['totp', 'TOTP'],
      ['hotp', 'HOTP'],
      ['steam', 'Steam'],
    ],
    a.type,
  );
  const algo = select(
    [
      ['SHA1', 'SHA-1'],
      ['SHA256', 'SHA-256'],
      ['SHA512', 'SHA-512'],
    ],
    a.algorithm,
  );
  const digits = input({
    type: 'number',
    min: '4',
    max: '10',
    value: String(a.digits),
    inputmode: 'numeric',
  });
  const period = input({
    type: 'number',
    min: '1',
    max: '86400',
    value: String(a.period),
    inputmode: 'numeric',
  });
  const counter = input({ type: 'number', min: '0', value: String(a.counter), inputmode: 'numeric' });
  const status = h('div', { class: 'form-status', 'aria-live': 'polite' });
  const form = h(
    'form',
    {
      class: 'form tag-plate',
      onsubmit: (async (e: Event) => {
        e.preventDefault();
        try {
          v.update(
            JSON.stringify({
              id: a.id,
              issuer: issuer.value,
              account: acct.value,
              tags: tags.value
                .split(',')
                .map((x) => x.trim())
                .filter(Boolean),
              note: note.value,
              favorite: fav.checked,
              type: type.value,
              algorithm: algo.value,
              digits: Number(digits.value),
              period: Number(period.value),
              counter: Number(counter.value),
            }),
            Date.now(),
            app.device.id,
          );
          await app.save();
          toast(t('saved'));
          location.hash = `#/a/${a.id}`;
        } catch (err) {
          mount(status, notice(message(err), 'error'));
        }
      }) as EventListener,
    },
    field(t('edit.issuer'), issuer),
    field(t('edit.account'), acct),
    field(t('edit.tags'), tags, t('edit.tags.hint')),
    field(t('edit.note'), note),
    h('label', { class: 'check', for: 'fav' }, fav, h('span', {}, t('account.favorite'))),
    h(
      'details',
      { class: 'advanced' },
      h('summary', {}, t('edit.advanced')),
      h(
        'div',
        { class: 'grid-2' },
        field(t('edit.type'), type),
        field(t('edit.algorithm'), algo),
        field(t('edit.digits'), digits),
        field(t('edit.period'), period),
        field(t('edit.counter'), counter),
      ),
    ),
    status,
    h(
      'div',
      { class: 'actions' },
      button(t('edit.save'), () => {}, { kind: 'primary', type: 'submit' }),
      h('a', { class: 'btn btn-quiet', href: `#/a/${a.id}` }, t('edit.cancel')),
    ),
  );
  mount(
    main,
    h(
      'section',
      { class: 'narrow' },
      pageHead(t('edit.title'), { href: `#/a/${a.id}`, label: a.label }),
      form,
    ),
  );
  issuer.focus();
}

export function share(main: HTMLElement, id: string, base: string): void {
  const a = find(id);
  const v = app.vault;
  if (!a || !v) {
    location.hash = '#/';
    return;
  }
  const expires = select(
    [
      ['600', t('share.expires.10m')],
      ['3600', t('share.expires.1h')],
      ['86400', t('share.expires.1d')],
      ['604800', t('share.expires.7d')],
    ],
    '86400',
  );
  const pass = input({ type: 'password', autocomplete: 'new-password' });
  const out = h('div', { class: 'share-out' });
  const form = h(
    'form',
    {
      class: 'form tag-plate',
      onsubmit: ((e: Event) => {
        e.preventDefault();
        try {
          const link = v.shareLink(
            base,
            JSON.stringify([a.id]),
            Date.now() + Number(expires.value) * 1000,
            pass.value || undefined,
          );
          mount(
            out,
            linkRow(link),
            h('img', {
              class: 'qr',
              alt: t('account.qr'),
              src: svgUrl(core.qrSvg(link)),
              width: '240',
              height: '240',
            }),
          );
        } catch (err) {
          mount(out, notice(message(err), 'error'));
        }
      }) as EventListener,
    },
    field(t('share.expires'), expires),
    field(t('share.passphrase'), pass, t('share.passphrase.hint')),
    notice(t('share.warning'), 'warn'),
    h(
      'div',
      { class: 'actions' },
      button(t('share.create'), () => {}, { kind: 'primary', type: 'submit', icon: 'link' }),
    ),
  );
  mount(
    main,
    h(
      'section',
      { class: 'narrow' },
      pageHead(t('share.title', { label: a.label }), { href: `#/a/${a.id}`, label: a.label }),
      h('p', { class: 'lead' }, t('share.lead')),
      form,
      out,
    ),
  );
}
