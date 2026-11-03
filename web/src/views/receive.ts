// Share links and device links opened from #s=…

import { h, mount } from '../dom';
import { t, tn } from '../i18n';
import { app } from '../state';
import { backendOf, describeRemote, fromDeviceSetup } from '../sync';
import { button, field, input, notice, pageHead, toast } from '../ui';
import { type Account, core, type ImportResult, message } from '../wasm';
import { report } from './add';

interface Opened {
  entries: Account[];
  device: unknown;
  expires: number;
  share: string;
}

export const pendingLink = { value: null as string | null };

export function receive(main: HTMLElement, link: string): void {
  const status = h('div', { class: 'form-status', 'aria-live': 'polite' });
  const body = h('div', { class: 'narrow' });
  const show = (o: Opened) => {
    if (o.device) {
      const { remotes, skipped } = fromDeviceSetup(o.device);
      // Show exactly where sync would go: a hostile link could name someone else's repository.
      mount(
        body,
        h('p', { class: 'lead' }, t('receive.device.lead', { list: remotes.length ? '' : '—' })),
        h(
          'ul',
          { class: 'remotes' },
          ...remotes.map((r) =>
            h(
              'li',
              { class: 'remote' },
              h('span', { class: 'remote-text' }, h('strong', {}, r.name), h('span', {}, describeRemote(r))),
            ),
          ),
        ),
        skipped.length ? notice(t('receive.device.skipped', { list: skipped.join(', ') }), 'warn') : null,
        notice(t('receive.device.check'), 'warn'),
        h(
          'div',
          { class: 'actions' },
          button(
            t('receive.device.apply'),
            async () => {
              const first = remotes[0];
              if (!first || (first.kind !== 'github' && first.kind !== 'gist')) return;
              for (const r of remotes) {
                const mine = app.remotes.find((x) => x.name === r.name);
                if (mine && describeRemote(mine) !== describeRemote(r)) {
                  mount(status, notice(t('receive.device.exists', { name: r.name }), 'error'));
                  return;
                }
              }
              try {
                // Every remote must hold one and the same vault (this browser's, if it has one).
                let seen = app.file ? core.vaultId(app.file) : null;
                let got: { content: string } | null = null;
                for (const r of remotes) {
                  const f = await backendOf(r, app.files)?.fetch();
                  if (!f || !core.isVault(f.content)) {
                    mount(status, notice(t('fetch.notfound'), 'error'));
                    return;
                  }
                  const id = core.vaultId(f.content);
                  if (seen && seen !== id) {
                    mount(status, notice(t('receive.device.other'), 'error'));
                    return;
                  }
                  seen = id;
                  got ??= f;
                }
                if (!got) return;
                if (!app.file) await app.setFile(got.content);
                app.pending = remotes;
                if (app.vault) await app.opened(app.vault);
                pendingLink.value = null;
                toast(t('fetch.done'));
                location.hash = '#/';
              } catch (e) {
                mount(status, notice(message(e), 'error'));
              }
            },
            { kind: 'primary', icon: 'sync' },
          ),
        ),
      );
      return;
    }
    mount(
      body,
      h('p', { class: 'lead' }, tn('receive.lead', o.entries.length)),
      h(
        'ul',
        { class: 'board board-preview' },
        ...o.entries.map((e) =>
          h(
            'li',
            { class: 'tag' },
            h(
              'span',
              { class: 'tag-hit' },
              h(
                'span',
                { class: 'tag-name' },
                h('strong', {}, e.issuer || e.account),
                e.issuer ? h('span', { class: 'tag-account' }, e.account) : null,
              ),
            ),
          ),
        ),
      ),
      h(
        'div',
        { class: 'actions' },
        app.vault
          ? button(
              t('receive.add'),
              async () => {
                const v = app.vault;
                if (!v) return;
                try {
                  const r = JSON.parse(v.addShared(o.share, Date.now(), app.device.id)) as ImportResult;
                  if (r.added) await app.save();
                  pendingLink.value = null;
                  mount(status, report(r));
                } catch (e) {
                  mount(status, notice(message(e), 'error'));
                }
              },
              { kind: 'primary' },
            )
          : h(
              'a',
              { class: 'btn btn-primary', href: app.file ? '#/' : '#/create' },
              app.file ? t('unlock.submit') : t('receive.create'),
            ),
      ),
    );
  };
  const tryOpen = (pass?: string) => {
    try {
      show(JSON.parse(core.openLink(link, pass, Date.now())) as Opened);
      mount(status);
    } catch (e) {
      const m = message(e);
      mount(status, notice(/expired/i.test(m) ? t('receive.expired') : t('receive.bad'), 'error'));
    }
  };
  mount(
    main,
    h(
      'section',
      { class: 'narrow' },
      pageHead(t('receive.title'), { href: '#/', label: t('nav.home') }),
      body,
      status,
    ),
  );
  if (core.linkNeedsPassphrase(link)) {
    const pass = input({ type: 'password', autocomplete: 'off', required: true });
    mount(
      body,
      h(
        'form',
        {
          class: 'form tag-plate',
          onsubmit: ((e: Event) => {
            e.preventDefault();
            tryOpen(pass.value);
          }) as EventListener,
        },
        field(t('receive.passphrase'), pass),
        h(
          'div',
          { class: 'actions' },
          button(t('receive.open'), () => {}, { kind: 'primary', type: 'submit' }),
        ),
      ),
    );
    pass.focus();
  } else {
    tryOpen();
  }
}
