// Share links and device links opened from #s=…

import { h, mount } from '../dom';
import { t } from '../i18n';
import { app } from '../state';
import { fromDeviceSetup } from '../sync';
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
  const body = h('div', {});
  const show = (o: Opened) => {
    if (o.device) {
      const { remotes, skipped } = fromDeviceSetup(o.device);
      mount(
        body,
        h(
          'p',
          { class: 'lead' },
          t('receive.device.lead', { list: remotes.map((r) => r.name).join(', ') || '—' }),
        ),
        skipped.length
          ? notice(`${skipped.join(', ')}: folder remotes stay on the other machine.`, 'warn')
          : null,
        h(
          'div',
          { class: 'actions' },
          button(
            t('receive.device.apply'),
            async () => {
              const first = remotes[0];
              if (!first || (first.kind !== 'github' && first.kind !== 'gist')) return;
              try {
                const { backendOf } = await import('../sync');
                const got = await backendOf(first, app.files)?.fetch();
                if (got && core.isVault(got.content)) {
                  if (!app.file) await app.setFile(got.content);
                  app.pending = remotes;
                  if (app.vault) {
                    await app.opened(app.vault);
                  }
                  pendingLink.value = null;
                  toast(t('fetch.done'));
                  location.hash = '#/';
                } else {
                  mount(status, notice(t('fetch.notfound'), 'error'));
                }
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
      h('p', { class: 'lead' }, t('receive.lead', { n: o.entries.length })),
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
