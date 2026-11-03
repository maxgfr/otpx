// Remotes: list, sync now, add GitHub / gist / file, device link.

import { h, icon, mount, rich, svgUrl } from '../dom';
import { duration, t } from '../i18n';
import { app } from '../state';
import { createGist, describeRemote, type Outcome, type RemoteConfig } from '../sync';
import { button, field, input, linkRow, notice, pageHead, toast } from '../ui';
import { core, message } from '../wasm';

const results: Record<Outcome, () => string> = {
  up: () => t('sync.result.up'),
  pushed: () => t('sync.result.pushed'),
  pulled: () => t('sync.result.pulled'),
  merged: () => t('sync.result.merged'),
};

export async function runSync(): Promise<void> {
  const out = await app.syncAll();
  for (const r of out) {
    if (r.error)
      toast(
        t('sync.failed', { name: r.name, error: r.error === 'other-vault' ? t('sync.other') : r.error }),
        'error',
      );
    else if (r.result) toast(`${r.name}: ${t('sync.done', { result: results[r.result]() })}`);
  }
}

function when(r: RemoteConfig): string {
  return r.lastSync ? t('sync.ago', { t: duration((Date.now() - r.lastSync) / 1000) }) : t('sync.never');
}

export function syncView(main: HTMLElement, base: string): void {
  const v = app.vault;
  if (!v) return;
  const listEl = h('ul', { class: 'remotes' });
  const renderList = () => {
    const all = app.allRemotes();
    if (!all.length) {
      mount(listEl, h('li', {}, notice(t('sync.none'), 'warn')));
      return;
    }
    mount(
      listEl,
      ...all.map((r) =>
        h(
          'li',
          { class: 'remote' },
          icon(r.kind === 'local' ? 'terminal' : r.kind === 'file' ? 'folder' : 'cloud'),
          h(
            'span',
            { class: 'remote-text' },
            h('strong', {}, r.name),
            h('span', {}, describeRemote(r)),
            h('span', { class: 'hint' }, rich(r.kind === 'local' ? t('sync.local.lead') : when(r))),
          ),
          r.kind === 'local'
            ? null
            : button(
                t('sync.remove'),
                async () => {
                  app.remotes = app.remotes.filter((x) => x.name !== r.name);
                  app.files.delete(r.name);
                  await app.saveLocal();
                  await app.saveHandles();
                  renderList();
                },
                { kind: 'quiet' },
              ),
        ),
      ),
    );
  };
  renderList();
  const off = app.on(renderList);

  const addRemote = async (r: RemoteConfig) => {
    app.remotes = app.remotes.filter((x) => x.name !== r.name);
    app.remotes.push(r);
    await app.saveLocal();
    renderList();
    await runSync();
  };

  // GitHub repository.
  const repo = input({ placeholder: 'you/otpx-vault', required: true, pattern: '[^/\\s]+/[^/\\s]+' });
  const path = input({ value: 'vault.otpx', required: true });
  const branch = input({});
  const token = input({ type: 'password', required: true });
  const ghStatus = h('div', { class: 'form-status', 'aria-live': 'polite' });
  const ghForm = h(
    'form',
    {
      class: 'form',
      onsubmit: (async (e: Event) => {
        e.preventDefault();
        try {
          await addRemote({
            kind: 'github',
            name: 'github',
            repo: repo.value.trim(),
            path: path.value.trim(),
            branch: branch.value.trim(),
            token: token.value.trim(),
            lastSync: 0,
          });
          mount(ghStatus);
        } catch (err) {
          mount(ghStatus, notice(message(err), 'error'));
        }
      }) as EventListener,
    },
    field(t('sync.github.repo'), repo),
    h('div', { class: 'grid-2' }, field(t('sync.github.path'), path), field(t('sync.github.branch'), branch)),
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
    ghStatus,
    h(
      'div',
      { class: 'actions' },
      button(t('sync.add'), () => {}, { kind: 'primary', type: 'submit' }),
    ),
  );

  // Gist.
  const gistId = input({});
  const gistToken = input({ type: 'password', required: true });
  const gistStatus = h('div', { class: 'form-status', 'aria-live': 'polite' });
  const gistForm = h(
    'form',
    {
      class: 'form',
      onsubmit: (async (e: Event) => {
        e.preventDefault();
        try {
          const tok = gistToken.value.trim();
          const id = gistId.value.trim() || (await createGist(tok, 'vault.otpx'));
          await addRemote({ kind: 'gist', name: 'gist', id, file: 'vault.otpx', token: tok, lastSync: 0 });
          mount(gistStatus);
        } catch (err) {
          mount(gistStatus, notice(message(err), 'error'));
        }
      }) as EventListener,
    },
    field(t('sync.gist.id'), gistId),
    field(t('sync.token'), gistToken, t('sync.token.proof')),
    gistStatus,
    h(
      'div',
      { class: 'actions' },
      button(t('sync.add'), () => {}, { kind: 'primary', type: 'submit' }),
    ),
  );

  // A file (File System Access, Chromium only).
  const picker = (window as unknown as { showSaveFilePicker?: (o: unknown) => Promise<FileSystemFileHandle> })
    .showSaveFilePicker;
  const fileBlock = picker
    ? h(
        'details',
        { class: 'remote-add' },
        h('summary', {}, icon('folder'), h('span', {}, t('sync.file'))),
        h('p', {}, t('sync.file.lead')),
        h(
          'div',
          { class: 'actions' },
          button(
            t('sync.file.pick'),
            async () => {
              try {
                const handle = await picker({
                  suggestedName: 'vault.otpx',
                  types: [{ description: 'otpx vault', accept: { 'application/json': ['.otpx'] } }],
                });
                const name = handle.name;
                app.files.set(name, handle);
                await app.saveHandles();
                await addRemote({ kind: 'file', name, lastSync: 0 });
              } catch (err) {
                if (!/abort/i.test(message(err))) toast(message(err), 'error');
              }
            },
            { icon: 'folder' },
          ),
        ),
      )
    : null;

  // Device link.
  const pass = input({ type: 'password', autocomplete: 'new-password', minlength: '6', required: true });
  const linkOut = h('div', { class: 'share-out' });
  const deviceForm = h(
    'form',
    {
      class: 'form',
      onsubmit: ((e: Event) => {
        e.preventDefault();
        try {
          const remotes = app.remotes.filter((r) => r.kind === 'github' || r.kind === 'gist');
          const device = {
            remotes: remotes.map((r) =>
              r.kind === 'github'
                ? { name: r.name, kind: 'github', repo: r.repo, path: r.path, branch: r.branch }
                : r.kind === 'gist'
                  ? { name: r.name, kind: 'gist', id: r.id, file: r.file }
                  : {},
            ),
            tokens: remotes.map((r) => [r.name, 'token' in r ? r.token : '']),
          };
          const link = v.deviceLink(base, JSON.stringify(device), Date.now() + 15 * 60 * 1000, pass.value);
          mount(
            linkOut,
            linkRow(link),
            h('img', {
              class: 'qr',
              alt: t('account.qr'),
              src: svgUrl(core.qrSvg(link)),
              width: '240',
              height: '240',
            }),
            notice(t('share.warning'), 'warn'),
          );
        } catch (err) {
          mount(linkOut, notice(message(err), 'error'));
        }
      }) as EventListener,
    },
    field(t('sync.devicelink.passphrase'), pass),
    h(
      'div',
      { class: 'actions' },
      button(t('sync.devicelink.create'), () => {}, { kind: 'primary', type: 'submit', icon: 'link' }),
    ),
  );

  mount(
    main,
    h(
      'section',
      { class: 'narrow' },
      pageHead(t('sync.title'), { href: '#/', label: t('nav.home') }),
      h('p', { class: 'lead' }, t('sync.lead')),
      listEl,
      h(
        'div',
        { class: 'actions' },
        button(t('sync.now'), () => void runSync(), {
          kind: 'primary',
          icon: 'sync',
          disabled: !app.allRemotes().length,
        }),
      ),
      h(
        'details',
        { class: 'remote-add', open: !app.remotes.length },
        h('summary', {}, icon('cloud'), h('span', {}, t('sync.github'))),
        h('p', {}, t('sync.github.lead')),
        ghForm,
      ),
      h(
        'details',
        { class: 'remote-add' },
        h('summary', {}, icon('cloud'), h('span', {}, t('sync.gist'))),
        h('p', {}, t('sync.gist.lead')),
        gistForm,
      ),
      fileBlock,
      app.remotes.some((r) => r.kind === 'github' || r.kind === 'gist')
        ? h(
            'details',
            { class: 'remote-add' },
            h('summary', {}, icon('link'), h('span', {}, t('sync.devicelink'))),
            h('p', {}, t('sync.devicelink.lead')),
            deviceForm,
            linkOut,
          )
        : null,
    ),
  );
  main.addEventListener('otpx:leave', off, { once: true });
}
