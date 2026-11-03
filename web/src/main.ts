// otpx web app: shell, router, boot.

import { h, icon, mount } from './dom';
import { detectLang, duration, setLang, t } from './i18n';
import { app } from './state';
import { toast } from './ui';
import { account, edit, share } from './views/account';
import { add } from './views/add';
import { list, search } from './views/list';
import { pendingLink, receive } from './views/receive';
import { settings } from './views/settings';
import { create, fetchGithub, openFile, openLink, recovery, unlock, welcome } from './views/start';
import { runSync, syncView } from './views/sync';
import { transfer } from './views/transfer';
import { loadCore } from './wasm';

declare const OTPX_WASM: string;

/** Where share links point: this page's own address. */
function linkBase(): string {
  return `${location.origin}${location.pathname}`;
}

const header = document.getElementById('bar') as HTMLElement;
const main = document.getElementById('main') as HTMLElement;
let leave: (() => void) | null = null;

function navLink(href: string, ic: Parameters<typeof icon>[0], label: string): HTMLAnchorElement {
  const current =
    location.hash === href || (href === '#/' && (location.hash === '' || location.hash === '#/'));
  return h(
    'a',
    { class: 'nav-btn', href, 'aria-label': label, title: label, 'aria-current': current ? 'page' : null },
    icon(ic),
    h('span', { class: 'nav-label' }, label),
  );
}

function syncState(): HTMLElement | null {
  const remotes = app.allRemotes();
  if (!remotes.length)
    return h(
      'a',
      { class: 'sync-state is-none', href: '#/sync', title: t('sync.none') },
      icon('alert'),
      h('span', {}, t('sync.never')),
    );
  const last = Math.max(...remotes.map((r) => r.lastSync));
  const text = app.syncing ? '…' : last > 0 ? duration((Date.now() - last) / 1000) : t('sync.never');
  return h(
    'button',
    {
      type: 'button',
      class: `sync-state${app.syncing ? ' is-busy' : ''}${app.lastError ? ' is-error' : ''}`,
      title: app.lastError ?? t('sync.now'),
      'aria-label': `${t('sync.now')} (${text})`,
      onclick: (() => void runSync()) as EventListener,
    },
    icon(app.lastError ? 'alert' : 'sync'),
    h('span', {}, text),
  );
}

function renderBar(): void {
  if (!app.vault || app.recoveryPending) {
    mount(header, h('a', { class: 'brand', href: '#/' }, 'otpx'));
    return;
  }
  const q = h('input', {
    type: 'search',
    id: 'search',
    class: 'search',
    placeholder: t('search.placeholder'),
    'aria-label': t('search.label'),
    autocomplete: 'off',
    spellcheck: 'false',
    value: search.query,
  });
  q.addEventListener('input', () => {
    search.query = q.value;
    if (location.hash !== '#/' && location.hash !== '') location.hash = '#/';
    document.dispatchEvent(new Event('otpx:search'));
  });
  q.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') document.dispatchEvent(new Event('otpx:search-enter'));
    if (e.key === 'Escape') {
      q.value = '';
      search.query = '';
      document.dispatchEvent(new Event('otpx:search'));
    }
  });
  mount(
    header,
    h('a', { class: 'brand', href: '#/' }, 'otpx'),
    h('div', { class: 'search-wrap' }, icon('search'), q),
    h(
      'nav',
      { class: 'nav', 'aria-label': 'otpx' },
      syncState(),
      navLink('#/add', 'plus', t('nav.add')),
      navLink('#/transfer', 'upload', t('nav.transfer')),
      navLink('#/sync', 'cloud', t('nav.sync')),
      navLink('#/settings', 'settings', t('nav.settings')),
      h(
        'button',
        {
          type: 'button',
          class: 'nav-btn',
          'aria-label': t('nav.lock'),
          title: t('nav.lock'),
          onclick: (() => {
            app.lock('user');
            location.hash = '#/';
          }) as EventListener,
        },
        icon('lock'),
        h('span', { class: 'nav-label' }, t('nav.lock')),
      ),
    ),
  );
}

async function route(): Promise<void> {
  leave?.();
  leave = null;
  main.dispatchEvent(new Event('otpx:leave'));
  renderBar();
  const path = (location.hash.replace(/^#/, '') || '/').split('/').filter(Boolean);
  const [first, second, third] = path;
  if (first === 'receive' && pendingLink.value) {
    receive(main, pendingLink.value);
    focusHeading();
    return;
  }
  if (!app.file) {
    if (first === 'create')
      create(main, async (v, rc) => {
        app.recoveryPending = true;
        await app.opened(v);
        recovery(main, rc, () => {
          app.recoveryPending = false;
          location.hash = pendingLink.value ? '#/receive' : '#/';
        });
      });
    else if (first === 'fetch') fetchGithub(main);
    else if (first === 'open') openFile(main);
    else if (first === 'link') openLink(main, takeLink);
    else welcome(main);
    focusHeading();
    return;
  }
  if (!app.vault) {
    await unlock(main, async (v) => {
      await app.opened(v);
      const target = pendingLink.value ? '#/receive' : location.hash || '#/';
      if (location.hash === target) void route();
      else location.hash = target;
    });
    return;
  }
  if (first === 'a' && second) {
    if (third === 'edit') edit(main, second);
    else if (third === 'share') share(main, second, linkBase());
    else leave = account(main, second);
  } else if (first === 'add') leave = add(main);
  else if (first === 'transfer') transfer(main);
  else if (first === 'sync') syncView(main, linkBase());
  else if (first === 'settings') await settings(main, () => void route());
  else if (first === 'link') openLink(main, takeLink);
  else leave = list(main);
  focusHeading();
}

function focusHeading(): void {
  // Moves focus to the new page for screen readers, without scrolling or stealing it from a field.
  const active = document.activeElement;
  if (active && active !== document.body && main.contains(active)) return;
  const h1 = main.querySelector<HTMLElement>('h1');
  h1?.focus({ preventScroll: true });
}

/** Takes a share/device link: its fragment is kept in memory only, and erased from the address bar. */
function takeLink(link: string): void {
  const i = link.indexOf('#');
  const frag = i >= 0 ? link.slice(i + 1) : link;
  if (!/(^|&)s=/.test(frag)) {
    toast(t('receive.bad'), 'error');
    return;
  }
  pendingLink.value = frag;
  history.replaceState(null, '', `${location.pathname}#/receive`);
  void route();
}

async function readFragment(): Promise<void> {
  const frag = location.hash.replace(/^#/, '');
  if (/(^|&)s=/.test(frag)) {
    pendingLink.value = frag;
    history.replaceState(null, '', `${location.pathname}#/receive`);
  }
  const local = /(?:^|&)local=([\w-]+)/.exec(frag);
  if (local?.[1]) {
    history.replaceState(null, '', `${location.pathname}#/`);
    await app.attachLocal(local[1]);
  }
}

async function boot(): Promise<void> {
  await Promise.all([loadCore(OTPX_WASM), app.boot()]);
  setLang(detectLang(app.prefs.lang));
  await readFragment();
  app.on(() => {
    if (
      !app.vault &&
      !['', '#/', '#/receive', '#/create', '#/fetch', '#/open', '#/link'].includes(location.hash)
    ) {
      location.hash = '#/';
    } else if (!app.vault) {
      void route();
    } else {
      renderBar();
    }
  });
  for (const ev of ['pointerdown', 'keydown', 'wheel', 'touchstart'])
    window.addEventListener(ev, () => app.touch(), { passive: true });
  document.addEventListener('visibilitychange', () => {
    if (document.hidden && app.prefs.hideLock && app.vault) app.lock('auto');
  });
  document.addEventListener('keydown', (e) => {
    const target = e.target as HTMLElement | null;
    const typing = target?.closest('input, textarea, select');
    if (e.key === '/' && !typing && app.vault) {
      e.preventDefault();
      document.getElementById('search')?.focus();
    }
  });
  window.addEventListener('hashchange', () => {
    // A share link opened while the app is already loaded only changes the fragment.
    const frag = location.hash.replace(/^#/, '');
    if (/(^|&)s=/.test(frag)) takeLink(frag);
    else void route();
  });
  window.addEventListener('online', () => app.vault && app.allRemotes().length && void app.syncAll());
  window.addEventListener('offline', () => toast(t('offline')));
  await route();
  document.body.classList.add('is-ready');
  if ('serviceWorker' in navigator && location.protocol === 'https:') {
    navigator.serviceWorker.register('sw.js', { scope: './' }).catch(() => undefined);
  }
}

boot().catch((e: unknown) => {
  mount(
    main,
    h(
      'p',
      { class: 'notice notice-error', role: 'alert' },
      t('error.generic', { error: e instanceof Error ? e.message : String(e) }),
    ),
  );
});
