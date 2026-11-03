// Application state: the vault file, the open vault, remotes, preferences, auto-lock.

import { type Backing, idb } from './store';
import {
  type Backend,
  backendOf,
  localServer,
  type Outcome,
  type RemoteConfig,
  SyncError,
  syncOne,
} from './sync';
import { core, message, type Vault } from './wasm';

export interface Device {
  id: string;
  name: string;
}

export interface Prefs {
  lang: 'en' | 'fr' | null;
  hideLock: boolean;
}

/** Sealed with the vault key: never readable while locked. */
interface LocalData {
  remotes: RemoteConfig[];
}

type Listener = () => void;

function guessDeviceName(): string {
  const ua = navigator.userAgent;
  const os = /iPhone/.test(ua)
    ? 'iPhone'
    : /iPad/.test(ua)
      ? 'iPad'
      : /Android/.test(ua)
        ? 'Android'
        : /Mac/.test(ua)
          ? 'Mac'
          : /Windows/.test(ua)
            ? 'Windows'
            : 'Linux';
  const browser = /Edg\//.test(ua)
    ? 'Edge'
    : /Firefox\//.test(ua)
      ? 'Firefox'
      : /Chrome\//.test(ua)
        ? 'Chrome'
        : /Safari\//.test(ua)
          ? 'Safari'
          : 'browser';
  return `${browser} on ${os}`;
}

function randomId(): string {
  return [...crypto.getRandomValues(new Uint8Array(6))].map((b) => b.toString(16).padStart(2, '0')).join('');
}

export class App {
  store: Backing = idb;
  file: string | null = null;
  vault: Vault | null = null;
  device: Device = { id: '', name: '' };
  prefs: Prefs = { lang: null, hideLock: false };
  remotes: RemoteConfig[] = [];
  /** Remotes received before the vault could be opened (device link, first fetch). */
  pending: RemoteConfig[] = [];
  /** File handles of `file` remotes (structured-cloned into IndexedDB). */
  files = new Map<string, FileSystemFileHandle>();
  /** The token of the `otpx web` process that served this page, if any. */
  localToken: string | null = null;
  syncing = false;
  lastError: string | null = null;
  private listeners = new Set<Listener>();
  private lockTimer: ReturnType<typeof setTimeout> | null = null;
  private syncTimer: ReturnType<typeof setTimeout> | null = null;

  on(fn: Listener): () => void {
    this.listeners.add(fn);
    return () => this.listeners.delete(fn);
  }

  emit(): void {
    for (const fn of this.listeners) fn();
  }

  async boot(store: Backing = idb): Promise<void> {
    this.store = store;
    this.file = (await store.get<string>('vault')) ?? null;
    this.prefs = { ...this.prefs, ...((await store.get<Prefs>('prefs')) ?? {}) };
    const d = await store.get<Device>('device');
    if (d) {
      this.device = d;
    } else {
      this.device = { id: randomId(), name: guessDeviceName() };
      await store.set('device', this.device);
    }
    this.files = (await store.get<Map<string, FileSystemFileHandle>>('handles')) ?? new Map();
  }

  /** Takes the `otpx web` link: the local vault becomes a remote, and the default vault when none is here. */
  async attachLocal(token: string): Promise<void> {
    this.localToken = token;
    try {
      const got = await localServer(token).fetch();
      if (got && !this.file && core.isVault(got.content)) await this.setFile(got.content);
    } catch (e) {
      this.lastError = message(e);
    }
  }

  async setFile(text: string): Promise<void> {
    this.file = text;
    await this.store.set('vault', text);
    this.emit();
  }

  async savePrefs(p: Partial<Prefs>): Promise<void> {
    this.prefs = { ...this.prefs, ...p };
    await this.store.set('prefs', this.prefs);
  }

  async saveDevice(name: string): Promise<void> {
    this.device = { ...this.device, name: name.trim() || this.device.name };
    await this.store.set('device', this.device);
  }

  /** The vault is open: load device-local data, adopt pending remotes, arm auto-lock. */
  async opened(vault: Vault): Promise<void> {
    this.vault = vault;
    const sealed = await this.store.get<string>(`local:${vault.id()}`);
    let local: LocalData = { remotes: [] };
    if (sealed) {
      try {
        local = JSON.parse(vault.openLocal(sealed)) as LocalData;
      } catch {
        local = { remotes: [] };
      }
    }
    this.remotes = local.remotes;
    if (this.pending.length) {
      for (const r of this.pending) {
        this.remotes = this.remotes.filter((x) => x.name !== r.name);
        this.remotes.push(r);
      }
      this.pending = [];
      await this.saveLocal();
    }
    await this.save(false);
    this.touch();
    this.emit();
    if (this.allRemotes().length) void this.syncAll();
  }

  async saveLocal(): Promise<void> {
    if (!this.vault) return;
    const data: LocalData = { remotes: this.remotes };
    await this.store.set(`local:${this.vault.id()}`, this.vault.sealLocal(JSON.stringify(data)));
  }

  async saveHandles(): Promise<void> {
    await this.store.set('handles', this.files);
  }

  /** Seals and stores the vault; syncs a moment later when remotes exist. */
  async save(sync = true): Promise<void> {
    if (!this.vault) return;
    const sealed = this.vault.seal();
    this.file = sealed;
    await this.store.set('vault', sealed);
    if (sync && this.allRemotes().length) {
      if (this.syncTimer) clearTimeout(this.syncTimer);
      this.syncTimer = setTimeout(() => void this.syncAll(), 800);
    }
    this.emit();
  }

  /** Configured remotes plus the `otpx web` one. */
  allRemotes(): RemoteConfig[] {
    const list = [...this.remotes];
    if (this.localToken)
      list.unshift({ kind: 'local', name: 'otpx web', token: this.localToken, lastSync: 0 });
    return list;
  }

  /** Syncs with every remote; returns per-remote results. */
  async syncAll(): Promise<{ name: string; result?: Outcome; error?: string }[]> {
    const vault = this.vault;
    if (!vault || this.syncing) return [];
    this.syncing = true;
    this.lastError = null;
    this.emit();
    const out: { name: string; result?: Outcome; error?: string }[] = [];
    try {
      for (const r of this.allRemotes()) {
        const b: Backend | null = backendOf(r, this.files);
        if (!b) {
          out.push({ name: r.name, error: 'file access not granted' });
          continue;
        }
        try {
          if (r.kind === 'file') await requestFileAccess(this.files.get(r.name));
          const result = await syncOne(vault, b, this.device.name);
          out.push({ name: r.name, result });
          const kept = this.remotes.find((x) => x.name === r.name);
          if (kept) kept.lastSync = Date.now();
        } catch (e) {
          const m = e instanceof SyncError && e.message === 'other-vault' ? 'other-vault' : message(e);
          out.push({ name: r.name, error: m });
          this.lastError = `${r.name}: ${m}`;
        }
      }
      if (this.vault === vault) {
        await this.saveLocal();
        const sealed = vault.seal();
        this.file = sealed;
        await this.store.set('vault', sealed);
      }
    } finally {
      this.syncing = false;
      this.emit();
    }
    return out;
  }

  /** Restarts the inactivity timer. */
  touch(): void {
    if (!this.vault) return;
    if (this.lockTimer) clearTimeout(this.lockTimer);
    const secs = (JSON.parse(this.vault.settings()) as { auto_lock_secs: number }).auto_lock_secs;
    this.lockTimer = setTimeout(() => this.lock('auto'), Math.max(30, secs) * 1000);
  }

  lockReason: 'auto' | 'user' | null = null;

  lock(reason: 'auto' | 'user' = 'user'): void {
    if (this.lockTimer) clearTimeout(this.lockTimer);
    if (this.syncTimer) clearTimeout(this.syncTimer);
    this.vault?.free();
    this.vault = null;
    this.remotes = [];
    this.lockReason = reason;
    this.emit();
  }

  /** Erases everything this browser holds. */
  async forget(): Promise<void> {
    this.lock();
    await this.store.clear();
    this.file = null;
    this.files = new Map();
    this.emit();
  }
}

async function requestFileAccess(h: FileSystemFileHandle | undefined): Promise<void> {
  const handle = h as
    | (FileSystemFileHandle & { requestPermission?: (o: { mode: string }) => Promise<string> })
    | undefined;
  if (handle?.requestPermission) {
    const state = await handle.requestPermission({ mode: 'readwrite' });
    if (state !== 'granted') throw new Error('file access not granted');
  }
}

export const app = new App();
