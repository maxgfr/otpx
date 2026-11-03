// Sync backends and the sync loop. The merge itself is the core's (`Vault.absorb`), the
// same code the CLI runs, so a browser and a terminal never disagree.

import type { Vault } from './wasm';

export type Fetched = { content: string; version: string } | null;
/** `lost`: the write landed but replaced a version written meanwhile (gists): merge it, push again. */
export type Pushed = { version: string; lost?: string } | 'conflict';

export interface Backend {
  fetch(): Promise<Fetched>;
  push(content: string, base: string | null, message: string): Promise<Pushed>;
}

export type RemoteConfig =
  | {
      kind: 'github';
      name: string;
      repo: string;
      path: string;
      branch: string;
      token: string;
      lastSync: number;
    }
  | { kind: 'gist'; name: string; id: string; file: string; token: string; lastSync: number }
  | { kind: 'local'; name: string; token: string; lastSync: number }
  | { kind: 'file'; name: string; lastSync: number };

export class SyncError extends Error {
  constructor(
    message: string,
    readonly status = 0,
    /** For `key-changed`: the remote file, to unlock with the current password. */
    readonly remote?: string,
  ) {
    super(message);
  }
}

const API = 'https://api.github.com';

function b64encode(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let bin = '';
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

function b64decode(b64: string): string {
  const bin = atob(b64.replace(/\s/g, ''));
  const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
  return new TextDecoder().decode(bytes);
}

async function gh(token: string, url: string, init: RequestInit = {}): Promise<Response> {
  let resp: Response;
  try {
    resp = await fetch(url, {
      ...init,
      cache: 'no-store',
      headers: {
        Accept: 'application/vnd.github+json',
        Authorization: `Bearer ${token}`,
        'X-GitHub-Api-Version': '2022-11-28',
        ...(init.body ? { 'Content-Type': 'application/json' } : {}),
      },
    });
  } catch {
    throw new SyncError('GitHub unreachable');
  }
  return resp;
}

async function failure(what: string, r: Response): Promise<SyncError> {
  let msg = '';
  try {
    msg = ((await r.json()) as { message?: string }).message ?? '';
  } catch {
    /* not JSON */
  }
  const hint =
    r.status === 401
      ? ' (token refused: expired or revoked?)'
      : r.status === 403
        ? ' (token lacks access)'
        : r.status === 404
          ? ' (not found, or the token cannot see it)'
          : '';
  return new SyncError(`${what}: HTTP ${r.status} ${msg}${hint}`.trim(), r.status);
}

function enc(path: string): string {
  return path
    .replace(/^\/+/, '')
    .split('/')
    .map((s) => encodeURIComponent(s))
    .join('/');
}

export function githubRepo(token: string, repo: string, path: string, branch: string, api = API): Backend {
  const url = `${api}/repos/${repo}/contents/${enc(path)}`;
  return {
    async fetch() {
      const r = await gh(token, branch ? `${url}?ref=${encodeURIComponent(branch)}` : url);
      if (r.status === 404) {
        const repoCheck = await gh(token, `${api}/repos/${repo}`);
        if (repoCheck.ok) return null;
        throw await failure(repo, repoCheck);
      }
      if (!r.ok) throw await failure(repo, r);
      const v = (await r.json()) as { sha: string; content?: string; download_url?: string };
      let content = v.content ? b64decode(v.content) : '';
      if (!content) {
        const raw = await gh(token, branch ? `${url}?ref=${encodeURIComponent(branch)}` : url, {
          headers: { Accept: 'application/vnd.github.raw+json' },
        });
        content = await raw.text();
      }
      return { content, version: v.sha };
    },
    async push(content, base, message) {
      const body: Record<string, string> = { message, content: b64encode(content) };
      if (base) body.sha = base;
      if (branch) body.branch = branch;
      const r = await gh(token, url, { method: 'PUT', body: JSON.stringify(body) });
      if (r.status === 409 || r.status === 422) return 'conflict';
      if (!r.ok) throw await failure(repo, r);
      const v = (await r.json()) as { content: { sha: string } };
      return { version: v.content.sha };
    },
  };
}

export function gist(token: string, id: string, file: string, api = API): Backend {
  const read = async () => {
    const r = await gh(token, `${api}/gists/${id}`);
    if (!r.ok) throw await failure(`gist ${id}`, r);
    return (await r.json()) as {
      history: { version: string }[];
      files: Record<string, { content?: string; truncated?: boolean; raw_url?: string } | null>;
    };
  };
  return {
    async fetch() {
      const v = await read();
      const f = v.files[file];
      if (!f) return null;
      let content = f.content ?? '';
      if (f.truncated && f.raw_url) content = await (await fetch(f.raw_url)).text();
      return { content, version: v.history[0]?.version ?? '' };
    },
    async push(content, base) {
      const v = await read();
      const current = v.history[0]?.version ?? '';
      if ((base === null && v.files[file]) || (base !== null && base !== current)) return 'conflict';
      const r = await gh(token, `${api}/gists/${id}`, {
        method: 'PATCH',
        body: JSON.stringify({ files: { [file]: { content } } }),
      });
      if (!r.ok) throw await failure(`gist ${id}`, r);
      const after = (await r.json()) as { history: { version: string }[] };
      const version = after.history[0]?.version ?? '';
      // No conditional write on gists: if another write landed between our check and our
      // PATCH, our parent is not the version we merged. Hand it back to be merged.
      const parent = after.history[1]?.version;
      if (base !== null && parent && parent !== base) {
        const prev = await gh(token, `${api}/gists/${id}/${parent}`);
        if (prev.ok) {
          const pv = (await prev.json()) as { files: Record<string, { content?: string } | null> };
          const lost = pv.files[file]?.content;
          if (lost) return { version, lost };
        }
      }
      return { version };
    },
  };
}

export async function createGist(token: string, file: string, api = API): Promise<string> {
  const r = await gh(token, `${api}/gists`, {
    method: 'POST',
    body: JSON.stringify({
      description: 'otpx vault (encrypted)',
      public: false,
      files: {
        [`${file}.README`]: { content: 'otpx vault: the encrypted vault is the other file of this gist.\n' },
      },
    }),
  });
  if (r.status !== 201) throw await failure('creating the gist', r);
  return ((await r.json()) as { id: string }).id;
}

/** The vault of the `otpx web` process that served this page. */
export function localServer(token: string, base = ''): Backend {
  const headers = { 'X-Otpx-Token': token, 'Content-Type': 'application/json' };
  return {
    async fetch() {
      const r = await fetch(`${base}/api/vault`, { headers, cache: 'no-store' });
      if (r.status === 404) return null;
      if (!r.ok) throw new SyncError(`otpx web: HTTP ${r.status}`, r.status);
      return (await r.json()) as { content: string; version: string };
    },
    async push(content, baseVersion) {
      const r = await fetch(`${base}/api/vault`, {
        method: 'PUT',
        headers,
        body: JSON.stringify({ content, version: baseVersion }),
      });
      if (r.status === 409) return 'conflict';
      if (!r.ok) throw new SyncError(`otpx web: HTTP ${r.status}`, r.status);
      return (await r.json()) as { version: string };
    },
  };
}

async function digest(text: string): Promise<string> {
  const d = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

/** A file picked with the File System Access API (Chromium). */
export function fileHandle(handle: FileSystemFileHandle): Backend {
  return {
    async fetch() {
      const text = await (await handle.getFile()).text();
      if (!text.trim()) return null;
      return { content: text, version: await digest(text) };
    },
    async push(content, base) {
      const text = await (await handle.getFile()).text();
      const current = text.trim() ? await digest(text) : null;
      if (current !== base) return 'conflict';
      const w = await handle.createWritable();
      await w.write(content);
      await w.close();
      return { version: await digest(content) };
    },
  };
}

export type Outcome = 'up' | 'pushed' | 'pulled' | 'merged';

function absorbRemote(
  vault: Vault,
  content: string,
  now: () => number,
): { changed: boolean; differs: boolean } {
  try {
    return JSON.parse(vault.absorb(content, now())) as { changed: boolean; differs: boolean };
  } catch (e) {
    const m = e instanceof Error ? e.message : String(e);
    if (m.startsWith('other-vault')) throw new SyncError('other-vault');
    if (m === 'key-changed') throw new SyncError('key-changed', 0, content);
    throw new SyncError(m);
  }
}

/** Syncs `vault` with one backend: fetch, merge, write back only if unchanged meanwhile.
 *  Throws `key-changed` (with the remote file) when the vault was re-keyed elsewhere. */
export async function syncOne(
  vault: Vault,
  backend: Backend,
  device: string,
  now = Date.now,
): Promise<Outcome> {
  let pulled = false;
  for (let attempt = 0; attempt < 6; attempt++) {
    if (attempt > 0) await new Promise((r) => setTimeout(r, 150 * attempt));
    const remote = await backend.fetch();
    let base: string | null = null;
    if (remote) {
      const res = absorbRemote(vault, remote.content, now);
      pulled ||= res.changed;
      if (!res.differs) return pulled ? 'pulled' : 'up';
      base = remote.version;
    }
    const pushed = await backend.push(vault.seal(), base, `otpx: sync from ${device}`);
    if (pushed === 'conflict') continue;
    if (pushed.lost) {
      // Merge what our write replaced, then write again.
      pulled ||= absorbRemote(vault, pushed.lost, now).changed;
      continue;
    }
    return pulled ? 'merged' : 'pushed';
  }
  throw new SyncError('the remote kept changing during the sync; try again');
}

/** Builds the backend of a configured remote. */
export function backendOf(r: RemoteConfig, files: Map<string, FileSystemFileHandle>): Backend | null {
  switch (r.kind) {
    case 'github':
      return githubRepo(r.token, r.repo, r.path, r.branch);
    case 'gist':
      return gist(r.token, r.id, r.file);
    case 'local':
      return localServer(r.token);
    case 'file': {
      const h = files.get(r.name);
      return h ? fileHandle(h) : null;
    }
  }
}

/** One line describing a remote. */
export function describeRemote(r: RemoteConfig): string {
  switch (r.kind) {
    case 'github':
      return `${r.repo}${r.branch ? `@${r.branch}` : ''}:${r.path}`;
    case 'gist':
      return `gist ${r.id}/${r.file}`;
    case 'local':
      return 'otpx web';
    case 'file':
      return r.name;
  }
}

/** Remotes from a CLI device link (`otpx link`): GitHub repos and gists; folders stay on that machine. */
export function fromDeviceSetup(device: unknown): { remotes: RemoteConfig[]; skipped: string[] } {
  const d = device as { remotes?: Record<string, unknown>[]; tokens?: [string, string][] };
  const tokens = new Map(d.tokens ?? []);
  const remotes: RemoteConfig[] = [];
  const skipped: string[] = [];
  for (const r of d.remotes ?? []) {
    const name = String(r.name ?? '');
    const token = tokens.get(name) ?? '';
    if (r.kind === 'github') {
      remotes.push({
        kind: 'github',
        name,
        repo: String(r.repo),
        path: String(r.path ?? 'vault.otpx'),
        branch: String(r.branch ?? ''),
        token,
        lastSync: 0,
      });
    } else if (r.kind === 'gist') {
      remotes.push({
        kind: 'gist',
        name,
        id: String(r.id),
        file: String(r.file ?? 'vault.otpx'),
        token,
        lastSync: 0,
      });
    } else {
      skipped.push(name);
    }
  }
  return { remotes, skipped };
}
