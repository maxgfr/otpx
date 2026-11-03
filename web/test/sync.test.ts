import { expect, test } from 'bun:test';
import { type Backend, fromDeviceSetup, type SyncError, syncOne } from '../src/sync';
import { core } from './core';

/** A remote holding one file, with a version counter and optional forced conflicts. */
function fakeRemote(conflicts = 0): Backend & { content: string | null; puts: number } {
  let version = 0;
  let left = conflicts;
  const r = {
    content: null as string | null,
    puts: 0,
    async fetch() {
      return r.content === null ? null : { content: r.content, version: String(version) };
    },
    async push(content: string, base: string | null) {
      r.puts++;
      if (left > 0 && r.content !== null) {
        left--;
        version++;
        return 'conflict' as const;
      }
      if ((r.content === null ? null : String(version)) !== base) return 'conflict' as const;
      r.content = content;
      version++;
      return { version: String(version) };
    },
  };
  return r;
}

const GH = 'otpauth://totp/GitHub:me?secret=JBSWY3DPEHPK3PXP&issuer=GitHub';
const AWS = 'otpauth://totp/AWS:root?secret=GEZDGNBVGY3TQOJQ&issuer=AWS';

test('two devices edit offline and both changes survive, through conflicts', async () => {
  const remote = fakeRemote(1);
  const a = core.Vault.create('pw', 1, 'test');
  a.addText(GH, 2, 'a');
  expect(await syncOne(a, remote, 'a')).toBe('pushed');
  const b = core.Vault.unlockPassword(remote.content ?? '', 'pw');
  b.addText(AWS, 3, 'b');
  const ghId = (JSON.parse(a.entries()) as { id: string }[])[0]?.id ?? '';
  a.update(JSON.stringify({ id: ghId, note: 'from a' }), 4, 'a');
  expect(await syncOne(b, remote, 'b')).toBe('pushed');
  expect(await syncOne(a, remote, 'a')).toBe('merged');
  expect(await syncOne(b, remote, 'b')).toBe('pulled');
  for (const v of [a, b]) {
    const list = JSON.parse(v.entries()) as { label: string; note: string }[];
    expect(list.map((e) => e.label)).toEqual(['AWS (root)', 'GitHub (me)']);
    expect(list.find((e) => e.label === 'GitHub (me)')?.note).toBe('from a');
  }
  expect(await syncOne(a, remote, 'a')).toBe('up');
  expect(remote.puts).toBeGreaterThanOrEqual(4);
});

test('a remote holding another vault is refused', async () => {
  const remote = fakeRemote();
  const a = core.Vault.create('pw', 1, 'test');
  await syncOne(a, remote, 'a');
  const other = core.Vault.create('pw', 1, 'test');
  await expect(syncOne(other, remote, 'x')).rejects.toThrow('other-vault');
});

test('device links from the CLI map to web remotes', () => {
  const { remotes, skipped } = fromDeviceSetup({
    remotes: [
      { name: 'github', kind: 'github', repo: 'me/vault', path: 'vault.otpx', branch: '', last_sync: 0 },
      { name: 'gist', kind: 'gist', id: 'abc', file: 'vault.otpx' },
      { name: 'icloud', kind: 'folder', path: '/Users/me/iCloud' },
    ],
    tokens: [
      ['github', 'tok1'],
      ['gist', 'tok2'],
    ],
  });
  expect(remotes).toHaveLength(2);
  expect(remotes[0]).toMatchObject({ kind: 'github', repo: 'me/vault', token: 'tok1' });
  expect(remotes[1]).toMatchObject({ kind: 'gist', id: 'abc', token: 'tok2' });
  expect(skipped).toEqual(['icloud']);
});

test('a password change elsewhere is detected, then adopted with the new password', async () => {
  const remote = fakeRemote();
  const a = core.Vault.create('old pw', 1, 'a');
  a.addText(GH, 2, 'a');
  await syncOne(a, remote, 'a');
  const b = core.Vault.unlockPassword(remote.content ?? '', 'old pw');
  a.setPassword('new pw', 3, 'a');
  await syncOne(a, remote, 'a');
  b.addText(AWS, 4, 'b');
  // B's key is retired: the sync stops and hands over the remote file.
  let rekeyed = '';
  try {
    await syncOne(b, remote, 'b');
  } catch (e) {
    expect((e as SyncError).message).toBe('key-changed');
    rekeyed = (e as SyncError).remote ?? '';
  }
  expect(() => core.Vault.unlockPassword(rekeyed, 'old pw')).toThrow();
  const newer = core.Vault.unlockPassword(rekeyed, 'new pw');
  b.absorbRotated(newer, 5, 'b');
  expect(await syncOne(b, remote, 'b')).toBe('pushed');
  const labels = (
    JSON.parse(core.Vault.unlockPassword(remote.content ?? '', 'new pw').entries()) as { label: string }[]
  ).map((e) => e.label);
  expect(labels).toEqual(['AWS (root)', 'GitHub (me)']);
});
