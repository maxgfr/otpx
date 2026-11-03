// The browser build and the CLI binary read each other's vaults (skipped without the binary).
import { expect, test } from 'bun:test';
import { existsSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { core } from './core';

const bin = [
  join(import.meta.dir, '..', '..', 'target', 'debug', 'otpx'),
  join(import.meta.dir, '..', '..', 'target', 'release', 'otpx'),
].find(existsSync);

function otpx(home: string, args: string[], input?: string): { code: number; out: string } {
  const p = Bun.spawnSync([bin ?? 'otpx', ...args], {
    env: {
      HOME: home,
      PATH: process.env.PATH ?? '',
      OTPX_CONFIG_DIR: join(home, 'cfg'),
      OTPX_DATA_DIR: join(home, 'data'),
      OTPX_KEYCHAIN: '0',
      OTPX_TEST_FAST_KDF: '1',
      OTPX_NO_INPUT: '1',
      NO_COLOR: '1',
      OTPX_NOW: '1234567890',
    },
    stdin: input === undefined ? 'ignore' : new TextEncoder().encode(input),
  });
  return { code: p.exitCode ?? -1, out: p.stdout.toString() };
}

test.skipIf(!bin)('a vault made in the browser opens in the CLI, and the other way round', () => {
  const home = mkdtempSync(join(tmpdir(), 'otpx-'));
  const v = core.Vault.create('shared pw', Date.now(), 'test');
  v.addText(
    'otpauth://totp/GitHub:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=GitHub&digits=8',
    Date.now(),
    'web',
  );
  const browserCode = (JSON.parse(v.codes(1234567890)) as { code: string }[])[0]?.code;
  const data = join(home, 'data');
  Bun.spawnSync(['mkdir', '-p', data]);
  writeFileSync(join(data, 'vault.otpx'), v.seal(), { mode: 0o600 });
  expect(otpx(home, ['unlock', '--password-stdin'], 'shared pw\n').code).toBe(0);
  const cli = otpx(home, ['code', 'github']);
  expect(cli.code).toBe(0);
  expect(cli.out.trim()).toBe(browserCode ?? 'missing');
  // RFC 6238, T = 1234567890, SHA-1, 8 digits.
  expect(browserCode).toBe('89005924');
  expect(otpx(home, ['add', 'otpauth://totp/AWS:root?secret=JBSWY3DPEHPK3PXP&issuer=AWS']).code).toBe(0);
  const back = core.Vault.unlockPassword(readFileSync(join(data, 'vault.otpx'), 'utf8'), 'shared pw');
  expect((JSON.parse(back.entries()) as { label: string }[]).map((e) => e.label)).toEqual([
    'AWS (root)',
    'GitHub (me)',
  ]);
});
