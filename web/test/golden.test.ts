import { expect, test } from 'bun:test';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { core } from './core';

const dir = join(import.meta.dir, '..', '..', 'testdata', 'golden');
const file = readFileSync(join(dir, 'vault.otpx'), 'utf8');
const expected = JSON.parse(readFileSync(join(dir, 'expected.json'), 'utf8')) as {
  password: string;
  recovery_code: string;
  time: number;
  codes: { label: string; code: string }[];
};

test('the golden vault opens in the browser build with the same codes', () => {
  const v = core.Vault.unlockPassword(file, expected.password);
  const entries = JSON.parse(v.entries()) as { id: string; label: string }[];
  const codes = JSON.parse(v.codes(expected.time)) as { id: string; code: string }[];
  for (const want of expected.codes) {
    const e = entries.find((x) => x.label === want.label);
    expect(codes.find((c) => c.id === e?.id)?.code).toBe(want.code);
  }
  expect(() => core.Vault.unlockPassword(file, 'nope')).toThrow();
  expect(core.Vault.unlockRecovery(file, expected.recovery_code.toLowerCase()).id()).toBe(v.id());
});

test('formats, QR and links from the same core', () => {
  const v = core.Vault.create('pw', Date.now(), true);
  const r = JSON.parse(v.addText('otpauth://totp/A:a?secret=JBSWY3DPEHPK3PXP&issuer=A', Date.now(), 'd')) as {
    added: number;
  };
  expect(r.added).toBe(1);
  const aegis = v.export('aegis', '', 'pw2', Date.now());
  const other = core.Vault.create('x', Date.now(), true);
  expect(() =>
    other.importBytes(new TextEncoder().encode(aegis), 'auto', undefined, Date.now(), 'd'),
  ).toThrow(/needs-password/);
  expect(
    JSON.parse(other.importBytes(new TextEncoder().encode(aegis), 'auto', 'pw2', Date.now(), 'd')).added,
  ).toBe(1);
  const id = (JSON.parse(v.entries()) as { id: string }[])[0]?.id ?? '';
  const link = v.shareLink('https://maxgfr.github.io/otpx/', JSON.stringify([id]), Date.now() + 60_000, 'pp');
  expect(core.linkNeedsPassphrase(link)).toBe(true);
  expect(() => core.openLink(link, 'wrong', Date.now())).toThrow();
  expect((JSON.parse(core.openLink(link, 'pp', Date.now())) as { entries: unknown[] }).entries).toHaveLength(
    1,
  );
  expect(core.qrSvg(v.uri(id))).toContain('<svg');
});
