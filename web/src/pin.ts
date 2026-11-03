// A device-local PIN. The vault key is wrapped (Argon2id, in the core) with the PIN plus a
// 32-byte device secret; the device secret is itself encrypted by a non-extractable
// WebCrypto key, so a copy of this browser's storage cannot be attacked offline.

import type { Backing } from './store';
import { core, type Vault } from './wasm';

export const ATTEMPTS = 5;

interface Stored {
  vault: string;
  wrap: string;
  iv: Uint8Array<ArrayBuffer>;
  dct: ArrayBuffer;
  key: CryptoKey;
  failures: number;
}

function secret(pin: string, device: Uint8Array): Uint8Array {
  const p = new TextEncoder().encode(`${pin}|`);
  const out = new Uint8Array(p.length + device.length);
  out.set(p);
  out.set(device, p.length);
  return out;
}

export function valid(pin: string): boolean {
  return /^\d{4,12}$/.test(pin);
}

export async function enable(store: Backing, vault: Vault, pin: string, fast = false): Promise<void> {
  const device = crypto.getRandomValues(new Uint8Array(32));
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const dct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, device);
  const wrap = vault.localWrap(secret(pin, device), fast);
  device.fill(0);
  await store.set('pin', { vault: vault.id(), wrap, iv, dct, key, failures: 0 } satisfies Stored);
}

export async function disable(store: Backing): Promise<void> {
  await store.del('pin');
}

export async function isSet(store: Backing, vaultId: string): Promise<boolean> {
  const s = await store.get<Stored>('pin');
  return !!s && s.vault === vaultId;
}

export type PinResult = { vault: Vault } | { left: number } | 'erased';

export async function unlock(store: Backing, file: string, pin: string): Promise<PinResult> {
  const s = await store.get<Stored>('pin');
  if (!s) return 'erased';
  const device = new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: s.iv }, s.key, s.dct));
  try {
    const vault = core.Vault.unlockLocal(file, s.wrap, secret(pin, device));
    await store.set('pin', { ...s, failures: 0 });
    return { vault };
  } catch {
    const failures = s.failures + 1;
    if (failures >= ATTEMPTS) {
      await store.del('pin');
      return 'erased';
    }
    await store.set('pin', { ...s, failures });
    return { left: ATTEMPTS - failures };
  } finally {
    device.fill(0);
  }
}
