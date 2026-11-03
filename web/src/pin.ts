// A PIN for this browser. It opens a device slot of the vault, whose secret is a random
// 32-byte device key combined with the PIN (Argon2id, in the core). The device key is kept
// here encrypted by a non-extractable WebCrypto key.
//
// Limit: a script running on this origin can use that WebCrypto key, so it could recover the
// device key and try PINs. On the shared maxgfr.github.io origin prefer a passkey, or run
// `otpx web` for an origin of its own.

import type { Backing } from './store';
import { core, type Vault } from './wasm';

export const ATTEMPTS = 5;

interface Stored {
  vault: string;
  slot: string;
  iv: Uint8Array<ArrayBuffer>;
  kct: ArrayBuffer;
  key: CryptoKey;
  failures: number;
}

export function valid(pin: string): boolean {
  return /^\d{4,12}$/.test(pin);
}

/** The slot name of this browser's PIN. */
export function slotName(deviceId: string): string {
  return `${deviceId}:pin`;
}

/** Runs `fn` under a cross-tab lock, so attempts from several tabs are counted one by one. */
async function locked<T>(fn: () => Promise<T>): Promise<T> {
  const locks = (navigator as Navigator & { locks?: LockManager }).locks;
  return locks ? locks.request('otpx-pin', fn) : fn();
}

export async function enable(
  store: Backing,
  vault: Vault,
  pin: string,
  deviceId: string,
  label: string,
): Promise<void> {
  const slot = slotName(deviceId);
  const deviceKey = new Uint8Array(vault.addDevice(slot, label, pin, Date.now(), deviceId));
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const kct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, deviceKey);
  deviceKey.fill(0);
  await store.set('pin', { vault: vault.id(), slot, iv, kct, key, failures: 0 } satisfies Stored);
}

export async function disable(store: Backing, vault: Vault | null, deviceId: string): Promise<void> {
  await store.del('pin');
  vault?.removeDevice(slotName(deviceId), Date.now(), deviceId);
}

export async function isSet(store: Backing, file: string): Promise<boolean> {
  const s = await store.get<Stored>('pin');
  return !!s && s.vault === core.vaultId(file) && core.hasDevice(file, s.slot);
}

export type PinResult = { vault: Vault } | { left: number } | 'erased' | 'removed';

export function unlock(store: Backing, file: string, pin: string): Promise<PinResult> {
  return locked(async () => {
    const s = await store.get<Stored>('pin');
    if (!s) return 'erased';
    if (!core.hasDevice(file, s.slot)) {
      await store.del('pin');
      return 'removed';
    }
    // Count the attempt before making it: a closed tab or a crash cannot hide one.
    const failures = s.failures + 1;
    if (failures > ATTEMPTS) {
      await store.del('pin');
      return 'erased';
    }
    await store.set('pin', { ...s, failures });
    const deviceKey = new Uint8Array(
      await crypto.subtle.decrypt({ name: 'AES-GCM', iv: s.iv }, s.key, s.kct),
    );
    try {
      const vault = core.Vault.unlockDevice(file, s.slot, deviceKey, pin);
      await store.set('pin', { ...s, failures: 0 });
      return { vault };
    } catch {
      if (failures >= ATTEMPTS) {
        await store.del('pin');
        return 'erased';
      }
      return { left: ATTEMPTS - failures };
    } finally {
      deviceKey.fill(0);
    }
  });
}
