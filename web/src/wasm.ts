// The Rust core, compiled to WebAssembly: every code, cipher, merge and format goes through it.
import init, * as core from '../pkg/otpx.js';

export { core };
export type Vault = core.Vault;

let ready: Promise<void> | null = null;

/** Loads the core once. `url` is the hashed wasm file written by the build. */
export function loadCore(url: string): Promise<void> {
  ready ??= init({ module_or_path: url }).then(() => undefined);
  return ready;
}

/** Account as the core describes it (never the secret). */
export interface Account {
  id: string;
  issuer: string;
  account: string;
  label: string;
  type: 'totp' | 'hotp' | 'steam';
  algorithm: string;
  digits: number;
  period: number;
  counter: number;
  tags: string[];
  note: string;
  favorite: boolean;
  created: number;
}

export interface Code {
  id: string;
  code: string;
  remaining: number;
  period: number;
  next: string | null;
}

export interface ImportResult {
  format: string;
  added: number;
  duplicates: number;
  skipped: string[];
  missing: number[];
}

export function accounts(v: Vault): Account[] {
  return JSON.parse(v.entries()) as Account[];
}

export function codes(v: Vault, nowSecs: number): Map<string, Code> {
  const list = JSON.parse(v.codes(nowSecs)) as Code[];
  return new Map(list.map((c) => [c.id, c]));
}

/** Error text of a core call (wasm-bindgen throws `JsError`s). */
export function message(e: unknown): string {
  if (e instanceof Error) return e.message;
  return String(e);
}
