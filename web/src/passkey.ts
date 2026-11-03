// Touch ID / Face ID through passkeys with the PRF extension: the authenticator returns 32
// bytes bound to the passkey and a salt, from which the core derives the key of a vault slot.

function rand(n: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(n));
}

export function b64url(bytes: ArrayBuffer | Uint8Array): string {
  const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  let bin = '';
  for (const b of u) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export function unb64url(s: string): Uint8Array<ArrayBuffer> {
  const b = atob(s.replace(/-/g, '+').replace(/_/g, '/'));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

/** Whether this browser exposes WebAuthn at all (PRF itself is only known after trying). */
export function available(): boolean {
  return typeof PublicKeyCredential !== 'undefined' && !!navigator.credentials;
}

interface PrfOutput {
  enabled?: boolean;
  results?: { first?: ArrayBuffer };
}

type Extended = AuthenticationExtensionsClientOutputs & { prf?: PrfOutput };

/** Creates a passkey and returns `{credential, salt, prf}`; throws when PRF is unsupported. */
export async function create(label: string): Promise<{ credential: string; salt: string; prf: Uint8Array }> {
  const salt = rand(32);
  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: { name: 'otpx', id: location.hostname },
      user: { id: rand(16), name: `otpx · ${label}`, displayName: `otpx · ${label}` },
      challenge: rand(32),
      pubKeyCredParams: [
        { type: 'public-key', alg: -7 },
        { type: 'public-key', alg: -257 },
      ],
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      extensions: { prf: { eval: { first: salt } } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error('cancelled');
  const ext = cred.getClientExtensionResults() as Extended;
  if (!ext.prf?.enabled && !ext.prf?.results?.first) throw new Error('prf-unsupported');
  const credential = b64url(cred.rawId);
  const first = ext.prf.results?.first;
  const prf = first ? new Uint8Array(first) : await evaluate([[credential, b64url(salt)]]).then((r) => r.prf);
  return { credential, salt: b64url(salt), prf };
}

/** Asks for any of `passkeys` (`[credential, salt]`) and returns the PRF output of the one used. */
export async function evaluate(
  passkeys: [string, string][],
): Promise<{ credential: string; prf: Uint8Array }> {
  const evalByCredential: Record<string, { first: Uint8Array<ArrayBuffer> }> = {};
  for (const [c, s] of passkeys) evalByCredential[c] = { first: unb64url(s) };
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge: rand(32),
      rpId: location.hostname,
      allowCredentials: passkeys.map(([c]) => ({ type: 'public-key', id: unb64url(c) })),
      userVerification: 'required',
      extensions: { prf: { evalByCredential } } as AuthenticationExtensionsClientInputs,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error('cancelled');
  const first = (cred.getClientExtensionResults() as Extended).prf?.results?.first;
  if (!first) throw new Error('prf-unsupported');
  return { credential: b64url(cred.rawId), prf: new Uint8Array(first) };
}
