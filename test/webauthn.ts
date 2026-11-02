// A software authenticator (passkeys.test.ts, enroll.test.ts): builds and
// signs exactly what a phone or laptop would (attestation "none", ES256), so
// @simplewebauthn/server checks it for real.

export const ISSUER = 'https://login.kaboutersoft.be';
export const RP_ID = 'login.kaboutersoft.be';

export const b64u = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
export const fromB64u = (text: string) => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4)), (c) => c.charCodeAt(0));
export const utf8 = (text: string) => new TextEncoder().encode(text);
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) (out.set(p, at), (at += p.length));
  return out;
};
export const sha256 = async (bytes: Uint8Array) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

// Just enough CBOR for an attestation object and a COSE key.
function cbor(value: unknown): Uint8Array {
  const head = (major: number, n: number) =>
    n < 24 ? Uint8Array.of((major << 5) | n) : n < 256 ? Uint8Array.of((major << 5) | 24, n) : Uint8Array.of((major << 5) | 25, n >> 8, n & 255);
  if (typeof value === 'number') return value >= 0 ? head(0, value) : head(1, -1 - value);
  if (typeof value === 'string') return concat(head(3, utf8(value).length), utf8(value));
  if (value instanceof Uint8Array) return concat(head(2, value.length), value);
  if (value instanceof Map) return concat(head(5, value.size), ...[...value].flatMap(([k, v]) => [cbor(k), cbor(v)]));
  throw new Error('cbor: unsupported value');
}

// WebCrypto signs ECDSA as r‖s; WebAuthn carries it DER-encoded.
function der(raw: Uint8Array): Uint8Array {
  const int = (b: Uint8Array) => {
    let i = 0;
    while (i < b.length - 1 && b[i] === 0) i++;
    const v = b.slice(i);
    const body = v[0] & 0x80 ? concat(Uint8Array.of(0), v) : v;
    return concat(Uint8Array.of(0x02, body.length), body);
  };
  const seq = concat(int(raw.slice(0, 32)), int(raw.slice(32)));
  return concat(Uint8Array.of(0x30, seq.length), seq);
}

const UP = 0x01;
const UV = 0x04;
const BE = 0x08;
const BS = 0x10;
const AT = 0x40;

export class Authenticator {
  id = crypto.getRandomValues(new Uint8Array(16));
  userHandle = '';
  counter = 0;
  private keys!: CryptoKeyPair;

  async init() {
    this.keys = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])) as CryptoKeyPair;
    return this;
  }

  private async authData(flags: number, rpId: string, attested?: Uint8Array) {
    const counter = Uint8Array.of(0, 0, (this.counter >> 8) & 255, this.counter & 255);
    return concat(await sha256(utf8(rpId)), Uint8Array.of(flags), counter, attested ?? new Uint8Array());
  }

  async create(options: any, opts: { uv?: boolean; origin?: string; rpId?: string; aaguid?: string; transports?: string[]; synced?: boolean } = {}) {
    const jwk = (await crypto.subtle.exportKey('jwk', this.keys.publicKey)) as JsonWebKey;
    const cose = new Map<number, unknown>([[1, 2], [3, -7], [-1, 1], [-2, fromB64u(jwk.x!)], [-3, fromB64u(jwk.y!)]]);
    const aaguid = opts.aaguid ? Uint8Array.from(opts.aaguid.replace(/-/g, '').match(/../g)!, (h) => parseInt(h, 16)) : new Uint8Array(16);
    const attested = concat(aaguid, Uint8Array.of(0, this.id.length), this.id, cbor(cose));
    const synced = opts.synced === false ? 0 : BE | BS;
    const authData = await this.authData(UP | (opts.uv === false ? 0 : UV) | synced | AT, opts.rpId ?? RP_ID, attested);
    this.userHandle = options.user.id;
    const clientData = utf8(JSON.stringify({ type: 'webauthn.create', challenge: options.challenge, origin: opts.origin ?? ISSUER, crossOrigin: false }));
    return {
      id: b64u(this.id),
      rawId: b64u(this.id),
      type: 'public-key',
      clientExtensionResults: {},
      response: { clientDataJSON: b64u(clientData), attestationObject: b64u(cbor(new Map<string, unknown>([['fmt', 'none'], ['attStmt', new Map()], ['authData', authData]]))), transports: opts.transports ?? ['internal', 'hybrid'] },
    };
  }

  async get(options: any, opts: { uv?: boolean; origin?: string; userHandle?: string } = {}) {
    const authData = await this.authData(UP | (opts.uv === false ? 0 : UV) | BE | BS, RP_ID);
    const clientData = utf8(JSON.stringify({ type: 'webauthn.get', challenge: options.challenge, origin: opts.origin ?? ISSUER, crossOrigin: false }));
    const signed = concat(authData, await sha256(clientData));
    const raw = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, this.keys.privateKey, signed));
    return {
      id: b64u(this.id),
      rawId: b64u(this.id),
      type: 'public-key',
      clientExtensionResults: {},
      response: { clientDataJSON: b64u(clientData), authenticatorData: b64u(authData), signature: b64u(der(raw)), userHandle: opts.userHandle ?? this.userHandle },
    };
  }
}
