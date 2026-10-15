import { env, SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { cleanup } from '../src/cleanup';
import { signInWithCode } from './signin';

// Passkeys: adding one (signed in), signing in with it, the offer after
// signing in another way, renaming and removing — against a software
// authenticator that builds and signs exactly what a phone or laptop would
// (attestation "none", ES256), so @simplewebauthn/server checks it for real.

const ISSUER = 'https://login.kaboutersoft.be';
const RP_ID = 'login.kaboutersoft.be';
const FORM = { 'Content-Type': 'application/x-www-form-urlencoded', Origin: ISSUER };
const JSON_FROM_HERE = { 'Content-Type': 'application/json', Origin: ISSUER };

let seq = 0;
const uniqueEmail = (tag: string) => `${tag}-${Date.now()}-${++seq}@example.test`;
const someIp = () => `10.${seq % 250}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;
const call = (path: string, init: RequestInit = {}) => SELF.fetch(`${ISSUER}${path}`, { redirect: 'manual', ...init });
const post = (path: string, fields: Record<string, string>, headers: Record<string, string> = {}) =>
  call(path, { method: 'POST', headers: { ...FORM, 'CF-Connecting-IP': someIp(), ...headers }, body: new URLSearchParams(fields) });
const postJson = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  call(path, { method: 'POST', headers: { ...JSON_FROM_HERE, 'CF-Connecting-IP': someIp(), ...headers }, body: JSON.stringify(body) });
const cookieOf = (res: Response) => (res.headers.get('Set-Cookie') || '').split(';')[0];

async function mails(): Promise<{ body: { message: { to: string; subject: string; text: string } } }[]> {
  return (await (await env.MAILER!.fetch('https://mailer/__calls')).json()) as never;
}

// A new account, signed in with its mailed code → the session cookie, and where it went next.
const signUp = (email: string, continueTo = '/account') => signInWithCode(post, email, { continueTo });

// --- A software authenticator.

const b64u = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64u = (text: string) => Uint8Array.from(atob(text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4)), (c) => c.charCodeAt(0));
const utf8 = (text: string) => new TextEncoder().encode(text);
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) (out.set(p, at), (at += p.length));
  return out;
};
const sha256 = async (bytes: Uint8Array) => new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));

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

class Authenticator {
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

async function addPasskey(cookie: string, name = 'Mac') {
  const auth = await new Authenticator().init();
  const options = await (await postJson('/passkey/register/options', {}, { Cookie: cookie })).json();
  const res = await postJson('/passkey/register', { response: await auth.create(options), name, continue: '/account?passkey=added' }, { Cookie: cookie });
  expect(res.status, await res.clone().text()).toBe(200);
  return auth;
}

const loginOptions = async () => (await postJson('/passkey/login/options', {})).json();
const row = (id: Uint8Array) => env.DB.prepare('SELECT * FROM passkeys WHERE id = ?').bind(b64u(id)).first<Record<string, unknown>>();

describe('adding a passkey', () => {
  it('asks for a discoverable passkey with user verification, no attestation, for this site', async () => {
    const email = uniqueEmail('opts');
    const { cookie } = await signUp(email);
    const res = await postJson('/passkey/register/options', {}, { Cookie: cookie });
    expect(res.status).toBe(200);
    const o = (await res.json()) as any;
    expect(o.rp).toEqual({ name: 'Arcanum', id: RP_ID });
    expect(o.user.name).toBe(email);
    expect(new TextDecoder().decode(fromB64u(o.user.id))).toMatch(/^[0-9a-f-]{36}$/); // the user's id (sub)
    expect(o.attestation).toBe('none');
    expect(o.authenticatorSelection).toMatchObject({ residentKey: 'required', userVerification: 'required' });
  });

  it('stores it with its public key, tells the owner by mail, and lists it on /account', async () => {
    const email = uniqueEmail('add');
    const { cookie } = await signUp(email);
    const auth = await addPasskey(cookie, 'Mac van Jan');
    const stored = (await row(auth.id))!;
    expect(stored).toMatchObject({ name: 'Mac van Jan', counter: 0, device_type: 'multiDevice', backed_up: 1 });
    expect(JSON.parse(stored.transports as string)).toEqual(['internal', 'hybrid']);
    const mail = (await mails()).reverse().find((m) => m.body.message.to === email)!;
    expect(mail.body.message.subject).toMatch(/passkey/i);
    expect(mail.body.message.text).toContain(`${ISSUER}/account`);
    const page = await (await call('/account?passkey=added', { headers: { Cookie: cookie } })).text();
    expect(page).toContain('Mac van Jan');
    expect(page).toContain('Passkey toegevoegd.');
  });

  it('only when signed in, only from this site, and a challenge works once and only for its own user', async () => {
    expect((await postJson('/passkey/register/options', {})).status).toBe(401);
    const a = await signUp(uniqueEmail('own-a'));
    const b = await signUp(uniqueEmail('own-b'));
    expect((await postJson('/passkey/register/options', {}, { Cookie: a.cookie, Origin: 'https://evil.test' })).status).toBe(403);
    const auth = await new Authenticator().init();
    const optionsA = await (await postJson('/passkey/register/options', {}, { Cookie: a.cookie })).json();
    // B can't use A's challenge (and that tried it away).
    expect((await postJson('/passkey/register', { response: await auth.create(optionsA) }, { Cookie: b.cookie })).status).toBe(400);
    expect((await postJson('/passkey/register', { response: await auth.create(optionsA) }, { Cookie: a.cookie })).status).toBe(400);
    // Without user verification, or for another site: refused.
    const o1 = await (await postJson('/passkey/register/options', {}, { Cookie: a.cookie })).json();
    expect((await postJson('/passkey/register', { response: await auth.create(o1, { uv: false }) }, { Cookie: a.cookie })).status).toBe(400);
    const o2 = await (await postJson('/passkey/register/options', {}, { Cookie: a.cookie })).json();
    expect((await postJson('/passkey/register', { response: await auth.create(o2, { origin: 'https://evil.test' }) }, { Cookie: a.cookie })).status).toBe(400);
    const o3 = await (await postJson('/passkey/register/options', {}, { Cookie: a.cookie })).json();
    expect((await postJson('/passkey/register', { response: await auth.create(o3, { rpId: 'evil.test' }) }, { Cookie: a.cookie })).status).toBe(400);
    expect(await row(auth.id)).toBeNull();
  });

  it('names it by what it is: a known model, a security key, a phone — else the device; the list shows which kind and when', async () => {
    const { cookie } = await signUp(uniqueEmail('names'));
    const add = async (create: Record<string, unknown>, browserName = 'Mac') => {
      const auth = await new Authenticator().init();
      const options = await (await postJson('/passkey/register/options', {}, { Cookie: cookie })).json();
      expect((await postJson('/passkey/register', { response: await auth.create(options, create), name: browserName }, { Cookie: cookie })).status).toBe(200);
      return (await row(auth.id))!;
    };
    expect(await add({ aaguid: 'fbfc3007-154e-4ecc-8c0b-6e020557d7bd' })).toMatchObject({ name: 'iCloud Keychain', aaguid: 'fbfc3007-154e-4ecc-8c0b-6e020557d7bd' });
    expect(await add({ transports: ['usb'], synced: false })).toMatchObject({ name: 'Beveiligingssleutel', device_type: 'singleDevice', aaguid: '00000000-0000-0000-0000-000000000000' });
    expect((await add({ transports: ['hybrid'] })).name).toBe('Telefoon');
    expect((await add({ transports: ['internal'], synced: false }, 'Windows')).name).toBe('Windows');
    const page = await (await call('/account', { headers: { Cookie: cookie } })).text();
    expect(page).toContain('Beveiligingssleutel · USB');
    expect(page).toContain('Gesynchroniseerd tussen je toestellen');
    expect(page).toContain('Alleen op het toestel waarop hij gemaakt werd');
    // Date and time, Belgian time.
    expect(page).toMatch(/Toegevoegd op \d{1,2} \w+ \d{4} om \d{2}:\d{2}/);
    const en = await (await call('/account', { headers: { Cookie: cookie, 'Accept-Language': 'en' } })).text();
    expect(en).toMatch(/Added on \d{1,2} \w+ \d{4} at \d{2}:\d{2}/);
    expect(en).toContain('Security key · USB'); // the kind follows the language; the stored name doesn't
  });

  it('a device that already has one for the account is excluded', async () => {
    const { cookie } = await signUp(uniqueEmail('exclude'));
    const auth = await addPasskey(cookie);
    const o = (await (await postJson('/passkey/register/options', {}, { Cookie: cookie })).json()) as any;
    expect(o.excludeCredentials.map((c: any) => c.id)).toEqual([b64u(auth.id)]);
  });
});

describe('signing in with a passkey', () => {
  it('needs no e-mail: the passkey says who it is — a session, then on to where it was going', async () => {
    const email = uniqueEmail('signin');
    const { cookie } = await signUp(email);
    const auth = await addPasskey(cookie);
    const res = await postJson('/passkey/login', { response: await auth.get(await loginOptions()), continue: '/device?user_code=BCDF-GHJK' });
    expect(res.status, await res.clone().text()).toBe(200);
    expect(await res.json()).toEqual({ redirect: '/device?user_code=BCDF-GHJK' });
    const session = cookieOf(res);
    expect(session).toMatch(/^__Host-arcanum_auth=/);
    expect(await (await call('/account', { headers: { Cookie: session } })).text()).toContain(email);
    expect((await row(auth.id))!.last_used_at).toBeTruthy();
    // Somewhere else than our own pages: /account.
    const elsewhere = await postJson('/passkey/login', { response: await auth.get(await loginOptions()), continue: 'https://evil.test/' });
    expect(await elsewhere.json()).toEqual({ redirect: '/account' });
  });

  it('keeps the signature counter, and refuses one that went back', async () => {
    const { cookie } = await signUp(uniqueEmail('counter'));
    const auth = await addPasskey(cookie);
    auth.counter = 5;
    expect((await postJson('/passkey/login', { response: await auth.get(await loginOptions()) })).status).toBe(200);
    expect((await row(auth.id))!.counter).toBe(5);
    auth.counter = 3;
    expect((await postJson('/passkey/login', { response: await auth.get(await loginOptions()) })).status).toBe(401);
  });

  it('refuses a used challenge, another site, no user verification, a stranger, an unknown passkey, a foreign post', async () => {
    const { cookie } = await signUp(uniqueEmail('refuse'));
    const auth = await addPasskey(cookie);
    const once = await auth.get(await loginOptions());
    expect((await postJson('/passkey/login', { response: once })).status).toBe(200);
    const reused = await postJson('/passkey/login', { response: once });
    expect(reused.status).toBe(400);
    expect(((await reused.json()) as { error: string }).error).toMatch(/te lang/);
    expect((await postJson('/passkey/login', { response: await auth.get(await loginOptions(), { origin: 'https://evil.test' }) })).status).toBe(401);
    expect((await postJson('/passkey/login', { response: await auth.get(await loginOptions(), { uv: false }) })).status).toBe(401);
    // The user handle must be the passkey's own user.
    expect((await postJson('/passkey/login', { response: await auth.get(await loginOptions(), { userHandle: b64u(utf8(crypto.randomUUID())) }) })).status).toBe(401);
    const stranger = await new Authenticator().init();
    const unknown = await postJson('/passkey/login', { response: await stranger.get(await loginOptions(), { userHandle: '' }) });
    expect(unknown.status).toBe(401);
    expect(((await unknown.json()) as { error: string }).error).toMatch(/geen account/);
    expect((await postJson('/passkey/login/options', {}, { Origin: 'https://evil.test' })).status).toBe(403);
    expect((await call('/passkey/login/options', { method: 'POST', headers: { ...FORM }, body: '' })).status).toBe(403);
  });
});

describe('the offer after signing in another way', () => {
  it('comes once after signing in without a passkey; "not now" waits 30 days; never with a passkey', async () => {
    const email = uniqueEmail('offer');
    const first = await signUp(email, '/account');
    expect(first.next).toBe('/passkey/offer?continue=%2Faccount');
    const page = await call(first.next, { headers: { Cookie: first.cookie } });
    const html = await page.text();
    expect(html).toContain('data-passkey-register');
    expect(html).toContain('data-skip="/account"'); // a browser without passkeys goes straight on
    const notNow = await post('/passkey/offer', { continue: '/account' }, { Cookie: first.cookie });
    expect(notNow.headers.get('Location')).toBe('/account');
    expect((await signUp(email)).next).toBe('/account');
    // 31 days later it's offered again.
    await env.DB.prepare('UPDATE users SET passkey_offer_dismissed_at = ? WHERE email = ?').bind(new Date(Date.now() - 31 * 86_400_000).toISOString(), email).run();
    expect((await signUp(email)).next).toBe('/passkey/offer?continue=%2Faccount');

    const other = await signUp(uniqueEmail('offer-has'));
    await addPasskey(other.cookie);
    expect((await call('/passkey/offer?continue=%2Faccount', { headers: { Cookie: other.cookie } })).headers.get('Location')).toBe('/account');
  });
});

describe('/account', () => {
  it('renames and removes passkeys — only one\'s own', async () => {
    const a = await signUp(uniqueEmail('manage-a'));
    const b = await signUp(uniqueEmail('manage-b'));
    const key = await addPasskey(a.cookie, 'Oud');
    await post('/account/passkeys', { action: 'rename', id: b64u(key.id), name: 'Andermans' }, { Cookie: b.cookie });
    await post('/account/passkeys', { action: 'delete', id: b64u(key.id) }, { Cookie: b.cookie });
    expect((await row(key.id))!.name).toBe('Oud');
    expect((await post('/account/passkeys', { action: 'rename', id: b64u(key.id), name: '  iPhone  ' }, { Cookie: a.cookie })).headers.get('Location')).toBe('/account');
    expect((await row(key.id))!.name).toBe('iPhone');
    expect((await post('/account/passkeys', { action: 'rename', id: b64u(key.id), name: 'x' }, { Cookie: a.cookie, Origin: 'https://evil.test' })).status).toBe(403);
    await post('/account/passkeys', { action: 'delete', id: b64u(key.id) }, { Cookie: a.cookie });
    expect(await row(key.id)).toBeNull();
    // A removed passkey no longer signs in.
    expect((await postJson('/passkey/login', { response: await key.get(await loginOptions()) })).status).toBe(401);
  });
});

describe('the pages', () => {
  it('load the one script from this site only, where passkeys are offered', async () => {
    const login = await call('/login');
    const csp = login.headers.get('Content-Security-Policy')!;
    expect(csp).toContain("script-src 'self'");
    expect(csp).toContain("connect-src 'self'");
    const html = await login.text();
    expect(html).toContain('<script src="/passkey.js" defer></script>');
    expect(html).toContain('autocomplete="username webauthn"');
    expect(html).toMatch(/<div data-passkey-box hidden>[\s\S]*data-passkey-login/);
    expect(await (await call('/device')).text()).not.toContain('<script');
    const script = await call('/passkey.js');
    expect(script.headers.get('Content-Type')).toContain('text/javascript');
    expect(await script.text()).toContain('/passkey/login/options');
  });

  it('the hourly clean-up drops expired challenges', async () => {
    await env.DB.prepare("INSERT INTO webauthn_challenges (challenge_hash, purpose, expires_at) VALUES ('old-challenge', 'login', '2000-01-01T00:00:00.000Z')").run();
    const report = await cleanup(env);
    expect(report.webauthn_challenges).toBeGreaterThanOrEqual(1);
    expect(await env.DB.prepare("SELECT 1 FROM webauthn_challenges WHERE challenge_hash = 'old-challenge'").first()).toBeNull();
  });
});
