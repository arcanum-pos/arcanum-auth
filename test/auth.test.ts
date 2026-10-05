import { env, SELF } from 'cloudflare:test';
import { createLocalJWKSet, decodeJwt, jwtVerify } from 'jose';
import { describe, expect, it } from 'vitest';

const ISSUER = 'https://login.kaboutersoft.be';
const APP = 'https://arcanum.test';
const REDIRECT = `${APP}/callback`;
const FORM = { 'Content-Type': 'application/x-www-form-urlencoded', Origin: ISSUER };

let seq = 0;
const uniqueEmail = (tag: string) => `${tag}-${Date.now()}-${++seq}@example.test`;

function call(path: string, init: RequestInit = {}) {
  return SELF.fetch(`${ISSUER}${path}`, { redirect: 'manual', ...init });
}

// Each request from its own address (rate limits count per IP, like real traffic).
const someIp = () => `10.${seq % 250}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;

function post(path: string, fields: Record<string, string>, headers: Record<string, string> = {}) {
  return call(path, { method: 'POST', headers: { ...FORM, 'CF-Connecting-IP': someIp(), ...headers }, body: new URLSearchParams(fields) });
}

function cookieOf(res: Response): string {
  const set = res.headers.get('Set-Cookie') || '';
  return set.split(';')[0];
}

async function newClient(name = 'Test installation') {
  const res = await call('/admin/clients', {
    method: 'POST',
    headers: { Authorization: 'Bearer test-admin-key', 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, redirect_uris: [REDIRECT], post_logout_redirect_uris: [APP] }),
  });
  expect(res.status).toBe(201);
  return (await res.json()) as { client_id: string; client_secret: string };
}

async function mails(): Promise<{ body: { to: string; subject: string; text: string } }[]> {
  return (await (await env.MAILER!.fetch('https://mailer/__calls')).json()) as never;
}

async function lastCodeFor(email: string): Promise<string> {
  const mail = (await mails()).reverse().find((m) => m.body.to === email)!;
  return mail.body.text.match(/\b(\d{6})\b/)![1];
}

// Sign up with e-mail + password (verified by the mailed code) → session cookie.
async function signUp(email: string, password = 'correct horse battery', name = 'Jan Peeters'): Promise<string> {
  const res = await post('/signup', { name, email, password, continue: '/account' });
  expect(res.status).toBe(302);
  const id = new URL(res.headers.get('Location')!, ISSUER).searchParams.get('id')!;
  const verified = await post('/verify', { id, code: await lastCodeFor(email), continue: '/account' });
  expect(verified.status).toBe(302);
  return cookieOf(verified);
}

async function pkce() {
  const verifier = 'v'.repeat(20) + crypto.randomUUID().replace(/-/g, '');
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return { verifier, challenge };
}

function authorizeUrl(clientId: string, challenge: string, extra: Record<string, string> = {}) {
  return `/authorize?${new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: REDIRECT,
    scope: 'openid profile email offline_access',
    state: 'st4te',
    nonce: 'n0nce',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...extra,
  })}`;
}

async function codeFlow(client: { client_id: string; client_secret: string }, cookie: string) {
  const { verifier, challenge } = await pkce();
  const res = await call(authorizeUrl(client.client_id, challenge), { headers: { Cookie: cookie } });
  expect(res.status).toBe(302);
  const back = new URL(res.headers.get('Location')!);
  expect(`${back.origin}${back.pathname}`).toBe(REDIRECT);
  expect(back.searchParams.get('state')).toBe('st4te');
  const code = back.searchParams.get('code')!;
  const tokenRes = await post('/token', {
    grant_type: 'authorization_code',
    code,
    redirect_uri: REDIRECT,
    client_id: client.client_id,
    client_secret: client.client_secret,
    code_verifier: verifier,
  });
  return { code, verifier, tokenRes };
}

describe('discovery and keys', () => {
  it('publishes what arcanum-bff reads from discovery', async () => {
    const d = (await (await call('/.well-known/openid-configuration')).json()) as Record<string, unknown>;
    expect(d.issuer).toBe(ISSUER);
    expect(d.authorization_endpoint).toBe(`${ISSUER}/authorize`);
    expect(d.token_endpoint).toBe(`${ISSUER}/token`);
    expect(d.userinfo_endpoint).toBe(`${ISSUER}/userinfo`);
    expect(d.device_authorization_endpoint).toBe(`${ISSUER}/device/code`);
    expect(d.end_session_endpoint).toBe(`${ISSUER}/logout`);
    expect(d.grant_types_supported).toContain('urn:ietf:params:oauth:grant-type:device_code');
  });

  it('publishes only the public half of the signing key', async () => {
    const { keys } = (await (await call('/.well-known/jwks.json')).json()) as { keys: Record<string, string>[] };
    expect(keys[0].kid).toBe('test-key');
    expect(keys[0].n).toBeTruthy();
    expect(keys[0].d).toBeUndefined();
  });
});

describe('admin API', () => {
  it('needs the admin key, and never returns a secret after creation', async () => {
    expect((await call('/admin/clients', { method: 'POST', body: '{}' })).status).toBe(401);
    const client = await newClient('Listed');
    expect(client.client_secret.length).toBeGreaterThan(30);
    const list = (await (await call('/admin/clients', { headers: { Authorization: 'Bearer test-admin-key' } })).json()) as Record<string, unknown>[];
    const mine = list.find((c) => c.client_id === client.client_id)!;
    expect(mine.name).toBe('Listed');
    expect(mine).not.toHaveProperty('client_secret');
  });

  it('refuses non-https redirect URIs', async () => {
    const res = await call('/admin/clients', {
      method: 'POST',
      headers: { Authorization: 'Bearer test-admin-key', 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'x', redirect_uris: ['http://evil.test/cb'] }),
    });
    expect(res.status).toBe(400);
  });
});

describe('authorization code flow (the console)', () => {
  it('signs up, authorizes with PKCE and gets tokens the BFF accepts', async () => {
    const client = await newClient();
    const email = uniqueEmail('code');
    const cookie = await signUp(email);
    const { tokenRes } = await codeFlow(client, cookie);
    expect(tokenRes.status).toBe(200);
    const tokens = (await tokenRes.json()) as Record<string, string>;
    expect(tokens.refresh_token).toBeTruthy();

    const jwks = createLocalJWKSet((await (await call('/.well-known/jwks.json')).json()) as never);
    const { payload } = await jwtVerify(tokens.id_token, jwks, { issuer: ISSUER, audience: client.client_id });
    expect(payload).toMatchObject({ email, email_verified: true, name: 'Jan Peeters', nonce: 'n0nce' });

    const info = (await (await call('/userinfo', { headers: { Authorization: `Bearer ${tokens.access_token}` } })).json()) as Record<string, string>;
    expect(info).toMatchObject({ sub: payload.sub, email, name: 'Jan Peeters' });
  });

  it('a code works once, only with its PKCE verifier, redirect_uri and client', async () => {
    const client = await newClient();
    const other = await newClient('Other');
    const cookie = await signUp(uniqueEmail('once'));
    const { code, verifier, tokenRes } = await codeFlow(client, cookie);
    expect(tokenRes.status).toBe(200);
    const again = await post('/token', { grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: client.client_id, client_secret: client.client_secret, code_verifier: verifier });
    expect(((await again.json()) as Record<string, string>).error).toBe('invalid_grant');

    const { challenge } = await pkce();
    const res = await call(authorizeUrl(client.client_id, challenge), { headers: { Cookie: cookie } });
    const fresh = new URL(res.headers.get('Location')!).searchParams.get('code')!;
    const wrongVerifier = await post('/token', { grant_type: 'authorization_code', code: fresh, redirect_uri: REDIRECT, client_id: client.client_id, client_secret: client.client_secret, code_verifier: 'x'.repeat(50) });
    expect(((await wrongVerifier.json()) as Record<string, string>).error).toBe('invalid_grant');

    const wrongSecret = await post('/token', { grant_type: 'authorization_code', code: fresh, redirect_uri: REDIRECT, client_id: other.client_id, client_secret: 'nope' });
    expect(wrongSecret.status).toBe(401);
  });

  it('sends a signed-out user to sign in, and back', async () => {
    const client = await newClient();
    const email = uniqueEmail('return');
    await signUp(email);
    const { challenge } = await pkce();
    const res = await call(authorizeUrl(client.client_id, challenge));
    expect(res.status).toBe(302);
    const loginUrl = new URL(res.headers.get('Location')!, ISSUER);
    expect(loginUrl.pathname).toBe('/login');
    const continueTo = loginUrl.searchParams.get('continue')!;
    expect(continueTo.startsWith('/authorize?')).toBe(true);

    const wrong = await post('/login', { email, password: 'wrong password!', continue: continueTo });
    expect(wrong.status).toBe(401);
    const ok = await post('/login', { email, password: 'correct horse battery', continue: continueTo });
    expect(ok.status).toBe(302);
    // No passkey yet: once by way of the offer to add one, then on.
    expect(ok.headers.get('Location')).toBe(`/passkey/offer?continue=${encodeURIComponent(continueTo)}`);
    const notNow = await post('/passkey/offer', { continue: continueTo }, { Cookie: cookieOf(ok) });
    expect(notNow.headers.get('Location')).toBe(continueTo);
    const again = await post('/login', { email, password: 'correct horse battery', continue: continueTo });
    expect(again.headers.get('Location')).toBe(continueTo);
  });

  it('never redirects to an unregistered redirect_uri, and requires PKCE', async () => {
    const client = await newClient();
    const cookie = await signUp(uniqueEmail('redir'));
    const { challenge } = await pkce();
    const bad = await call(authorizeUrl(client.client_id, challenge, { redirect_uri: 'https://evil.test/cb' }), { headers: { Cookie: cookie } });
    expect(bad.status).toBe(400);
    expect(bad.headers.get('Location')).toBeNull();
    const noPkce = await call(authorizeUrl(client.client_id, challenge, { code_challenge_method: 'plain' }), { headers: { Cookie: cookie } });
    expect(new URL(noPkce.headers.get('Location')!).searchParams.get('error')).toBe('invalid_request');
  });
});

describe('refresh tokens', () => {
  it('rotate on use; reusing an old one revokes the family', async () => {
    const client = await newClient();
    const { tokenRes } = await codeFlow(client, await signUp(uniqueEmail('refresh')));
    const first = ((await tokenRes.json()) as Record<string, string>).refresh_token;
    const refresh = (token: string) => post('/token', { grant_type: 'refresh_token', refresh_token: token, client_id: client.client_id, client_secret: client.client_secret });

    const r1 = await refresh(first);
    expect(r1.status).toBe(200);
    const second = ((await r1.json()) as Record<string, string>).refresh_token;
    expect(second).not.toBe(first);

    expect(((await (await refresh(first)).json()) as Record<string, string>).error).toBe('invalid_grant');
    // The theft response also killed the newer one.
    expect(((await (await refresh(second)).json()) as Record<string, string>).error).toBe('invalid_grant');
  });
});

describe('device authorization grant (the kassa)', () => {
  async function start(clientId: string) {
    const res = await post('/device/code', { client_id: clientId, scope: 'openid profile email offline_access' });
    expect(res.status).toBe(200);
    return (await res.json()) as { device_code: string; user_code: string; verification_uri_complete: string; interval: number };
  }
  const poll = (client: { client_id: string; client_secret: string }, deviceCode: string) =>
    post('/token', { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: deviceCode, client_id: client.client_id, client_secret: client.client_secret });

  it('pending → slow_down → approved on the phone → tokens', async () => {
    const client = await newClient('Scouts Elewijt');
    const email = uniqueEmail('device');
    const cookie = await signUp(email);
    const d = await start(client.client_id);
    expect(d.user_code).toMatch(/^[A-Z]{4}-[A-Z]{4}$/);
    expect(d.verification_uri_complete).toBe(`${ISSUER}/device?user_code=${d.user_code}`);

    expect(((await (await poll(client, d.device_code)).json()) as Record<string, string>).error).toBe('authorization_pending');
    expect(((await (await poll(client, d.device_code)).json()) as Record<string, string>).error).toBe('slow_down');

    const page = await call(`/device?user_code=${d.user_code}`, { headers: { Cookie: cookie } });
    expect(await page.text()).toContain('Scouts Elewijt');
    const allowed = await post('/device/confirm', { user_code: d.user_code, decision: 'allow' }, { Cookie: cookie });
    expect(allowed.status).toBe(200);

    await env.DB.prepare('UPDATE device_codes SET last_poll_at = NULL').run();
    const tokens = await poll(client, d.device_code);
    expect(tokens.status).toBe(200);
    const body = (await tokens.json()) as Record<string, string>;
    expect(decodeJwt(body.id_token)).toMatchObject({ iss: ISSUER, aud: client.client_id, email });
    expect(body.refresh_token).toBeTruthy();
    // Handed out once.
    expect(((await (await poll(client, d.device_code)).json()) as Record<string, string>).error).toBe('invalid_grant');
  });

  it('denied on the phone → access_denied; an unknown code is refused', async () => {
    const client = await newClient();
    const cookie = await signUp(uniqueEmail('deny'));
    const d = await start(client.client_id);
    await post('/device/confirm', { user_code: d.user_code, decision: 'deny' }, { Cookie: cookie });
    expect(((await (await poll(client, d.device_code)).json()) as Record<string, string>).error).toBe('access_denied');
    const unknown = await post('/device', { user_code: 'BBBB-CCCC' }, { Cookie: cookie });
    expect(unknown.status).toBe(400);
  });

  it('a signed-out phone signs in first, then lands on the confirmation', async () => {
    const client = await newClient();
    const d = await start(client.client_id);
    const res = await call(`/device?user_code=${d.user_code}`);
    const loginUrl = new URL(res.headers.get('Location')!, ISSUER);
    expect(loginUrl.pathname).toBe('/login');
    expect(loginUrl.searchParams.get('continue')).toBe(`/device?user_code=${d.user_code}`);
  });
});

describe('accounts', () => {
  it('needs a verified e-mail: no user exists before the code is entered', async () => {
    const email = uniqueEmail('pending');
    await post('/signup', { name: 'X', email, password: 'correct horse battery', continue: '/account' });
    expect(await env.DB.prepare('SELECT 1 FROM users WHERE email = ?').bind(email).first()).toBeNull();
    const mail = (await mails()).reverse().find((m) => m.body.to === email)!;
    expect(mail.body.subject).toBeTruthy();
  });

  it("accepts its own page's form when the browser sends Origin: null (Sec-Fetch-Site decides)", async () => {
    const email = uniqueEmail('nullorigin');
    const own = await post('/signup', { name: 'N', email, password: 'correct horse battery', continue: '/account' }, { Origin: 'null', 'Sec-Fetch-Site': 'same-origin' });
    expect(own.status).toBe(302);
    const unknown = await post('/signup', { name: 'N', email: uniqueEmail('nullorigin2'), password: 'correct horse battery' }, { Origin: 'null' });
    expect(unknown.status).toBe(403);
    const crossSite = await post('/login', { email, password: 'x' }, { Origin: 'null', 'Sec-Fetch-Site': 'cross-site' });
    expect(crossSite.status).toBe(403);
  });

  it('pages send a referrer policy that keeps Origin on their own form posts', async () => {
    const res = await call('/signup')
    expect(res.headers.get('Referrer-Policy')).toBe('same-origin');
  });

  it('refuses a form post from another site (CSRF)', async () => {
    const res = await call('/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: 'https://evil.test' }, body: 'email=a@b.c&password=x' });
    expect(res.status).toBe(403);
  });

  it('limits wrong passwords per address (whatever the IP)', async () => {
    const email = uniqueEmail('brute');
    await signUp(email);
    for (let i = 0; i < 10; i++) await post('/login', { email, password: `wrong-${i}-password`, continue: '/account' });
    const res = await post('/login', { email, password: 'correct horse battery', continue: '/account' });
    expect(res.status).toBe(429);
  });

  it('resets a password with a mailed code, and the old one stops working', async () => {
    const email = uniqueEmail('reset');
    await signUp(email);
    const req = await post('/reset', { email, continue: '/account' });
    const id = (await req.text()).match(/name="id" value="([^"]+)"/)![1];
    const done = await post('/reset/confirm', { id, code: await lastCodeFor(email), password: 'a brand new password', continue: '/account' });
    expect(done.status).toBe(302);
    expect((await post('/login', { email, password: 'correct horse battery', continue: '/account' })).status).toBe(401);
    expect((await post('/login', { email, password: 'a brand new password', continue: '/account' })).status).toBe(302);
  });
});

describe('sign in with Google', () => {
  it('starts at Google, and links to the password account with the same e-mail (same sub)', async () => {
    const email = uniqueEmail('google');
    await signUp(email);
    const before = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first<{ id: string }>();

    const start = await call('/google?continue=%2Faccount');
    const target = new URL(start.headers.get('Location')!);
    expect(target.origin).toBe('https://accounts.google.com');
    expect(target.searchParams.get('redirect_uri')).toBe(`${ISSUER}/callback/google`);

    const back = await call(`/callback/google?code=${encodeURIComponent(email)}&state=${target.searchParams.get('state')}`);
    expect(back.status).toBe(302);
    expect(cookieOf(back)).toMatch(/^arcanum_auth=/);
    const after = await env.DB.prepare('SELECT id, google_sub FROM users WHERE email = ?').bind(email).first<{ id: string; google_sub: string }>();
    expect(after).toEqual({ id: before!.id, google_sub: `google-${email}` });
  });

  it('refuses an unverified Google address and a replayed state', async () => {
    const start = await call('/google?continue=%2Faccount');
    const state = new URL(start.headers.get('Location')!).searchParams.get('state')!;
    const res = await call(`/callback/google?code=unverified-${uniqueEmail('g')}&state=${state}`);
    expect(res.status).toBe(400);
    const replay = await call(`/callback/google?code=${uniqueEmail('g2')}&state=${state}`);
    expect(replay.status).toBe(400);
  });
});

describe('logout', () => {
  it('ends the session and returns only to a registered address', async () => {
    const client = await newClient();
    const cookie = await signUp(uniqueEmail('logout'));
    const res = await call(`/logout?client_id=${client.client_id}&post_logout_redirect_uri=${encodeURIComponent(APP)}`, { headers: { Cookie: cookie } });
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toBe(`${APP}/`);
    const stranger = await call(`/logout?client_id=${client.client_id}&post_logout_redirect_uri=${encodeURIComponent('https://evil.test')}`);
    expect(stranger.status).toBe(200);
    // The old cookie no longer signs anyone in.
    const { challenge } = await pkce();
    const again = await call(authorizeUrl(client.client_id, challenge), { headers: { Cookie: cookie } });
    expect(new URL(again.headers.get('Location')!, ISSUER).pathname).toBe('/login');
  });
});
