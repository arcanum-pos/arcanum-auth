import { env, SELF } from 'cloudflare:test';
import { createLocalJWKSet, decodeJwt, jwtVerify } from 'jose';
import { describe, expect, it } from 'vitest';
import { askCode, cookieOf, lastCodeFor, lastLinkFor, signInWithCode } from './signin';

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


async function newClient(name = 'Test installation') {
  const res = await call('/admin/clients', {
    method: 'POST',
    headers: { Authorization: 'Bearer test-admin-key', 'Content-Type': 'application/json' },
    body: JSON.stringify({ name, redirect_uris: [REDIRECT], post_logout_redirect_uris: [APP] }),
  });
  expect(res.status).toBe(201);
  return (await res.json()) as { client_id: string; client_secret: string };
}

async function mails(): Promise<{ body: { message: { to: string; subject: string; text: string } } }[]> {
  return (await (await env.MAILER!.fetch('https://mailer/__calls')).json()) as never;
}

// A new account, signed in with its mailed code → session cookie.
async function signUp(email: string, name = 'Jan Peeters'): Promise<string> {
  return (await signInWithCode(post, email, { name })).cookie;
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

    const { id } = await askCode(post, email, continueTo);
    const wrong = await post('/login/code', { id, code: (await lastCodeFor(email)) === '000000' ? '111111' : '000000' });
    expect(wrong.status).toBe(400);
    const ok = await post('/login/code', { id, code: await lastCodeFor(email) });
    expect(ok.status).toBe(302);
    // No passkey yet: once by way of the offer to add one, then on.
    expect(ok.headers.get('Location')).toBe(`/passkey/offer?continue=${encodeURIComponent(continueTo)}`);
    const notNow = await post('/passkey/offer', { continue: continueTo }, { Cookie: cookieOf(ok) });
    expect(notNow.headers.get('Location')).toBe(continueTo);
    const again = await signInWithCode(post, email, { continueTo });
    expect(again.next).toBe(continueTo);
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

    // Again right away: a parallel request of the same app — fresh tokens, nothing revoked.
    const parallel = await refresh(first);
    expect(parallel.status).toBe(200);
    expect((await refresh(((await parallel.json()) as Record<string, string>).refresh_token)).status).toBe(200);

    // Again after the grace window: a stolen copy.
    await env.DB.prepare('UPDATE refresh_tokens SET rotated_at = ? WHERE rotated_at IS NOT NULL AND client_id = ?').bind(new Date(Date.now() - 60_000).toISOString(), client.client_id).run();
    expect(((await (await refresh(first)).json()) as Record<string, string>).error).toBe('invalid_grant');
    // The theft response also killed the newer one.
    expect(((await (await refresh(second)).json()) as Record<string, string>).error).toBe('invalid_grant');
  });

  it('the grace window ends at a revocation: an old token gets nothing', async () => {
    const client = await newClient();
    const email = uniqueEmail('refresh-reset');
    const { tokenRes } = await codeFlow(client, await signUp(email));
    const first = ((await tokenRes.json()) as Record<string, string>).refresh_token;
    const refresh = (token: string) => post('/token', { grant_type: 'refresh_token', refresh_token: token, client_id: client.client_id, client_secret: client.client_secret });
    expect((await refresh(first)).status).toBe(200);
    // Everything of this user revoked, within the window.
    const user = (await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first<{ id: string }>())!;
    await env.DB.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').bind(new Date(Date.now() + 1000).toISOString(), user.id).run();
    expect(((await (await refresh(first)).json()) as Record<string, string>).error).toBe('invalid_grant');
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

describe('accounts, without passwords', () => {
  it('one flow: a new address gets its account after its code and its name; next time the code alone', async () => {
    const email = uniqueEmail('new');
    const { id } = await askCode(post, email);
    expect(await env.DB.prepare('SELECT 1 FROM users WHERE email = ?').bind(email).first()).toBeNull();
    const mail = (await mails()).reverse().find((m) => m.body.message.to === email)!.body.message;
    expect(mail.subject).toBe('Je aanmeldcode');
    expect(mail.text).toContain(`${ISSUER}/login/link?id=${id}&t=`);
    const asked = await post('/login/code', { id, code: await lastCodeFor(email) });
    expect(asked.status).toBe(200);
    const html = await asked.text();
    expect(html).toContain('Hoe heet je?');
    // Proven, but not yet an account: that takes the name.
    expect(await env.DB.prepare('SELECT 1 FROM users WHERE email = ?').bind(email).first()).toBeNull();
    const finish = html.match(/name="finish" value="([^"]+)"/)![1];
    expect((await post('/login/name', { id, finish, name: '  ' })).status).toBe(400);
    const named = await post('/login/name', { id, finish, name: 'Mie Peeters' });
    expect(named.status).toBe(302);
    expect(cookieOf(named)).toMatch(/^__Host-session=/);
    expect(await env.DB.prepare('SELECT name, email_verified, password_hash FROM users WHERE email = ?').bind(email).first()).toEqual({ name: 'Mie Peeters', email_verified: 1, password_hash: null });
    // Its name step only once.
    expect((await post('/login/name', { id, finish, name: 'Someone else' })).status).toBe(400);
    // The next time: the code alone.
    const next = await askCode(post, email);
    expect((await post('/login/code', { id: next.id, code: await lastCodeFor(email) })).status).toBe(302);
  });

  it("never says whether an address has an account, and a code only works once", async () => {
    const known = uniqueEmail('known');
    await signUp(known);
    const a = await post('/login', { email: known, continue: '/account' });
    const b = await post('/login', { email: uniqueEmail('unknown'), continue: '/account' });
    expect([a.status, b.status]).toEqual([302, 302]);
    expect(new URL(a.headers.get('Location')!, ISSUER).pathname).toBe(new URL(b.headers.get('Location')!, ISSUER).pathname);
    const id = new URL(a.headers.get('Location')!, ISSUER).searchParams.get('id')!;
    const code = await lastCodeFor(known);
    expect((await post('/login/code', { id, code })).status).toBe(302);
    expect((await post('/login/code', { id, code })).status).toBe(400);
  });

  it('the link: a button, never a sign-in on opening it; in the browser that asked directly, elsewhere it says so; once', async () => {
    const email = uniqueEmail('link');
    await signUp(email);
    const { browser } = await askCode(post, email);
    const link = new URL(await lastLinkFor(email));
    const elsewhere = await call(`${link.pathname}${link.search}`);
    expect(elsewhere.status).toBe(200);
    expect(elsewhere.headers.get('Set-Cookie')).toBeNull();
    expect(await elsewhere.text()).toContain('ander toestel');
    const here = await call(`${link.pathname}${link.search}`, { headers: { Cookie: browser } });
    const html = await here.text();
    expect(html).not.toContain('ander toestel');
    expect(html).toContain(`Aanmelden als ${email}?`);
    const fields = { id: link.searchParams.get('id')!, t: link.searchParams.get('t')! };
    expect((await post('/login/link', { ...fields, t: 'wrong' })).status).toBe(400);
    const signedIn = await post('/login/link', fields);
    expect(signedIn.status).toBe(302);
    expect(cookieOf(signedIn)).toMatch(/^__Host-session=/);
    // Used: neither the link nor its code works again.
    expect((await call(`${link.pathname}${link.search}`)).status).toBe(400);
    expect((await post('/login/link', fields)).status).toBe(400);
  });

  it('a new address through the link: also asked its name', async () => {
    const email = uniqueEmail('link-new');
    await askCode(post, email);
    const link = new URL(await lastLinkFor(email));
    const res = await post('/login/link', { id: link.searchParams.get('id')!, t: link.searchParams.get('t')! });
    expect(res.status).toBe(200);
    expect(await res.text()).toContain('Hoe heet je?');
  });

  it('the old pages (sign-up, verify, password reset) lead to sign-in', async () => {
    for (const path of ['/signup?continue=%2Faccount', '/reset', '/verify?id=x']) {
      const res = await call(path);
      expect(res.status).toBe(303);
      expect(res.headers.get('Location')).toBe('/login?continue=%2Faccount');
    }
    expect((await post('/signup', { email: uniqueEmail('old'), password: 'correct horse battery' })).status).toBe(303);
    // A password sent along is ignored: it's just a request for a code.
    expect((await call('/login')).status).toBe(200);
    expect(await (await call('/login')).text()).not.toContain('type="password"');
  });

  it("accepts its own page's form when the browser sends Origin: null (Sec-Fetch-Site decides)", async () => {
    const own = await post('/login', { email: uniqueEmail('nullorigin'), continue: '/account' }, { Origin: 'null', 'Sec-Fetch-Site': 'same-origin' });
    expect(own.status).toBe(302);
    const unknown = await post('/login', { email: uniqueEmail('nullorigin2') }, { Origin: 'null' });
    expect(unknown.status).toBe(403);
    const crossSite = await post('/login', { email: uniqueEmail('nullorigin3') }, { Origin: 'null', 'Sec-Fetch-Site': 'cross-site' });
    expect(crossSite.status).toBe(403);
  });

  it('pages send a referrer policy that keeps Origin on their own form posts', async () => {
    const res = await call('/login');
    expect(res.headers.get('Referrer-Policy')).toBe('same-origin');
  });

  it('refuses a form post from another site (CSRF)', async () => {
    const res = await call('/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: 'https://evil.test' }, body: 'email=a@b.c' });
    expect(res.status).toBe(403);
  });
});

describe('sign in with Google', () => {
  it('starts at Google, and links to the account with the same e-mail (same sub)', async () => {
    const email = uniqueEmail('google');
    await signUp(email);
    const before = await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first<{ id: string }>();

    const start = await call('/google?continue=%2Faccount');
    const target = new URL(start.headers.get('Location')!);
    expect(target.origin).toBe('https://accounts.google.com');
    expect(target.searchParams.get('redirect_uri')).toBe(`${ISSUER}/callback/google`);

    const back = await call(`/callback/google?code=${encodeURIComponent(email)}&state=${target.searchParams.get('state')}`, { headers: { Cookie: cookieOf(start) } });
    expect(back.status).toBe(302);
    expect(cookieOf(back)).toMatch(/^__Host-session=/);
    const after = await env.DB.prepare('SELECT id, google_sub FROM users WHERE email = ?').bind(email).first<{ id: string; google_sub: string }>();
    expect(after).toEqual({ id: before!.id, google_sub: `google-${email}` });
  });

  it('refuses an unverified Google address and a replayed state', async () => {
    const start = await call('/google?continue=%2Faccount');
    const state = new URL(start.headers.get('Location')!).searchParams.get('state')!;
    const browser = { headers: { Cookie: cookieOf(start) } };
    const res = await call(`/callback/google?code=unverified-${uniqueEmail('g')}&state=${state}`, browser);
    expect(res.status).toBe(400);
    const replay = await call(`/callback/google?code=${uniqueEmail('g2')}&state=${state}`, browser);
    expect(replay.status).toBe(400);
  });

  it("only finishes in the browser that started it (no login CSRF): someone else's callback link signs nobody in", async () => {
    const start = await call('/google?continue=%2Faccount');
    const stateCookie = start.headers.get('Set-Cookie')!;
    expect(stateCookie).toMatch(/^__Host-google_state=[^;]+; Path=\/; HttpOnly; Secure; SameSite=Lax/);
    const state = new URL(start.headers.get('Location')!).searchParams.get('state')!;
    const link = `/callback/google?code=${encodeURIComponent(uniqueEmail('attacker'))}&state=${state}`;
    // The victim's browser: no state cookie, or another login's.
    expect((await call(link)).status).toBe(400);
    expect((await call(link, { headers: { Cookie: '__Host-google_state=someone-elses' } })).status).toBe(400);
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

describe('no product name', () => {
  it('pages and mails name only this sign-in service (any application may use it)', async () => {
    const html = await (await call('/login')).text();
    expect(html).toContain('<div class="brand">login.kaboutersoft.be</div>');
    expect(html.toLowerCase()).not.toContain('arcanum');
    const email = uniqueEmail('noname');
    await askCode(post, email);
    const mail = (await mails()).reverse().find((m) => m.body.message.to === email)!.body.message;
    expect(`${mail.subject} ${mail.text}`.toLowerCase()).not.toContain('arcanum');
  });

  it('a session under the old cookie name still counts, and signing out clears both', async () => {
    const cookie = await signUp(uniqueEmail('oldcookie'));
    const old = cookie.replace(/^__Host-session=/, '__Host-arcanum_auth=');
    expect((await call('/account', { headers: { Cookie: old } })).status).toBe(200);
    const out = await call('/logout', { headers: { Cookie: old } });
    expect(out.headers.get('Set-Cookie')).toMatch(/__Host-session=;.*__Host-arcanum_auth=;/);
    expect((await call('/account', { headers: { Cookie: old } })).status).toBe(302);
  });
});
