import { env, SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { cookieOf, lastMailFor, signInWithCode } from './signin';
import { Authenticator, b64u, fromB64u, ISSUER } from './webauthn';

// Enrollment (enroll.ts): a mail installation vouches for an address on its
// own domains, and its new user's browser gets a first passkey without a
// mailed code. The link is asked at the click, opens once, then only works in
// that browser - and signs in to nothing until the passkey exists.

const APP = 'https://mail.enroll.test';
const REDIRECT = `${APP}/api/auth/oidc/callback`;
const FORM = { 'Content-Type': 'application/x-www-form-urlencoded', Origin: ISSUER };
const JSON_FROM_HERE = { 'Content-Type': 'application/json', Origin: ISSUER };
const ADMIN = { Authorization: 'Bearer test-admin-key', 'Content-Type': 'application/json' };

let seq = 0;
const someIp = () => `10.${seq % 250}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;
const call = (path: string, init: RequestInit = {}) => SELF.fetch(path.startsWith('http') ? path : `${ISSUER}${path}`, { redirect: 'manual', ...init });
const post = (path: string, fields: Record<string, string>, headers: Record<string, string> = {}) =>
  call(path, { method: 'POST', headers: { ...FORM, 'CF-Connecting-IP': someIp(), ...headers }, body: new URLSearchParams(fields) });
const postJson = (path: string, body: unknown, headers: Record<string, string> = {}) =>
  call(path, { method: 'POST', headers: { ...JSON_FROM_HERE, 'CF-Connecting-IP': someIp(), ...headers }, body: JSON.stringify(body) });

type Client = { client_id: string; client_secret: string };
const basic = (c: Client) => ({ Authorization: `Basic ${btoa(`${encodeURIComponent(c.client_id)}:${encodeURIComponent(c.client_secret)}`)}`, 'Content-Type': 'application/json' });

// A mail installation with its own domain (unique per test), allowed to enroll it.
async function mailClient(opts: { reset?: boolean; domains?: string[] } = {}) {
  const domain = `club-${Date.now()}-${++seq}.test`;
  const res = await call('/admin/clients', { method: 'POST', headers: ADMIN, body: JSON.stringify({ name: 'Mailflare', redirect_uris: [REDIRECT], instance_url: APP }) });
  expect(res.status).toBe(201);
  const client = (await res.json()) as Client;
  const patched = await call(`/admin/clients/${client.client_id}`, {
    method: 'PATCH',
    headers: ADMIN,
    body: JSON.stringify({ enroll_domains: opts.domains ?? [domain.toUpperCase()], enroll_reset: !!opts.reset }),
  });
  expect(patched.status).toBe(200);
  return { ...client, domain, address: (local: string) => `${local}@${domain}` };
}

const assign = (client: Client, email: string) => call(`/clients/self/users/${encodeURIComponent(email)}`, { method: 'PUT', headers: basic(client), body: '{}' });
const authorizePath = (client: Client, extra: Record<string, string> = {}) =>
  `/authorize?${new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: REDIRECT, scope: 'openid email', state: 'st', nonce: 'n', code_challenge: 'x'.repeat(43), code_challenge_method: 'S256', ...extra })}`;
const askEnrollment = (client: Client, email: string, body: Record<string, unknown> = {}) =>
  call(`/clients/self/users/${encodeURIComponent(email)}/enrollment`, {
    method: 'POST',
    headers: basic(client),
    body: JSON.stringify({ name: 'Henk Frigg', continue_to: authorizePath(client), ...body }),
  });

async function ticketFor(client: Client, email: string, body: Record<string, unknown> = {}) {
  const res = await askEnrollment(client, email, body);
  expect(res.status, await res.clone().text()).toBe(201);
  const { url, expires_in } = (await res.json()) as { url: string; expires_in: number };
  expect(expires_in).toBe(120);
  return url;
}

// Opens the link → this browser's enrollment cookie.
async function open(url: string) {
  const res = await call(url);
  expect(res.status).toBe(302);
  expect(res.headers.get('Location')).toBe('/enroll');
  expect(res.headers.get('Set-Cookie')).toMatch(/^__Host-enroll=[^;]+; Path=\/; HttpOnly; Secure; SameSite=Lax; Max-Age=600/);
  return cookieOf(res);
}

// The page's button: options, the authenticator, the passkey → the response.
async function createPasskey(cookie: string, auth?: Authenticator) {
  const authenticator = auth ?? (await new Authenticator().init());
  const options = await postJson('/enroll/options', {}, { Cookie: cookie });
  expect(options.status).toBe(200);
  const res = await postJson('/enroll', { response: await authenticator.create(await options.json()), name: 'iPhone' }, { Cookie: cookie });
  return { res, authenticator };
}

const userOf = (email: string) => env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first<Record<string, unknown>>();
const passkeysOf = async (email: string) =>
  (await env.DB.prepare('SELECT passkeys.* FROM passkeys JOIN users ON users.id = passkeys.user_id WHERE users.email = ?').bind(email).all()).results;

describe('enrolling a new address', () => {
  it('opens once into a page that only offers a passkey; the passkey makes the account, a passkey session and continues to /authorize', async () => {
    const client = await mailClient();
    const email = client.address('henk');
    expect((await assign(client, email)).status).toBe(200);
    const cookie = await open(await ticketFor(client, email));

    const page = await (await call('/enroll', { headers: { Cookie: cookie } })).text();
    expect(page).toContain('Maak je passkey');
    expect(page).toContain(`<strong>${email}</strong>`);
    expect(page).toContain('data-options="/enroll/options"');
    expect(page).not.toContain('/login');
    expect(await userOf(email)).toBeNull();

    const { res, authenticator } = await createPasskey(cookie);
    expect(res.status, await res.clone().text()).toBe(200);
    expect(((await res.json()) as { redirect: string }).redirect).toBe(authorizePath(client));
    const user = (await userOf(email))!;
    expect(user).toMatchObject({ name: 'Henk Frigg', email_verified: 1 });
    // The passkey carries the account's id (sub), planned before the account existed.
    expect(new TextDecoder().decode(fromB64u(authenticator.userHandle))).toBe(user.id);
    expect((await passkeysOf(email)).map((k) => k.id)).toEqual([b64u(authenticator.id)]);

    // The session is a passkey's: /authorize sends the code to the application.
    const session = cookieOf(res);
    expect(session).toMatch(/^__Host-session=/);
    const amr = await env.DB.prepare('SELECT amr FROM sessions WHERE user_id = ?').bind(user.id).first<{ amr: string }>();
    expect(amr!.amr).toBe('passkey');
    const authorized = await call(authorizePath(client), { headers: { Cookie: session } });
    expect(authorized.status).toBe(302);
    expect(new URL(authorized.headers.get('Location')!).origin + new URL(authorized.headers.get('Location')!).pathname).toBe(REDIRECT);
    expect((await lastMailFor(email)).subject).toMatch(/passkey/i);

    // Used: neither the link nor the cookie works again.
    expect((await postJson('/enroll/options', {}, { Cookie: cookie })).status).toBe(400);
    expect((await call('/enroll', { headers: { Cookie: cookie } })).status).toBe(400);
  });

  it('the link opens once and within two minutes; afterwards only the browser that opened it continues; only the newest link works', async () => {
    const client = await mailClient();
    const email = client.address('once');
    await assign(client, email);
    const url = await ticketFor(client, email);
    const cookie = await open(url);
    // A second open (a leaked link, another browser): nothing.
    expect((await call(url)).status).toBe(400);
    // Without this browser's cookie: nothing either.
    expect((await postJson('/enroll/options', {})).status).toBe(400);
    expect((await postJson('/enroll/options', {}, { Cookie: '__Host-enroll=forged' })).status).toBe(400);
    // Not from our own pages: refused.
    expect((await postJson('/enroll/options', {}, { Cookie: cookie, Origin: 'https://evil.test' })).status).toBe(403);

    // A newer link replaces it (even one already opened).
    const newer = await ticketFor(client, email);
    expect((await postJson('/enroll/options', {}, { Cookie: cookie })).status).toBe(400);

    // Not opened within two minutes: gone.
    await env.DB.prepare("UPDATE enrollments SET expires_at = '2000-01-01T00:00:00.000Z' WHERE email = ? AND used_at IS NULL").bind(email).run();
    expect((await call(newer)).status).toBe(400);

    // Opened but not finished within ten minutes: gone.
    const late = await open(await ticketFor(client, email));
    await env.DB.prepare("UPDATE enrollments SET opened_until = '2000-01-01T00:00:00.000Z' WHERE email = ? AND used_at IS NULL").bind(email).run();
    expect((await postJson('/enroll/options', {}, { Cookie: late })).status).toBe(400);
    expect(await userOf(email)).toBeNull();
  });

  it('signs in to nothing before the passkey exists', async () => {
    const client = await mailClient();
    const email = client.address('nothing');
    await assign(client, email);
    const cookie = await open(await ticketFor(client, email));
    const account = await call('/account', { headers: { Cookie: cookie } });
    expect(account.status).toBe(302);
    expect(account.headers.get('Location')).toMatch(/^\/login/);
    const authorized = await call(authorizePath(client), { headers: { Cookie: cookie } });
    expect(authorized.headers.get('Location')).toMatch(/^\/login/);
    expect((await postJson('/passkey/register/options', {}, { Cookie: cookie })).status).toBe(401);
  });

  it("a challenge from /passkey/register can't finish an enrollment, nor the other way round", async () => {
    const client = await mailClient();
    const email = client.address('mixed');
    await assign(client, email);
    const cookie = await open(await ticketFor(client, email));
    const auth = await new Authenticator().init();
    const options = (await (await postJson('/enroll/options', {}, { Cookie: cookie })).json()) as any;
    // Someone signed in elsewhere tries the enrollment's challenge on their own account: refused.
    const other = await signInWithCode(post, `other-${Date.now()}@example.test`);
    expect((await postJson('/passkey/register', { response: await auth.create(options) }, { Cookie: other.cookie })).status).toBe(400);
  });
});

describe('what a client may enroll', () => {
  it('only addresses on the domains a platform admin listed, assigned to it, for its own /authorize', async () => {
    const client = await mailClient();
    const email = client.address('rules');
    // Not assigned yet.
    expect(await (await askEnrollment(client, email)).json()).toEqual({ error: 'not_assigned' });
    await assign(client, email);
    // Another domain - even one assigned to the client.
    const foreign = `someone-${Date.now()}@gmail.test`;
    await assign(client, foreign);
    const refused = await askEnrollment(client, foreign);
    expect(refused.status).toBe(403);
    expect(await refused.json()).toEqual({ error: 'not_allowed' });
    // A lookalike of its domain.
    const lookalike = `x@evil${client.domain}`;
    await assign(client, lookalike);
    expect((await askEnrollment(client, lookalike)).status).toBe(403);
    // continue_to: nowhere but its own /authorize with its own redirect URI.
    const other = await mailClient();
    for (const continue_to of [
      `${ISSUER}${authorizePath(client)}`,
      authorizePath(other),
      authorizePath(client, { redirect_uri: 'https://evil.test/cb' }),
      '/account',
      '/login/passkey?continue=/account',
    ]) {
      expect((await askEnrollment(client, email, { continue_to })).status, continue_to).toBe(400);
    }
    // Another client's credentials, or none.
    expect((await call(`/clients/self/users/${encodeURIComponent(email)}/enrollment`, { method: 'POST', body: '{}' })).status).toBe(401);
    expect((await askEnrollment({ ...client, client_secret: 'wrong' }, email)).status).toBe(401);
    // A client nobody listed domains for.
    const plain = (await (await call('/admin/clients', { method: 'POST', headers: ADMIN, body: JSON.stringify({ name: 'Other', redirect_uris: [REDIRECT] }) })).json()) as Client;
    await assign(plain, email);
    expect(await (await askEnrollment(plain, email, { continue_to: authorizePath(plain) })).json()).toEqual({ error: 'not_allowed' });
  });

  it("never for an account that already has a way in, and reset only where a platform admin allowed it", async () => {
    const client = await mailClient();
    const email = client.address('has');
    await assign(client, email);
    const first = await open(await ticketFor(client, email));
    expect((await createPasskey(first)).res.status).toBe(200);
    const again = await askEnrollment(client, email);
    expect(again.status).toBe(409);
    expect(await again.json()).toEqual({ error: 'enrolled' });
    expect(await (await askEnrollment(client, email, { reset: true })).json()).toEqual({ error: 'reset_not_allowed' });
  });

  it('checks again at the end: unassigned or enrolled meanwhile, nothing happens', async () => {
    const client = await mailClient();
    const email = client.address('race');
    await assign(client, email);
    const cookie = await open(await ticketFor(client, email));
    await call(`/clients/self/users/${encodeURIComponent(email)}`, { method: 'DELETE', headers: basic(client) });
    expect((await createPasskey(cookie)).res.status).toBe(400);
    expect(await userOf(email)).toBeNull();
  });

  it('a platform admin sets the domains: valid names only, never the client itself', async () => {
    const client = await mailClient();
    for (const enroll_domains of [['not a domain'], ['frigg'], 'frigg.be', ['*.frigg.be']]) {
      expect((await call(`/admin/clients/${client.client_id}`, { method: 'PATCH', headers: ADMIN, body: JSON.stringify({ enroll_domains }) })).status).toBe(400);
    }
    const listed = ((await (await call('/admin/clients', { headers: ADMIN })).json()) as any[]).find((c) => c.client_id === client.client_id);
    expect(listed).toMatchObject({ enroll_domains: [client.domain], enroll_reset: false });
    // The client's own PATCH ignores it.
    await call('/clients/self', { method: 'PATCH', headers: basic(client), body: JSON.stringify({ enroll_domains: ['gmail.com'], redirect_uris: [REDIRECT] }) });
    const after = ((await (await call('/admin/clients', { headers: ADMIN })).json()) as any[]).find((c) => c.client_id === client.client_id);
    expect(after.enroll_domains).toEqual([client.domain]);
  });

  it('a stolen secret can only ask so many', async () => {
    const client = await mailClient();
    const email = client.address('many');
    await assign(client, email);
    const statuses: number[] = [];
    for (let i = 0; i < 6; i++) statuses.push((await askEnrollment(client, email)).status);
    expect(statuses).toEqual([201, 201, 201, 201, 201, 429]);
  });
});

describe('starting over (reset)', () => {
  it('replaces the passkeys and Google, ends every session and refresh token, and tells the account by mail', async () => {
    const client = await mailClient({ reset: true });
    const email = client.address('lost');
    await assign(client, email);
    const old = await createPasskey(await open(await ticketFor(client, email)));
    const oldSession = cookieOf(old.res);
    const user = (await userOf(email))!;
    await env.DB.prepare("UPDATE users SET google_sub = 'google-lost' WHERE id = ?").bind(user.id).run();

    const cookie = await open(await ticketFor(client, email, { reset: true }));
    const { res, authenticator } = await createPasskey(cookie);
    expect(res.status, await res.clone().text()).toBe(200);
    expect((await passkeysOf(email)).map((k) => k.id)).toEqual([b64u(authenticator.id)]);
    expect((await userOf(email))!).toMatchObject({ id: user.id, google_sub: null });
    // The old browser is signed out; the new one is in.
    expect((await call('/account', { headers: { Cookie: oldSession } })).status).toBe(302);
    expect((await call('/account', { headers: { Cookie: cookieOf(res) } })).status).toBe(200);
    expect((await lastMailFor(email)).subject).toBe('Je aanmelding werd opnieuw ingesteld');
  });
});
