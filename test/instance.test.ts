// Phase 1 of AUTH_DEDICATED.md: SIGN_IN=google, GOOGLE_HOSTED_DOMAIN,
// PRODUCT_NAME and an issuer with a trailing slash - and, with none of them
// set, every route as before.
import { env } from 'cloudflare:test';
import { decodeJwt } from 'jose';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import { admin, call, codeFlow, form, googleSignIn, ISSUER, newClient, pkce, someIp, unique, withEnv } from './dedicated';

const GOOGLE = withEnv({ SIGN_IN: 'google' });
const WORKSPACE = withEnv({ SIGN_IN: 'google', GOOGLE_HOSTED_DOMAIN: 'radioscorpio.test' });

// What SIGN_IN=google switches off (index.ts), with how each one answers on
// the shared instance (no setting): never a 404 there.
const OFF: [string, string][] = [
  ['POST', '/login'],
  ['GET', '/login/code'],
  ['GET', '/login/link'],
  ['POST', '/login/name'],
  ['GET', '/login/passkey'],
  ['GET', '/login/once'],
  ['GET', '/enroll'],
  ['POST', '/enroll/options'],
  ['GET', '/device'],
  ['POST', '/device/confirm'],
  ['POST', '/device/code'],
  ['GET', '/passkey.js'],
  ['POST', '/passkey/login/options'],
  ['POST', '/passkey/register/options'],
  ['GET', '/passkey/offer'],
  ['POST', '/account/passkeys'],
  ['POST', '/account/google'],
  ['GET', '/clients/self'],
  ['GET', '/clients/self/users'],
  ['GET', '/access/some-client'],
  ['POST', '/access/some-client/request'],
];

function send(e: Env, method: string, path: string) {
  return call(e, path, { method, headers: { 'Content-Type': 'application/x-www-form-urlencoded', Origin: ISSUER, 'CF-Connecting-IP': someIp() }, body: method === 'POST' ? 'x=1' : undefined });
}

describe('with no new setting (the shared instance)', () => {
  it('every route SIGN_IN=google switches off is there', async () => {
    for (const [method, path] of OFF) expect([method, path, (await send(env, method, path)).status]).not.toEqual([method, path, 404]);
  });

  it('discovery advertises the device flow and client self-service; the issuer is exact', async () => {
    const d = (await (await call(env, '/.well-known/openid-configuration')).json()) as Record<string, unknown>;
    expect(d.issuer).toBe(ISSUER);
    expect(d.device_authorization_endpoint).toBe(`${ISSUER}/device/code`);
    expect(d.client_users_endpoint).toBe(`${ISSUER}/clients/self/users`);
    expect(d.grant_types_supported).toEqual(['authorization_code', 'refresh_token', 'urn:ietf:params:oauth:grant-type:device_code']);
  });

  it('/login is the e-mail form, Google sends no hd, pages name the host', async () => {
    const page = await (await call(env, '/login')).text();
    expect(page).toContain('name="email"');
    expect(page).toContain('<div class="brand">login.kaboutersoft.be</div>');
    const start = await call(env, '/google?continue=%2Faccount', { headers: { 'CF-Connecting-IP': someIp() } });
    expect(new URL(start.headers.get('Location')!).searchParams.has('hd')).toBe(false);
  });

  it('a Workspace account and any other both sign in with Google (no hd check)', async () => {
    expect((await googleSignIn(env, `hd:other.test:${unique('ws', 'other.test')}`)).res.status).toBe(302);
    expect((await googleSignIn(env, unique('gmail', 'gmail.test'))).res.status).toBe(302);
  });

  it('tools/admin still requires a passkey: a Google session is sent to the passkey step', async () => {
    const { cookie } = await googleSignIn(env, 'tool-admin@example.test');
    const { challenge } = await pkce();
    const res = await call(env, `/authorize?${new URLSearchParams({ response_type: 'code', client_id: 'arcanum-auth-admin', redirect_uri: 'http://127.0.0.1:8799/callback', scope: 'openid email', code_challenge: challenge, code_challenge_method: 'S256' })}`, { headers: { Cookie: cookie } });
    expect(res.headers.get('Location')).toMatch(/^\/login\/passkey\?continue=/);
  });

  it('an instance without APIs ignores an audience, as before: aud is the client, nothing refused', async () => {
    const client = await newClient(env);
    const { cookie } = await googleSignIn(env, unique('aud'));
    const flow = await codeFlow(env, client, cookie, { audience: 'https://some-api.test' });
    expect(flow.status).toBe(200);
    const at = decodeJwt(String(flow.body.access_token));
    expect(at.aud).toBe(client.client_id);
    expect(at.permissions).toBeUndefined();
    expect(await env.DB.prepare('SELECT audience FROM refresh_tokens WHERE client_id = ?').bind(client.client_id).first()).toEqual({ audience: null });
  });

  it('/admin/instance tells the settings: all off by default; the shared instance has Auth0 compatibility on (wrangler.jsonc)', async () => {
    const res = await admin(withEnv({ AUTH0_COMPAT: undefined }), 'GET', '/admin/instance');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ issuer: ISSUER, sign_in: 'all', google_hosted_domain: null, product_name: null, auth0_compat: false, actions: false, self_service: true, device_flow: true });
    expect((await admin(env, 'GET', '/admin/instance')).body).toMatchObject({ auth0_compat: true, sign_in: 'all', self_service: true, device_flow: true });
  });
});

describe('SIGN_IN=google', () => {
  it('switches every other way of signing in off (404)', async () => {
    for (const [method, path] of OFF) expect([method, path, (await send(GOOGLE, method, path)).status]).toEqual([method, path, 404]);
  });

  it('the sign-in page goes straight to Google, the continue kept', async () => {
    const res = await call(GOOGLE, '/login?continue=%2Faccount');
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toBe('/google?continue=%2Faccount');
  });

  it('discovery: no device endpoint or grant, no client self-service', async () => {
    const d = (await (await call(GOOGLE, '/.well-known/openid-configuration')).json()) as Record<string, unknown>;
    expect(d.device_authorization_endpoint).toBeUndefined();
    expect(d.client_users_endpoint).toBeUndefined();
    expect(d.grant_types_supported).toEqual(['authorization_code', 'refresh_token']);
    expect(d.authorization_endpoint).toBe(`${ISSUER}/authorize`);
  });

  it('the token endpoint refuses the device grant; guests and their links are off', async () => {
    const client = await newClient(GOOGLE);
    const res = await form(GOOGLE, '/token', { grant_type: 'urn:ietf:params:oauth:grant-type:device_code', device_code: 'x', client_id: client.client_id, client_secret: client.client_secret });
    expect(((await res.json()) as { error: string }).error).toBe('unsupported_grant_type');
    expect((await admin(GOOGLE, 'POST', '/admin/guests', {})).status).toBe(404);
    expect((await admin(GOOGLE, 'POST', '/admin/login-links', {})).status).toBe(404);
    // The shared instance keeps its guests.
    expect((await admin(env, 'POST', '/admin/guests', {})).status).toBe(201);
  });

  it('signs in with Google without a passkey offer; /account is reduced to who you are and sessions', async () => {
    const email = unique('google-only');
    const { res, cookie } = await googleSignIn(GOOGLE, email);
    expect(res.status).toBe(302);
    expect(res.headers.get('Location')).toBe('/account');
    const page = await (await call(GOOGLE, '/account', { headers: { Cookie: cookie } })).text();
    expect(page).toContain(email);
    expect(page).toContain('action="/account/sessions"');
    expect(page).not.toContain('Passkeys');
    expect(page).not.toContain('/passkey.js');
    expect(page).not.toContain('/account/google');
    // Signing out of every session still works.
    const out = await form(GOOGLE, '/account/sessions', { action: 'everywhere' }, { Cookie: cookie, Origin: ISSUER });
    expect(out.headers.get('Location')).toBe('/account?ended=everywhere');
  });

  it('a restricted client without access: a plain refusal, no request to send', async () => {
    const client = await newClient(GOOGLE, { restricted: true });
    const { cookie } = await googleSignIn(GOOGLE, unique('outsider'));
    const { challenge } = await pkce();
    const res = await call(GOOGLE, `/authorize?${new URLSearchParams({ response_type: 'code', client_id: client.client_id, redirect_uri: 'https://scorpio-app.test/callback', code_challenge: challenge, code_challenge_method: 'S256' })}`, { headers: { Cookie: cookie } });
    expect(res.status).toBe(403);
    expect(await res.text()).not.toContain('/request');
  });

  it('a client marked "passkey required" lets a Google session through (no passkeys here)', async () => {
    const client = await newClient(GOOGLE);
    expect((await admin(GOOGLE, 'PATCH', `/admin/clients/${client.client_id}`, { require_passkey: true })).status).toBe(200);
    const { cookie } = await googleSignIn(GOOGLE, unique('pk'));
    const flow = await codeFlow(GOOGLE, client, cookie);
    expect(flow.status).toBe(200);
  });

  it('tools/admin: an ADMIN_EMAILS address signs in with Google, its token opens the admin API', async () => {
    const { cookie } = await googleSignIn(GOOGLE, 'second@example.test');
    const flow = await codeFlow(GOOGLE, { client_id: 'arcanum-auth-admin' }, cookie, { scope: 'openid email', prompt: '' }, 'http://127.0.0.1:8799/callback');
    expect(flow.status).toBe(200);
    expect(flow.body.refresh_token).toBeUndefined();
    const info = await admin(GOOGLE, 'GET', '/admin/info', undefined, { Authorization: `Bearer ${flow.body.access_token}` });
    expect(info.status).toBe(200);
    expect(info.body).toMatchObject({ you: 'second@example.test', protections_off: [] });
    // Someone else with Google: refused by the admin client.
    const other = await googleSignIn(GOOGLE, unique('not-admin'));
    const { challenge } = await pkce();
    const refused = await call(GOOGLE, `/authorize?${new URLSearchParams({ response_type: 'code', client_id: 'arcanum-auth-admin', redirect_uri: 'http://127.0.0.1:8799/callback', code_challenge: challenge, code_challenge_method: 'S256' })}`, { headers: { Cookie: other.cookie } });
    expect(refused.status).toBe(403);
  });

  it('/admin/instance says so', async () => {
    expect((await admin(WORKSPACE, 'GET', '/admin/instance')).body).toMatchObject({ sign_in: 'google', sign_in_methods: ['google'], google_hosted_domain: 'radioscorpio.test', self_service: false, device_flow: false });
  });
});

describe('GOOGLE_HOSTED_DOMAIN', () => {
  it('is sent to Google as hd', async () => {
    const start = await call(WORKSPACE, '/google?continue=%2Faccount', { headers: { 'CF-Connecting-IP': someIp() } });
    expect(new URL(start.headers.get('Location')!).searchParams.get('hd')).toBe('radioscorpio.test');
  });

  it('a Workspace account of that domain signs in', async () => {
    const { res, cookie } = await googleSignIn(WORKSPACE, `hd:radioscorpio.test:${unique('jan', 'radioscorpio.test')}`);
    expect(res.status).toBe(302);
    expect(cookie).toMatch(/^__Host-session=/);
  });

  it('another Workspace or a plain Google account is refused: no session, no user', async () => {
    for (const code of [`hd:other.test:${unique('x', 'other.test')}`, unique('gmail', 'gmail.test'), `hd:RADIOSCORPIO.test.evil:${unique('y', 'evil.test')}`]) {
      const { res, cookie } = await googleSignIn(WORKSPACE, code);
      expect(res.status).toBe(403);
      expect(cookie).not.toMatch(/^__Host-session=./);
      const email = code.replace(/^hd:[^:]+:/, '');
      expect(await env.DB.prepare('SELECT 1 FROM users WHERE email = ?').bind(email).first()).toBeNull();
    }
  });

  it('an imported user on an alias domain of the Workspace links on first sign-in (no mailed code on this instance)', async () => {
    const email = unique('alias', 'scorpio-alias.test');
    expect((await admin(WORKSPACE, 'POST', '/admin/users', { id: `google-apps|${email}`, email, name: 'Alias' })).status).toBe(201);
    const { res } = await googleSignIn(WORKSPACE, `hd:radioscorpio.test:${email}`);
    expect(res.status).toBe(302);
    expect((await env.DB.prepare('SELECT google_sub FROM users WHERE email = ?').bind(email).first<{ google_sub: string }>())!.google_sub).toBe(`google-${email}`);
  });

  it('hd is compared without case', async () => {
    expect((await googleSignIn(WORKSPACE, `hd:RadioScorpio.test:${unique('case', 'radioscorpio.test')}`)).res.status).toBe(302);
  });
});

describe('PRODUCT_NAME', () => {
  it('names the sign-in pages instead of the host', async () => {
    const named = withEnv({ PRODUCT_NAME: 'Radio Scorpio' });
    const page = await (await call(named, '/login')).text();
    expect(page).toContain('<div class="brand">Radio Scorpio</div>');
    expect(page).toContain('· Radio Scorpio</title>');
    expect(page).not.toContain('<div class="brand">login.kaboutersoft.be</div>');
    expect(await (await call(named, '/nowhere')).text()).toContain('<div class="brand">Radio Scorpio</div>');
  });
});

describe('ISSUER with a trailing slash (Auth0 style)', () => {
  const SLASH = withEnv({ ISSUER: `${ISSUER}/` });

  it('discovery: iss exactly as given, every URL without a double slash', async () => {
    const d = (await (await call(SLASH, '/.well-known/openid-configuration')).json()) as Record<string, string>;
    expect(d.issuer).toBe(`${ISSUER}/`);
    for (const k of ['authorization_endpoint', 'token_endpoint', 'userinfo_endpoint', 'end_session_endpoint', 'jwks_uri', 'device_authorization_endpoint']) {
      expect(d[k].startsWith(`${ISSUER}/`)).toBe(true);
      expect(d[k].slice(8)).not.toContain('//');
    }
  });

  it('tokens carry iss with the slash, /userinfo accepts them, the authorization response says the same iss', async () => {
    const client = await newClient(SLASH);
    const { cookie } = await googleSignIn(SLASH, unique('slash'));
    const flow = await codeFlow(SLASH, client, cookie);
    expect(flow.authorize.searchParams.get('iss')).toBe(`${ISSUER}/`);
    expect(flow.status).toBe(200);
    expect(decodeJwt(String(flow.body.access_token)).iss).toBe(`${ISSUER}/`);
    expect(decodeJwt(String(flow.body.id_token)).iss).toBe(`${ISSUER}/`);
    const me = await call(SLASH, '/userinfo', { headers: { Authorization: `Bearer ${flow.body.access_token}` } });
    expect(me.status).toBe(200);
    // Without the slash it's another issuer: refused.
    expect((await call(env, '/userinfo', { headers: { Authorization: `Bearer ${flow.body.access_token}` } })).status).toBe(401);
  });

  it('Google comes back to /callback/google, not //callback/google', async () => {
    const start = await call(SLASH, '/google?continue=%2Faccount', { headers: { 'CF-Connecting-IP': someIp() } });
    expect(new URL(start.headers.get('Location')!).searchParams.get('redirect_uri')).toBe(`${ISSUER}/callback/google`);
  });
});
