// Phase 5 of AUTH_DEDICATED.md: AUTH0_COMPAT - /oauth/token, JSON bodies,
// /v2/logout, `connection` ignored. Off: none of it, as before.
import { env } from 'cloudflare:test';
import { decodeJwt } from 'jose';
import { describe, expect, it } from 'vitest';
import type { Env } from '../src/env';
import { admin, APP, call, cookieOf, form, googleSignIn, ISSUER, newClient, pkce, REDIRECT, unique, withEnv } from './dedicated';

const COMPAT = withEnv({ AUTH0_COMPAT: 'true' });
// Radio Scorpio's shape: Google Workspace only, Auth0's paths, the slash issuer.
const SCORPIO = withEnv({ AUTH0_COMPAT: 'true', SIGN_IN: 'google', GOOGLE_HOSTED_DOMAIN: 'radioscorpio.test', ISSUER: `${ISSUER}/` });

const jsonPost = (e: Env, path: string, body: Record<string, unknown>, headers: Record<string, string> = {}) =>
  call(e, path, { method: 'POST', headers: { 'Content-Type': 'application/json', ...headers }, body: JSON.stringify(body) });

// A signed-in browser's code, ready to exchange.
async function codeFor(e: Env, clientId: string, cookie: string, extra: Record<string, string> = {}) {
  const { verifier, challenge } = await pkce();
  const res = await call(e, `/authorize?${new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: REDIRECT, scope: 'openid profile email offline_access', code_challenge: challenge, code_challenge_method: 'S256', ...extra })}`, { headers: { Cookie: cookie } });
  const back = new URL(res.headers.get('Location')!);
  return { code: back.searchParams.get('code')!, verifier, back };
}

describe('with AUTH0_COMPAT unset (the shared instance)', () => {
  it('/oauth/token and /v2/logout are unknown', async () => {
    expect((await form(env, '/oauth/token', { grant_type: 'client_credentials' })).status).toBe(404);
    expect((await call(env, '/v2/logout?returnTo=https%3A%2F%2Fscorpio-app.test')).status).toBe(404);
  });

  it('a JSON body at /token is not read: no client', async () => {
    const client = await newClient(env);
    const res = await jsonPost(env, '/token', { grant_type: 'refresh_token', refresh_token: 'x', client_id: client.client_id, client_secret: client.client_secret });
    expect(res.status).toBe(401);
  });

  it('connection is ignored on /authorize', async () => {
    const client = await newClient(env);
    const { cookie } = await googleSignIn(env, unique('conn'));
    expect((await codeFor(env, client.client_id, cookie, { connection: 'google-oauth2' })).code).toBeTruthy();
  });
});

describe('AUTH0_COMPAT=true', () => {
  it('/oauth/token is /token, with a form or a JSON body (code, then refresh)', async () => {
    const client = await newClient(COMPAT);
    const { cookie } = await googleSignIn(COMPAT, unique('compat'));
    const { code, verifier } = await codeFor(COMPAT, client.client_id, cookie, { connection: 'google-apps' });
    const tokens = await jsonPost(COMPAT, '/oauth/token', { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: REDIRECT, client_id: client.client_id, client_secret: client.client_secret });
    expect(tokens.status).toBe(200);
    const body = (await tokens.json()) as Record<string, string>;
    expect(body.id_token).toBeTruthy();
    const refreshed = await form(COMPAT, '/oauth/token', { grant_type: 'refresh_token', refresh_token: body.refresh_token, client_id: client.client_id, client_secret: client.client_secret });
    expect(refreshed.status).toBe(200);
    const again = await jsonPost(COMPAT, '/token', { grant_type: 'refresh_token', refresh_token: ((await refreshed.json()) as Record<string, string>).refresh_token, client_id: client.client_id, client_secret: client.client_secret });
    expect(again.status).toBe(200);
  });

  it('a JSON body that is no object, or has nested values, gives nothing usable', async () => {
    expect((await call(COMPAT, '/oauth/token', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '[1,2]' })).status).toBe(401);
    expect((await jsonPost(COMPAT, '/oauth/token', { client_id: { a: 1 }, client_secret: ['x'] })).status).toBe(401);
  });

  it('/v2/logout ends the session and returns only to a registered address', async () => {
    const client = await newClient(COMPAT);
    for (const returnTo of [APP, REDIRECT]) {
      const { cookie } = await googleSignIn(COMPAT, unique('out'));
      const res = await call(COMPAT, `/v2/logout?${new URLSearchParams({ returnTo, client_id: client.client_id })}`, { headers: { Cookie: cookie } });
      expect(res.status).toBe(302);
      expect(res.headers.get('Location')).toBe(returnTo);
      expect(res.headers.get('Set-Cookie')).toContain('Max-Age=0');
      // Signed out: /account asks to sign in again.
      expect((await call(COMPAT, '/account', { headers: { Cookie: cookie } })).headers.get('Location')).toMatch(/^\/login/);
    }
  });

  it('/v2/logout never redirects elsewhere: an unregistered returnTo, another client\'s, none named', async () => {
    const client = await newClient(COMPAT);
    const other = await admin<{ client_id: string }>(COMPAT, 'POST', '/admin/clients', { name: 'Other', redirect_uris: ['https://other.test/callback'], post_logout_redirect_uris: ['https://other.test'], restricted: false });
    for (const q of <Record<string, string>[]>[
      { returnTo: 'https://evil.test', client_id: client.client_id },
      { returnTo: 'https://other.test', client_id: client.client_id },
      { returnTo: `${APP}/elsewhere`, client_id: client.client_id },
      { returnTo: APP },
      { returnTo: APP, client_id: 'unknown' },
    ]) {
      const { cookie } = await googleSignIn(COMPAT, unique('stay'));
      const res = await call(COMPAT, `/v2/logout?${new URLSearchParams(q)}`, { headers: { Cookie: cookie } });
      expect(res.status).toBe(200);
      expect(res.headers.get('Location')).toBeNull();
      // Signed out all the same.
      expect(cookieOf(res)).toMatch(/=$/);
    }
    expect(other.status).toBe(201);
  });

  it('Radio Scorpio\'s workers: client credentials as JSON at /oauth/token, iss with the slash', async () => {
    await admin(SCORPIO, 'POST', '/admin/apis', { id: 'zaracloud-api', name: 'Zaracloud', permissions: ['read:shows'] });
    const m = await admin<{ client_id: string; client_secret: string }>(SCORPIO, 'POST', '/admin/clients', { kind: 'machine', name: 'zara worker' });
    await admin(SCORPIO, 'PUT', `/admin/clients/${m.body.client_id}/api-access/zaracloud-api`, { client: ['read:shows'] });
    const res = await jsonPost(SCORPIO, '/oauth/token', { grant_type: 'client_credentials', client_id: m.body.client_id, client_secret: m.body.client_secret, audience: 'zaracloud-api' });
    expect(res.status).toBe(200);
    const at = decodeJwt(((await res.json()) as { access_token: string }).access_token);
    expect(at).toMatchObject({ iss: `${ISSUER}/`, aud: 'zaracloud-api', gty: 'client-credentials', scope: 'read:shows', permissions: ['read:shows'] });
  });
});
