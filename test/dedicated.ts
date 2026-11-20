// Helpers for the dedicated-instance settings (AUTH_DEDICATED.md): the
// Worker called with a changed env (SIGN_IN, GOOGLE_HOSTED_DOMAIN, …), as
// the other tests call it through SELF with the default one.
import { env } from 'cloudflare:test';
import { expect } from 'vitest';
import worker from '../src/index';
import type { Env } from '../src/env';

export const ISSUER = 'https://login.kaboutersoft.be';
export const APP = 'https://scorpio-app.test';
export const REDIRECT = `${APP}/callback`;
export const ADMIN_KEY = { Authorization: 'Bearer test-admin-key' };

let seq = 0;
export const unique = (tag: string, domain = 'example.test') => `${tag}-${Date.now()}-${++seq}@${domain}`;
export const someIp = () => `10.${++seq % 250}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;
export const cookieOf = (res: Response) => (res.headers.get('Set-Cookie') || '').split(';')[0];

export const withEnv = (extra: Partial<Env> & Record<string, unknown> = {}): Env => ({ ...env, ...extra }) as Env;

export function call(e: Env, path: string, init: RequestInit = {}): Promise<Response> {
  return worker.fetch(new Request(`${ISSUER}${path}`, { redirect: 'manual', ...init }), e);
}

export function form(e: Env, path: string, fields: Record<string, string>, headers: Record<string, string> = {}): Promise<Response> {
  return call(e, path, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers }, body: new URLSearchParams(fields) });
}

// The admin API as the bootstrapper calls it: over a binding (no CF-Connecting-IP), with the key.
export async function admin<T = Record<string, unknown>>(e: Env, method: string, path: string, body?: unknown, auth: Record<string, string> = ADMIN_KEY): Promise<{ status: number; body: T }> {
  const res = await call(e, path, { method, headers: { ...auth, ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}) }, body: body !== undefined ? JSON.stringify(body) : undefined });
  return { status: res.status, body: (await res.json().catch(() => ({}))) as T };
}

export async function newClient(e: Env, extra: Record<string, unknown> = {}): Promise<{ client_id: string; client_secret: string }> {
  const res = await admin<{ client_id: string; client_secret: string }>(e, 'POST', '/admin/clients', { name: 'Scorpio app', redirect_uris: [REDIRECT], post_logout_redirect_uris: [APP], restricted: false, ...extra });
  expect(res.status).toBe(201);
  return res.body;
}

// Signs in with Google (the fake token endpoint: the code names the account,
// "hd:<domain>:<email>" a Workspace account) → the session cookie.
export async function googleSignIn(e: Env, code: string, continueTo = '/account'): Promise<{ res: Response; cookie: string; start: URL }> {
  const start = await call(e, `/google?continue=${encodeURIComponent(continueTo)}`, { headers: { 'CF-Connecting-IP': someIp() } });
  expect(start.status).toBe(302);
  const target = new URL(start.headers.get('Location')!);
  const res = await call(e, `/callback/google?code=${encodeURIComponent(code)}&state=${target.searchParams.get('state')}`, { headers: { Cookie: cookieOf(start) } });
  return { res, cookie: cookieOf(res), start: target };
}

export async function pkce() {
  const verifier = 'v'.repeat(20) + crypto.randomUUID().replace(/-/g, '');
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  const challenge = btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  return { verifier, challenge };
}

export function authorizePath(clientId: string, challenge: string, extra: Record<string, string> = {}, redirectUri = REDIRECT) {
  return `/authorize?${new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'openid profile email offline_access',
    state: 'st4te',
    code_challenge: challenge,
    code_challenge_method: 'S256',
    ...extra,
  })}`;
}

// Authorization code flow for a signed-in browser → the token response.
export async function codeFlow(e: Env, client: { client_id: string; client_secret?: string }, cookie: string, extra: Record<string, string> = {}, redirectUri = REDIRECT) {
  const { verifier, challenge } = await pkce();
  const res = await call(e, authorizePath(client.client_id, challenge, extra, redirectUri), { headers: { Cookie: cookie } });
  expect(res.status).toBe(302);
  const back = new URL(res.headers.get('Location')!);
  const code = back.searchParams.get('code');
  if (!code) return { authorize: back, status: 0, body: {} as Record<string, unknown> };
  const fields: Record<string, string> = { grant_type: 'authorization_code', code, redirect_uri: redirectUri, client_id: client.client_id, code_verifier: verifier };
  if (client.client_secret) fields.client_secret = client.client_secret;
  const tokenRes = await form(e, '/token', fields);
  return { authorize: back, status: tokenRes.status, body: (await tokenRes.json()) as Record<string, unknown> };
}
