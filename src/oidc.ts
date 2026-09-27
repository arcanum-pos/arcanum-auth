import type { Env } from './env';
import { publicKeys } from './keys';
import { messagePage, texts } from './pages';
import { authenticateClient, clientById, currentSession, endSession, userById, type Client } from './store';
import { issueTokens, scopeHas, verifyAccessToken } from './tokens';
import { inSeconds, json, newUserCode, nowIso, oauthError, pkceMatches, randomToken, readForm, redirect, sha256, unixNow } from './util';

const SUPPORTED_SCOPES = ['openid', 'profile', 'email', 'offline_access'];
const AUTH_CODE_SECONDS = 300;
const DEVICE_CODE_SECONDS = 600;
const DEVICE_INTERVAL_SECONDS = 5;
const DEVICE_GRANT = 'urn:ietf:params:oauth:grant-type:device_code';

// Only the scopes we know; always openid (the BFF always asks for it).
function cleanScope(requested: string | null | undefined): string {
  const asked = (requested || 'openid').split(/\s+/).filter((s) => SUPPORTED_SCOPES.includes(s));
  return [...new Set(asked.includes('openid') ? asked : ['openid', ...asked])].join(' ');
}

// --- Discovery.

export function discovery(env: Env): Response {
  const i = env.ISSUER;
  return json(
    {
      issuer: i,
      authorization_endpoint: `${i}/authorize`,
      token_endpoint: `${i}/token`,
      userinfo_endpoint: `${i}/userinfo`,
      device_authorization_endpoint: `${i}/device/code`,
      end_session_endpoint: `${i}/logout`,
      jwks_uri: `${i}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code', 'refresh_token', DEVICE_GRANT],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: SUPPORTED_SCOPES,
      claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'email', 'email_verified', 'name'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic'],
      code_challenge_methods_supported: ['S256'],
    },
    200,
    { 'Cache-Control': 'public, max-age=300' }
  );
}

export async function jwks(env: Env): Promise<Response> {
  return json({ keys: await publicKeys(env) }, 200, { 'Cache-Control': 'public, max-age=300' });
}

// --- Authorization code (the console, the chooser).

export async function authorize(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const p = url.searchParams;
  const client = await clientById(env, p.get('client_id'));
  const redirectUri = p.get('redirect_uri') || '';
  // A bad client or redirect_uri never redirects (RFC 6749 §4.1.2.1).
  if (!client || !client.redirect_uris.includes(redirectUri)) return messagePage(request, texts(request).errors.request, 400);

  const back = (params: Record<string, string>) => {
    const target = new URL(redirectUri);
    for (const [k, v] of Object.entries(params)) target.searchParams.set(k, v);
    if (p.get('state')) target.searchParams.set('state', p.get('state')!);
    return redirect(target.toString());
  };

  if (p.get('response_type') !== 'code') return back({ error: 'unsupported_response_type' });
  // PKCE is required (S256 only): the BFF always sends it.
  const challenge = p.get('code_challenge') || '';
  if (p.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
    return back({ error: 'invalid_request', error_description: 'PKCE with S256 is required' });
  }

  const prompts = (p.get('prompt') || '').split(' ');
  const session = await currentSession(env, request);
  if (!session || prompts.includes('login')) {
    if (prompts.includes('none')) return back({ error: 'login_required' });
    // After signing in, come back here — without prompt=login, or it loops.
    const again = new URL(url);
    again.searchParams.set('prompt', prompts.filter((x) => x !== 'login').join(' '));
    if (!again.searchParams.get('prompt')) again.searchParams.delete('prompt');
    return redirect(`/login?continue=${encodeURIComponent(again.pathname + again.search)}`);
  }

  const code = randomToken(32);
  await env.DB.prepare(
    `INSERT INTO auth_codes (code_hash, client_id, user_id, redirect_uri, scope, nonce, code_challenge, auth_time, expires_at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(await sha256(code), client.id, session.user.id, redirectUri, cleanScope(p.get('scope')), p.get('nonce'), challenge, session.authTime, inSeconds(AUTH_CODE_SECONDS))
    .run();
  return back({ code });
}

// --- Token endpoint: authorization_code, refresh_token, device_code.

export async function token(request: Request, env: Env): Promise<Response> {
  const form = await readForm(request);
  const client = await authenticateClient(env, request, form);
  if (!client) return oauthError('invalid_client', 'Unknown client or wrong secret', 401);

  switch (form.grant_type) {
    case 'authorization_code':
      return authorizationCodeGrant(env, client, form);
    case 'refresh_token':
      return refreshGrant(env, client, form);
    case DEVICE_GRANT:
      return deviceGrant(env, client, form);
    default:
      return oauthError('unsupported_grant_type', 'Unsupported grant_type');
  }
}

interface AuthCodeRow {
  client_id: string;
  user_id: string;
  redirect_uri: string;
  scope: string;
  nonce: string | null;
  code_challenge: string;
  auth_time: number;
  expires_at: string;
  used_at: string | null;
}

async function authorizationCodeGrant(env: Env, client: Client, form: Record<string, string>): Promise<Response> {
  const codeHash = await sha256(form.code || '');
  // Single use: claim it atomically (D1 is one SQLite writer).
  const claimed = await env.DB.prepare('UPDATE auth_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?')
    .bind(nowIso(), codeHash, nowIso())
    .run();
  const row = await env.DB.prepare('SELECT * FROM auth_codes WHERE code_hash = ?').bind(codeHash).first<AuthCodeRow>();
  if (!claimed.meta.changes || !row) return oauthError('invalid_grant', 'Invalid, expired or used code');
  if (row.client_id !== client.id || row.redirect_uri !== form.redirect_uri) return oauthError('invalid_grant', 'Code was issued to another client or redirect_uri');
  if (!(await pkceMatches(form.code_verifier || '', row.code_challenge))) return oauthError('invalid_grant', 'PKCE verification failed');
  const user = await userById(env, row.user_id);
  if (!user) return oauthError('invalid_grant', 'User no longer exists');
  return json(await issueTokens(env, { clientId: client.id, user, scope: row.scope, authTime: row.auth_time, nonce: row.nonce }));
}

async function refreshGrant(env: Env, client: Client, form: Record<string, string>): Promise<Response> {
  const tokenHash = await sha256(form.refresh_token || '');
  const row = await env.DB.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?')
    .bind(tokenHash)
    .first<{ client_id: string; user_id: string; scope: string; auth_time: number; expires_at: string; revoked_at: string | null }>();
  if (!row || row.client_id !== client.id) return oauthError('invalid_grant', 'Invalid refresh token');
  if (row.revoked_at) {
    // A rotated-away token used again: someone has a copy. Revoke them all.
    await env.DB.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL')
      .bind(nowIso(), row.user_id, row.client_id)
      .run();
    return oauthError('invalid_grant', 'Refresh token was already used');
  }
  if (row.expires_at <= nowIso()) return oauthError('invalid_grant', 'Refresh token expired');
  const revoked = await env.DB.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE token_hash = ? AND revoked_at IS NULL').bind(nowIso(), tokenHash).run();
  if (!revoked.meta.changes) return oauthError('invalid_grant', 'Refresh token was already used');
  const user = await userById(env, row.user_id);
  if (!user) return oauthError('invalid_grant', 'User no longer exists');
  return json(await issueTokens(env, { clientId: client.id, user, scope: row.scope, authTime: row.auth_time }));
}

interface DeviceRow {
  device_code_hash: string;
  user_code: string;
  client_id: string;
  scope: string;
  status: 'pending' | 'approved' | 'denied';
  user_id: string | null;
  auth_time: number | null;
  interval_seconds: number;
  last_poll_at: string | null;
  expires_at: string;
}

async function deviceGrant(env: Env, client: Client, form: Record<string, string>): Promise<Response> {
  const hash = await sha256(form.device_code || '');
  const row = await env.DB.prepare('SELECT * FROM device_codes WHERE device_code_hash = ?').bind(hash).first<DeviceRow>();
  if (!row || row.client_id !== client.id) return oauthError('invalid_grant', 'Unknown device_code');
  if (row.expires_at <= nowIso()) return oauthError('expired_token', 'The device code expired');
  if (row.status === 'denied') {
    await env.DB.prepare('DELETE FROM device_codes WHERE device_code_hash = ?').bind(hash).run();
    return oauthError('access_denied', 'The user denied the request');
  }
  if (row.status === 'pending') {
    const tooSoon = row.last_poll_at && Date.parse(row.last_poll_at) > Date.now() - row.interval_seconds * 1000;
    await env.DB.prepare('UPDATE device_codes SET last_poll_at = ? WHERE device_code_hash = ?').bind(nowIso(), hash).run();
    return oauthError(tooSoon ? 'slow_down' : 'authorization_pending', tooSoon ? 'Polling too fast' : 'Waiting for the user');
  }
  // Approved: hand out the tokens once.
  const consumed = await env.DB.prepare("DELETE FROM device_codes WHERE device_code_hash = ? AND status = 'approved'").bind(hash).run();
  const user = row.user_id ? await userById(env, row.user_id) : null;
  if (!consumed.meta.changes || !user) return oauthError('invalid_grant', 'Unknown device_code');
  return json(await issueTokens(env, { clientId: client.id, user, scope: row.scope, authTime: row.auth_time ?? unixNow() }));
}

// --- Device authorization (RFC 8628): the kassa asks for a code. The BFF
// sends only client_id + scope here (no secret) — the secret is checked when
// it polls the token endpoint.

export async function deviceAuthorization(request: Request, env: Env): Promise<Response> {
  const form = await readForm(request);
  const client = await clientById(env, form.client_id);
  if (!client) return oauthError('invalid_client', 'Unknown client', 401);
  const deviceCode = randomToken(32);
  let userCode = newUserCode();
  for (let i = 0; i < 3; i++) {
    const clash = await env.DB.prepare('SELECT 1 FROM device_codes WHERE user_code = ?').bind(userCode).first();
    if (!clash) break;
    userCode = newUserCode();
  }
  await env.DB.prepare(
    'INSERT INTO device_codes (device_code_hash, user_code, client_id, scope, interval_seconds, expires_at) VALUES (?, ?, ?, ?, ?, ?)'
  )
    .bind(await sha256(deviceCode), userCode, client.id, cleanScope(form.scope), DEVICE_INTERVAL_SECONDS, inSeconds(DEVICE_CODE_SECONDS))
    .run();
  return json({
    device_code: deviceCode,
    user_code: userCode,
    verification_uri: `${env.ISSUER}/device`,
    verification_uri_complete: `${env.ISSUER}/device?user_code=${encodeURIComponent(userCode)}`,
    expires_in: DEVICE_CODE_SECONDS,
    interval: DEVICE_INTERVAL_SECONDS,
  });
}

// --- Userinfo.

export async function userinfo(request: Request, env: Env): Promise<Response> {
  const auth = request.headers.get('Authorization') || '';
  const claims = auth.startsWith('Bearer ') ? await verifyAccessToken(env, auth.slice(7)) : null;
  const user = claims ? await userById(env, claims.sub) : null;
  if (!claims || !user) return json({ error: 'invalid_token' }, 401, { 'WWW-Authenticate': 'Bearer error="invalid_token"' });
  const body: Record<string, unknown> = { sub: user.id };
  if (scopeHas(claims.scope, 'email')) Object.assign(body, { email: user.email, email_verified: !!user.email_verified });
  if (scopeHas(claims.scope, 'profile')) body.name = user.name;
  return json(body);
}

// --- RP-initiated logout: end the session here, then back to the client's
// registered post_logout_redirect_uri (never an unregistered one).

export async function logout(request: Request, env: Env): Promise<Response> {
  const p = new URL(request.url).searchParams;
  const cookie = await endSession(env, request);
  const client = await clientById(env, p.get('client_id'));
  const target = p.get('post_logout_redirect_uri');
  if (client && target && client.post_logout_redirect_uris.includes(target)) {
    const url = new URL(target);
    if (p.get('state')) url.searchParams.set('state', p.get('state')!);
    return redirect(url.toString(), { 'Set-Cookie': cookie });
  }
  const res = messagePage(request, texts(request).signedOut);
  res.headers.append('Set-Cookie', cookie);
  return res;
}

