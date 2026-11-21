import { compactVerify, createLocalJWKSet } from 'jose';
import { securityEvent } from './audit';
import type { Env } from './env';
import { auth0Compat, googleOnly, issuerUrl } from './instance';
import { sendMail } from './mail';
import { publicKeys } from './keys';
import { mayUse, noAccess } from './access';
import { consentPage, logoutConfirmPage, messagePage, texts } from './pages';
import { needsPasskey, passkeyStep } from './passkeys';
import { ADMIN_CLIENT_ID, authenticateClient, clientById, consentAskedOf, consentHost, currentSession, endSession, isMachine, needsConsent, userById, type Amr, type Client } from './store';
import { CLIENT_CREDENTIALS, clientCredentialsGrant } from './machine';
import { issueTokens, scopeHas, verifyAccessToken } from './tokens';
import { audienceCheck, userAccessTo } from './apis';
import { withinLimit } from './ratelimit';
import { inSeconds, json, newUserCode, nowIso, oauthError, pkceMatches, randomToken, readForm, redirect, sameOrigin, sha256, unixNow } from './util';

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
  const i = issuerUrl(env);
  // Only Google (SIGN_IN=google): no device flow and no client self-service to advertise.
  const google = googleOnly(env);
  return json(
    {
      issuer: env.ISSUER,
      authorization_endpoint: `${i}/authorize`,
      token_endpoint: `${i}/token`,
      userinfo_endpoint: `${i}/userinfo`,
      ...(google ? {} : { device_authorization_endpoint: `${i}/device/code` }),
      end_session_endpoint: `${i}/logout`,
      jwks_uri: `${i}/.well-known/jwks.json`,
      response_types_supported: ['code'],
      grant_types_supported: google ? ['authorization_code', 'refresh_token'] : ['authorization_code', 'refresh_token', DEVICE_GRANT],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['RS256'],
      scopes_supported: SUPPORTED_SCOPES,
      claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'auth_time', 'nonce', 'email', 'email_verified', 'name'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'client_secret_basic', 'none'],
      code_challenge_methods_supported: ['S256'],
      // RFC 9207: every authorization response says who answered (mix-up attacks).
      authorization_response_iss_parameter_supported: true,
      // Not standard: an application assigns who may use its client here
      // (with its own credentials; clients.ts). Arcanum looks for it.
      ...(google ? {} : { client_users_endpoint: `${i}/clients/self/users` }),
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
  if (!client || isMachine(client) || !client.redirect_uris.includes(redirectUri)) return messagePage(request, texts(request).errors.request, 400);

  const back = (params: Record<string, string>) => {
    const target = new URL(redirectUri);
    for (const [k, v] of Object.entries(params)) target.searchParams.set(k, v);
    if (p.get('state')) target.searchParams.set('state', p.get('state')!);
    target.searchParams.set('iss', env.ISSUER);
    return redirect(target.toString());
  };

  if (p.get('response_type') !== 'code') return back({ error: 'unsupported_response_type' });
  // PKCE is required (S256 only): the BFF always sends it.
  const challenge = p.get('code_challenge') || '';
  if (p.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) {
    return back({ error: 'invalid_request', error_description: 'PKCE with S256 is required' });
  }

  // An API (apis.ts): only one this application may ask for on behalf of its
  // users. On an instance without APIs (the shared one) it's ignored, as before.
  let audience: string | null = p.get('audience') || null;
  if (audience) {
    const check = await audienceCheck(env, client.id, audience);
    if (check === 'refused') return back({ error: 'invalid_request', error_description: 'Unknown audience, or this application may not ask for it' });
    if (check === 'ignored') audience = null;
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

  // A restricted client: only who's assigned (else: ask to be added).
  if (!(await mayUse(env, client, session.user))) return noAccess(request, env, client, session.user);
  // One that requires a passkey: only a session made with one (else: sign in with it, or add one).
  if (needsPasskey(client, session)) return passkeyStep(url.pathname + url.search);
  // A client someone else runs: once per person, a yes first (one query,
  // only for such a client). Not its owner (who made it), not a demo guest
  // (no real name or address).
  if (consentAskedOf(client, session.user)) {
    const given = await env.DB.prepare('SELECT 1 FROM consents WHERE user_id = ? AND client_id = ?').bind(session.user.id, client.id).first();
    if (!given) {
      if (p.get('consent') === 'denied') return back({ error: 'access_denied' });
      if (prompts.includes('none')) return back({ error: 'consent_required' });
      const again = new URL(url);
      again.searchParams.delete('consent');
      return consentPage(request, { clientName: client.name, host: consentHost(client, redirectUri), email: session.user.email, continueTo: again.pathname + again.search });
    }
  }

  const code = randomToken(32);
  const fields = [await sha256(code), client.id, session.user.id, redirectUri, cleanScope(p.get('scope')), p.get('nonce'), challenge, session.authTime, inSeconds(AUTH_CODE_SECONDS), session.amr];
  // With an audience (migration 0014) it's kept with the code; without, the statement as before.
  await (audience
    ? env.DB.prepare(
        `INSERT INTO auth_codes (code_hash, client_id, user_id, redirect_uri, scope, nonce, code_challenge, auth_time, expires_at, amr, audience)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(...fields, audience)
    : env.DB.prepare(
        `INSERT INTO auth_codes (code_hash, client_id, user_id, redirect_uri, scope, nonce, code_challenge, auth_time, expires_at, amr)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      ).bind(...fields)
  ).run();
  return back({ code });
}

// The consent page's answer (same origin, signed in): yes is remembered and
// the authorization goes on; cancel goes back to the app with access_denied
// (through /authorize again, which checks the client and redirect_uri).
export async function authorizeConsent(request: Request, env: Env): Promise<Response> {
  if (!sameOrigin(request, env.ISSUER)) return messagePage(request, texts(request).errors.request, 403);
  const form = await readForm(request);
  const to = form.continue || '';
  if (!to.startsWith('/authorize?')) return messagePage(request, texts(request).errors.request, 400);
  const session = await currentSession(env, request);
  if (!session) return redirect(`/login?continue=${encodeURIComponent(to)}`);
  const params = new URLSearchParams(to.slice('/authorize?'.length));
  params.delete('consent');
  if (form.decision === 'allow') {
    const client = await clientById(env, params.get('client_id'));
    if (!client || !needsConsent(client) || !(await mayUse(env, client, session.user))) return messagePage(request, texts(request).errors.request, 400);
    await env.DB.prepare('INSERT OR IGNORE INTO consents (user_id, client_id, created_at) VALUES (?, ?, ?)').bind(session.user.id, client.id, nowIso()).run();
    return redirect(`/authorize?${params}`);
  }
  params.set('consent', 'denied');
  return redirect(`/authorize?${params}`);
}

// --- Token endpoint: authorization_code, refresh_token, device_code.

// AUTH0_COMPAT: a JSON body too (Auth0's SDKs and the Scorpio workers send
// one) - its plain values as the form's. Else, as always, a form only.
async function tokenBody(request: Request, env: Env): Promise<Record<string, string>> {
  if (!auth0Compat(env) || !(request.headers.get('Content-Type') || '').includes('application/json')) return readForm(request);
  const body = (await request.json().catch(() => null)) as Record<string, unknown> | null;
  const out: Record<string, string> = {};
  if (body && typeof body === 'object' && !Array.isArray(body)) {
    for (const [k, v] of Object.entries(body)) if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') out[k] = String(v);
  }
  return out;
}

export async function token(request: Request, env: Env): Promise<Response> {
  const form = await tokenBody(request, env);
  // A machine client for itself (machine.ts): limited before the client is looked up.
  if (form.grant_type === CLIENT_CREDENTIALS) return clientCredentialsGrant(request, env, form);
  const client = await authenticateClient(env, request, form);
  if (!client) return oauthError('invalid_client', 'Unknown client or wrong secret', 401);
  // A machine client gets nothing but client credentials.
  if (isMachine(client)) return oauthError('unauthorized_client', 'A machine client may only use client_credentials');
  // The built-in admin client: one sign-in at a time, nothing else.
  if (client.id === ADMIN_CLIENT_ID && form.grant_type !== 'authorization_code') return oauthError('unauthorized_client', 'Only authorization_code for this client');

  switch (form.grant_type) {
    case 'authorization_code':
      return authorizationCodeGrant(env, client, form);
    case 'refresh_token':
      return refreshGrant(request, env, client, form);
    case DEVICE_GRANT:
      if (googleOnly(env)) return oauthError('unsupported_grant_type', 'Unsupported grant_type');
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
  amr: Amr | null;
  audience?: string | null;
}

async function authorizationCodeGrant(env: Env, client: Client, form: Record<string, string>): Promise<Response> {
  const codeHash = await sha256(form.code || '');
  // Client, redirect_uri and PKCE are checked before the code is claimed
  // (security review 2026-11-20): someone with a copy of the code but not
  // the verifier can't burn it - which would also have made the real
  // exchange look like a reuse and revoked that user's sessions.
  const row = await env.DB.prepare('SELECT * FROM auth_codes WHERE code_hash = ?').bind(codeHash).first<AuthCodeRow>();
  if (!row || row.expires_at <= nowIso()) return oauthError('invalid_grant', 'Invalid, expired or used code');
  if (row.client_id !== client.id || row.redirect_uri !== form.redirect_uri) return oauthError('invalid_grant', 'Code was issued to another client or redirect_uri');
  if (!(await pkceMatches(form.code_verifier || '', row.code_challenge))) return oauthError('invalid_grant', 'PKCE verification failed');
  // Single use: claim it atomically (D1 is one SQLite writer).
  const claimed = await env.DB.prepare('UPDATE auth_codes SET used_at = ? WHERE code_hash = ? AND used_at IS NULL AND expires_at > ?')
    .bind(nowIso(), codeHash, nowIso())
    .run();
  if (!claimed.meta.changes) {
    // Used before, by someone with the code and its verifier: a copy
    // (RFC 9700 §4.2.4). What it was exchanged for goes too - that user's
    // refresh tokens for this client.
    await env.DB.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL').bind(nowIso(), row.user_id, row.client_id).run();
    securityEvent('code_reuse', { client: client.id, user: row.user_id });
    return oauthError('invalid_grant', 'Invalid, expired or used code');
  }
  const user = await userById(env, row.user_id);
  if (!user) return oauthError('invalid_grant', 'User no longer exists');
  if (!(await mayUse(env, client, user))) return oauthError('invalid_grant', 'No access to this client');
  // No refresh token for the admin client: after an hour, a passkey again.
  const scope = client.id === ADMIN_CLIENT_ID ? row.scope.split(' ').filter((s) => s !== 'offline_access').join(' ') : row.scope;
  return json(await issueTokens(env, { clientId: client.id, user, scope, authTime: row.auth_time, nonce: row.nonce, amr: row.amr, audience: row.audience ?? null }));
}

// A rotated-away refresh token presented again within this window counts as
// a parallel request of the same app (several API calls at once when the
// access token runs out; an eventually consistent session store), not as a
// stolen copy: it gets fresh tokens. After it, reuse revokes them all.
const ROTATION_GRACE_MS = 30_000;

async function refreshGrant(request: Request, env: Env, client: Client, form: Record<string, string>): Promise<Response> {
  const tokenHash = await sha256(form.refresh_token || '');
  const row = await env.DB.prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?')
    .bind(tokenHash)
    .first<{ client_id: string; user_id: string; scope: string; auth_time: number; expires_at: string; revoked_at: string | null; rotated_at: string | null; amr: Amr | null; audience?: string | null }>();
  if (!row || row.client_id !== client.id) return oauthError('invalid_grant', 'Invalid refresh token');
  // Its audience is kept; the application must still have user access to it (apis.ts).
  const audience = row.audience ?? null;
  const audienceGone = async () => !!audience && !(await userAccessTo(env, client.id, audience));
  const noAudience = () => oauthError('invalid_grant', 'No access to this audience any more');
  if (row.revoked_at && row.rotated_at && Date.now() - Date.parse(row.rotated_at) <= ROTATION_GRACE_MS && row.expires_at > nowIso()) {
    // Only while nothing of this user + client was revoked since (theft, a new password).
    const revokedSince = await env.DB.prepare(
      'SELECT 1 FROM refresh_tokens WHERE user_id = ? AND client_id = ? AND rotated_at IS NULL AND revoked_at IS NOT NULL AND revoked_at >= ? LIMIT 1'
    )
      .bind(row.user_id, row.client_id, row.rotated_at)
      .first();
    const user = revokedSince ? null : await userById(env, row.user_id);
    if (user && !(await mayUse(env, client, user))) return oauthError('invalid_grant', 'No access to this client');
    if (user && (await audienceGone())) return noAudience();
    if (user) return json(await issueTokens(env, { clientId: client.id, user, scope: row.scope, authTime: row.auth_time, amr: row.amr, audience }));
  }
  if (row.revoked_at) {
    // A rotated-away token used again: someone has a copy. Revoke them all.
    const revoked = await env.DB.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND client_id = ? AND revoked_at IS NULL')
      .bind(nowIso(), row.user_id, row.client_id)
      .run();
    securityEvent('refresh_reuse', { client: client.id, user: row.user_id, revoked: revoked.meta.changes ?? 0 });
    // Told once (when it signed them out somewhere): they sign in again, and look if it repeats.
    const user = revoked.meta.changes ? await userById(env, row.user_id) : null;
    if (user && !user.guest) {
      const t = texts(request);
      await sendMail(env, user.email, t.mailTokenReuseSubject, t.mailTokenReuse(client.name, `${issuerUrl(env)}/account`)).catch((err) => console.error('token-reuse mail failed', err));
    }
    return oauthError('invalid_grant', 'Refresh token was already used');
  }
  if (row.expires_at <= nowIso()) return oauthError('invalid_grant', 'Refresh token expired');
  const now = nowIso();
  const revoked = await env.DB.prepare('UPDATE refresh_tokens SET revoked_at = ?, rotated_at = ? WHERE token_hash = ? AND revoked_at IS NULL').bind(now, now, tokenHash).run();
  if (!revoked.meta.changes) return oauthError('invalid_grant', 'Refresh token was already used');
  const user = await userById(env, row.user_id);
  if (!user) return oauthError('invalid_grant', 'User no longer exists');
  // Unassigned since: no new tokens (unassigning also revoked them; this is the backstop).
  if (!(await mayUse(env, client, user))) return oauthError('invalid_grant', 'No access to this client');
  if (await audienceGone()) return noAudience();
  return json(await issueTokens(env, { clientId: client.id, user, scope: row.scope, authTime: row.auth_time, amr: row.amr, audience }));
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
  amr: Amr | null;
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
  if (!(await mayUse(env, client, user))) return oauthError('access_denied', 'No access to this client');
  return json(await issueTokens(env, { clientId: client.id, user, scope: row.scope, authTime: row.auth_time ?? unixNow(), amr: row.amr }));
}

// --- Device authorization (RFC 8628): the kassa asks for a code. The BFF
// sends only client_id + scope here (no secret) — the secret is checked when
// it polls the token endpoint.

export async function deviceAuthorization(request: Request, env: Env): Promise<Response> {
  const form = await readForm(request);
  const client = await clientById(env, form.client_id);
  if (!client || client.id === ADMIN_CLIENT_ID || isMachine(client)) return oauthError('invalid_client', 'Unknown client', 401);
  // Per client (installation), not per IP: the kassas' requests come from
  // their installation's bff, i.e. Cloudflare's shared addresses. A client_id
  // is public; this keeps one from being used to flood the database.
  if (!(await withinLimit(env, `device-code:${client.id}`))) return oauthError('slow_down', 'Too many device codes for this client', 429);
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
    verification_uri: `${issuerUrl(env)}/device`,
    verification_uri_complete: `${issuerUrl(env)}/device?user_code=${encodeURIComponent(userCode)}`,
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
// registered post_logout_redirect_uri (never an unregistered one). With a
// valid id_token_hint (ours, for that client, for whoever is signed in - an
// expired one too) it happens right away; without, the browser is asked
// first (logoutConfirmPage): any page could send it here.

async function hintedUser(env: Env, hint: string | null, clientId: string | null): Promise<{ sub: string; aud: string } | null> {
  if (!hint) return null;
  try {
    const keys = createLocalJWKSet({ keys: await publicKeys(env) });
    const { payload } = await compactVerify(hint, keys, { algorithms: ['RS256'] });
    const claims = JSON.parse(new TextDecoder().decode(payload)) as { iss?: unknown; sub?: unknown; aud?: unknown };
    const aud = Array.isArray(claims.aud) ? claims.aud[0] : claims.aud;
    if (claims.iss !== env.ISSUER || typeof claims.sub !== 'string' || typeof aud !== 'string') return null;
    if (clientId && aud !== clientId) return null;
    return { sub: claims.sub, aud };
  } catch {
    return null;
  }
}

export async function logout(request: Request, env: Env): Promise<Response> {
  const params: Record<string, string> =
    request.method === 'POST' ? await readForm(request) : Object.fromEntries(new URL(request.url).searchParams);
  if (request.method === 'POST' && !sameOrigin(request, env.ISSUER)) return messagePage(request, texts(request).errors.request, 403);
  const session = await currentSession(env, request);
  const hint = await hintedUser(env, params.id_token_hint || null, params.client_id || null);
  // Signed in, no hint for this person, not confirmed here: ask.
  if (session && request.method === 'GET' && hint?.sub !== session.user.id) {
    const keep = ['client_id', 'post_logout_redirect_uri', 'state'].filter((k) => params[k]);
    return logoutConfirmPage(request, Object.fromEntries(keep.map((k) => [k, params[k]])));
  }
  const cookies = await endSession(env, request);
  const client = await clientById(env, params.client_id || hint?.aud || null);
  const target = params.post_logout_redirect_uri;
  let res: Response;
  if (client && target && client.post_logout_redirect_uris.includes(target)) {
    const url = new URL(target);
    if (params.state) url.searchParams.set('state', params.state);
    res = redirect(url.toString());
  } else {
    res = messagePage(request, texts(request).signedOut);
  }
  for (const cookie of cookies) res.headers.append('Set-Cookie', cookie);
  return res;
}

// --- AUTH0_COMPAT: Auth0's logout, GET /v2/logout?returnTo=…&client_id=…
// (Aquascenic's BFF). Signed in: asks first (below). Then, as Auth0: goes
// back to returnTo only when it's one of that client's registered logout or
// redirect URLs - never an open redirect. Anything else: "signed out" here.
export async function auth0Logout(request: Request, env: Env): Promise<Response> {
  const post = request.method === 'POST';
  if (post && !sameOrigin(request, env.ISSUER)) return messagePage(request, texts(request).errors.request, 403);
  const p = post ? new URLSearchParams(await readForm(request)) : new URL(request.url).searchParams;
  // Signed in and not confirmed here: asked first, like /logout without a
  // hint (security review 2026-11-21) - any page could link here and sign
  // someone out. The confirmation posts back here, from this origin only.
  if (!post && (await currentSession(env, request))) {
    const keep: Record<string, string> = {};
    for (const k of ['client_id', 'returnTo']) if (p.get(k)) keep[k] = p.get(k)!;
    return logoutConfirmPage(request, keep, '/v2/logout');
  }
  const cookies = await endSession(env, request);
  const client = await clientById(env, p.get('client_id'));
  const target = p.get('returnTo') || '';
  const registered = !!client && !isMachine(client) && !!target && (client.post_logout_redirect_uris.includes(target) || client.redirect_uris.includes(target));
  if (target && !registered) securityEvent('logout_return_refused', { client: client?.id ?? null });
  const res = registered ? redirect(target) : messagePage(request, texts(request).signedOut);
  for (const cookie of cookies) res.headers.append('Set-Cookie', cookie);
  return res;
}
