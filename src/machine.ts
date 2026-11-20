// Machine clients (AUTH_DEDICATED.md sections 3 and 3b, migration 0015): a
// worker calling an API for itself, Auth0's client credentials.
//
//   POST /token  grant_type=client_credentials, audience=X (required),
//                client id + secret in the body or HTTP Basic - never in the
//                URL's query string (URLs end up in logs: refused)
//   → { access_token, token_type, expires_in, scope }: aud X, sub
//     "<client_id>@clients", gty "client-credentials", the client's own
//     permissions on X (client_api_access kind 'client') in both
//     `permissions` and `scope`. An hour; no id token, no refresh token.
//
// Only a machine client may use it, and a machine client nothing else (no
// sign-in, no redirect URIs, no people). Rate limited in memory (below).
//
// Secrets: 256 random bits with a recognizable prefix (scs_), stored only as
// SHA-256, shown once. A rotation keeps the old one working 24 hours
// (previous_secret_hash); "revoke now" ends that at once. Rotations,
// revocations and failed attempts go to the audit log - never a secret.
//   POST   /admin/clients/:id/secret            → { client_id, client_secret, previous_secret_expires_at }
//   DELETE /admin/clients/:id/secret/previous   → the old secret stops now
import { SignJWT } from 'jose';
import { auditLog, securityEvent } from './audit';
import { clientPermissions } from './apis';
import type { Env } from './env';
import { signingKey } from './keys';
import { ipBucket, tooManyRequests, withinLimit } from './ratelimit';
import { authenticateClient, isMachine } from './store';
import { ACCESS_TOKEN_SECONDS } from './tokens';
import { inSeconds, json, nowIso, oauthError, randomToken, sha256, unixNow } from './util';

export const CLIENT_CREDENTIALS = 'client_credentials';
export const SECRET_PREFIX = 'scs_';
export const SECRET_OVERLAP_SECONDS = 24 * 3600;

// scs_ + 43 characters (32 random bytes, base64url).
export const newMachineSecret = () => `${SECRET_PREFIX}${randomToken(32)}`;

// Limits (security review 2026-11-20): a stranger knows a machine client's
// id (it's in every token it shows an API), so nothing a stranger can send
// may stop the right secret. Failed attempts are counted per caller (IP,
// IPv6 per /64) and per client id; past either limit a failure gets 429 and
// writes nothing. A request with the right secret never touches those
// buckets: it has its own, per client, that only the secret's holder can
// fill (a worker stuck in a loop). CLIENT_CREDENTIALS_RATE_LIMITER when
// bound (a limit for busy workers), else the public one (20 a minute).
const limiterOf = (env: Env): Env => (env.CLIENT_CREDENTIALS_RATE_LIMITER ? { ...env, PUBLIC_RATE_LIMITER: env.CLIENT_CREDENTIALS_RATE_LIMITER } : env);

async function overLimit(env: Env, keys: string[], fields: Record<string, unknown>): Promise<boolean> {
  for (const key of keys) {
    if (!(await withinLimit(limiterOf(env), key))) {
      securityEvent('rate_limited', { route: 'client_credentials', ...fields });
      return true;
    }
  }
  return false;
}

// A failure goes to the audit log at most once per client per this window
// (the first one): a flood can't bury the admins' entries or use up D1's
// daily writes. Every failure is still a security event in Workers Logs.
export const FAILURE_AUDIT_SECONDS = 15 * 60;

// The client id a request names (body, or Basic) - for the limits and the log, before it's checked.
function namedClient(request: Request, form: Record<string, string>): string {
  const auth = request.headers.get('Authorization') || '';
  if (auth.startsWith('Basic ')) {
    try {
      return decodeURIComponent(atob(auth.slice(6)).split(':')[0]).slice(0, 200);
    } catch {
      return '';
    }
  }
  return (form.client_id || '').slice(0, 200);
}

export async function clientCredentialsGrant(request: Request, env: Env, form: Record<string, string>): Promise<Response> {
  if (new URL(request.url).searchParams.has('client_secret')) {
    securityEvent('secret_in_url', { client: namedClient(request, form) });
    return oauthError('invalid_request', 'client_secret must not be in the URL: send it in the body or the Authorization header');
  }
  const named = namedClient(request, form);
  const ip = request.headers.get('CF-Connecting-IP');
  const client = await authenticateClient(env, request, form);
  if (!client) {
    if (await overLimit(env, [...(ip ? [`cc-fail-ip:${ipBucket(ip)}`] : []), `cc-fail:${named}`], { client: named, ip })) return tooManyRequests();
    securityEvent('client_credentials_failed', { client: named, ip });
    // A machine client that exists: in its audit log too (a wrong or old
    // secret somewhere) - the first failure in the window only.
    if (named) {
      const since = new Date(Date.now() - FAILURE_AUDIT_SECONDS * 1000).toISOString();
      const detail = JSON.stringify({ client: named });
      try {
        await env.DB.prepare(
          `INSERT INTO audit_log (at, name, by, detail)
           SELECT ?, 'client_credentials_failed', NULL, ?
           WHERE EXISTS (SELECT 1 FROM clients WHERE id = ? AND kind = 'machine' AND disabled_at IS NULL)
             AND NOT EXISTS (SELECT 1 FROM audit_log WHERE at > ? AND name = 'client_credentials_failed' AND detail = ?)`
        )
          .bind(nowIso(), detail, named, since, detail)
          .run();
      } catch (err) {
        console.error('audit log write failed', (err as Error).message);
      }
    }
    return oauthError('invalid_client', 'Unknown client or wrong secret', 401);
  }
  if (await overLimit(env, [`cc-ok:${client.id}`], { client: client.id, ip })) return tooManyRequests();
  if (!isMachine(client)) return oauthError('unauthorized_client', 'Only a machine client may use client_credentials');
  const audience = form.audience || '';
  if (!audience) return oauthError('invalid_request', 'audience is required');
  const permissions = await clientPermissions(env, client.id, audience);
  if (!permissions.length) return oauthError('access_denied', `This client has no access to ${audience}`, 403);

  const { key, kid } = await signingKey(env);
  const now = unixNow();
  const scope = permissions.join(' ');
  await env.DB.prepare('UPDATE clients SET last_used_at = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)')
    .bind(new Date(now * 1000).toISOString(), client.id, new Date((now - 3600) * 1000).toISOString())
    .run();
  const accessToken = await new SignJWT({ scope, permissions, gty: 'client-credentials', client_id: client.id, azp: client.id })
    .setProtectedHeader({ alg: 'RS256', kid, typ: 'at+jwt' })
    .setIssuer(env.ISSUER)
    .setSubject(`${client.id}@clients`)
    .setAudience(audience)
    .setIssuedAt(now)
    .setExpirationTime(now + ACCESS_TOKEN_SECONDS)
    .setJti(randomToken(16))
    .sign(key);
  return json({ access_token: accessToken, token_type: 'Bearer', expires_in: ACCESS_TOKEN_SECONDS, scope });
}

// --- Admin: rotating a client's secret, revoking the previous one.
export async function adminSecrets(request: Request, env: Env, path: string, by: string): Promise<Response | null> {
  const m = path.match(/^\/admin\/clients\/([^/]+)\/secret(\/previous)?$/);
  if (!m) return null;
  let id: string;
  try {
    id = decodeURIComponent(m[1]);
  } catch {
    return json({ error: 'Not found' }, 404);
  }
  const row = await env.DB.prepare('SELECT id, secret_hash, kind FROM clients WHERE id = ? AND disabled_at IS NULL').bind(id).first<{ id: string; secret_hash: string; kind: string }>();
  if (!row) return json({ error: 'Not found' }, 404);

  if (!m[2] && request.method === 'POST') {
    const secret = newMachineSecret();
    const now = nowIso();
    const until = inSeconds(SECRET_OVERLAP_SECONDS);
    await env.DB.prepare('UPDATE clients SET secret_hash = ?, secret_created_at = ?, previous_secret_hash = ?, previous_secret_expires_at = ? WHERE id = ?')
      .bind(await sha256(secret), now, row.secret_hash, until, id)
      .run();
    securityEvent('client_secret_rotated', { client: id, by });
    await auditLog(env, 'client_secret_rotated', by, { client: id, previous_until: until });
    // Shown here only, once.
    return json({ client_id: id, client_secret: secret, secret_created_at: now, previous_secret_expires_at: until });
  }
  if (m[2] && request.method === 'DELETE') {
    const res = await env.DB.prepare('UPDATE clients SET previous_secret_hash = NULL, previous_secret_expires_at = NULL WHERE id = ? AND previous_secret_hash IS NOT NULL').bind(id).run();
    securityEvent('client_secret_revoked', { client: id, by });
    await auditLog(env, 'client_secret_revoked', by, { client: id, had_previous: !!res.meta.changes });
    return json({ ok: true, revoked: !!res.meta.changes });
  }
  return json({ error: 'Not found' }, 404);
}
