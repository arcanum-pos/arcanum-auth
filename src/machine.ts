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
// sign-in, no redirect URIs, no people). Limited per client and per IP in
// memory before D1 is asked (a worker stuck in a loop can't eat the quota).
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
import { tooManyRequests, withinLimit } from './ratelimit';
import { authenticateClient, isMachine } from './store';
import { ACCESS_TOKEN_SECONDS } from './tokens';
import { inSeconds, json, nowIso, oauthError, randomToken, sha256, unixNow } from './util';

export const CLIENT_CREDENTIALS = 'client_credentials';
export const SECRET_PREFIX = 'scs_';
export const SECRET_OVERLAP_SECONDS = 24 * 3600;

// scs_ + 43 characters (32 random bytes, base64url).
export const newMachineSecret = () => `${SECRET_PREFIX}${randomToken(32)}`;

// Before anything touches D1: per IP (when it comes from the internet) and per
// client id as given. CLIENT_CREDENTIALS_RATE_LIMITER when bound (a limit for
// busy workers), else the public one (20 a minute).
async function limited(env: Env, request: Request, clientId: string): Promise<boolean> {
  const limiter = env.CLIENT_CREDENTIALS_RATE_LIMITER ? { ...env, PUBLIC_RATE_LIMITER: env.CLIENT_CREDENTIALS_RATE_LIMITER } : env;
  const ip = request.headers.get('CF-Connecting-IP');
  for (const key of [...(ip ? [`cc-ip:${ip}`] : []), `cc-client:${clientId}`]) {
    if (!(await withinLimit(limiter, key))) {
      securityEvent('rate_limited', { route: 'client_credentials', client: clientId, ip });
      return true;
    }
  }
  return false;
}

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
  if (await limited(env, request, named)) return tooManyRequests();
  const client = await authenticateClient(env, request, form);
  if (!client) {
    securityEvent('client_credentials_failed', { client: named, ip: request.headers.get('CF-Connecting-IP') });
    // A machine client that exists: in its audit log too (a wrong or old secret somewhere).
    if (named && (await env.DB.prepare("SELECT 1 FROM clients WHERE id = ? AND kind = 'machine'").bind(named).first())) {
      await auditLog(env, 'client_credentials_failed', null, { client: named });
    }
    return oauthError('invalid_client', 'Unknown client or wrong secret', 401);
  }
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
