import { jwtVerify, SignJWT } from 'jose';
import type { Env } from './env';
import { signingKey, verificationKey } from './keys';
import type { Amr, User } from './store';

const AMR_CLAIM: Record<Amr, string[]> = { otp: ['otp'], link: ['otp'], fed: ['fed'], passkey: ['hwk', 'mfa'] };
import { inSeconds, nowIso, randomToken, sha256, unixNow } from './util';

export const ACCESS_TOKEN_SECONDS = 3600;
export const REFRESH_TOKEN_SECONDS = 60 * 60 * 24 * 30;

export function scopeHas(scope: string, value: string): boolean {
  return scope.split(' ').includes(value);
}

// Access token + id token (+ a refresh token with offline_access), as the
// token endpoint returns them for every grant.
export async function issueTokens(
  env: Env,
  params: { clientId: string; user: User; scope: string; authTime: number; nonce?: string | null; amr?: Amr | null }
): Promise<Record<string, unknown>> {
  const { key, kid } = await signingKey(env);
  const now = unixNow();
  // The client is in use (the platform's overview, an owner's /account) — at most one write an hour.
  const nowText = new Date(now * 1000).toISOString();
  await env.DB.prepare('UPDATE clients SET last_used_at = ? WHERE id = ? AND (last_used_at IS NULL OR last_used_at < ?)')
    .bind(nowText, params.clientId, new Date((now - 3600) * 1000).toISOString())
    .run();
  const accessToken = await new SignJWT({ scope: params.scope, client_id: params.clientId })
    .setProtectedHeader({ alg: 'RS256', kid, typ: 'at+jwt' })
    .setIssuer(env.ISSUER)
    .setSubject(params.user.id)
    .setAudience(params.clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + ACCESS_TOKEN_SECONDS)
    .setJti(randomToken(16))
    .sign(key);

  const body: Record<string, unknown> = { access_token: accessToken, token_type: 'Bearer', expires_in: ACCESS_TOKEN_SECONDS, scope: params.scope };

  if (scopeHas(params.scope, 'openid')) {
    const claims: Record<string, unknown> = { auth_time: params.authTime };
    if (params.nonce) claims.nonce = params.nonce;
    // How the user signed in (RFC 8176 values where there's one): a passkey
    // with user verification counts as two factors.
    if (params.amr) claims.amr = AMR_CLAIM[params.amr];
    if (scopeHas(params.scope, 'email')) Object.assign(claims, { email: params.user.email, email_verified: !!params.user.email_verified });
    if (scopeHas(params.scope, 'profile')) claims.name = params.user.name;
    body.id_token = await new SignJWT(claims)
      .setProtectedHeader({ alg: 'RS256', kid, typ: 'JWT' })
      .setIssuer(env.ISSUER)
      .setSubject(params.user.id)
      .setAudience(params.clientId)
      .setIssuedAt(now)
      .setExpirationTime(now + ACCESS_TOKEN_SECONDS)
      .sign(key);
  }

  if (scopeHas(params.scope, 'offline_access')) {
    const refresh = randomToken(32);
    await env.DB.prepare(
      'INSERT INTO refresh_tokens (token_hash, client_id, user_id, scope, auth_time, created_at, expires_at, amr) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
    )
      .bind(await sha256(refresh), params.clientId, params.user.id, params.scope, params.authTime, nowIso(), inSeconds(REFRESH_TOKEN_SECONDS), params.amr ?? null)
      .run();
    body.refresh_token = refresh;
  }
  return body;
}

// One of our own access tokens (for /userinfo) → its subject and scope.
export async function verifyAccessToken(env: Env, token: string): Promise<{ sub: string; scope: string } | null> {
  try {
    const { payload, protectedHeader } = await jwtVerify(token, await verificationKey(env), { issuer: env.ISSUER, algorithms: ['RS256'] });
    if (protectedHeader.typ !== 'at+jwt' || typeof payload.sub !== 'string') return null;
    return { sub: payload.sub, scope: String(payload.scope || '') };
  } catch {
    return null;
  }
}
