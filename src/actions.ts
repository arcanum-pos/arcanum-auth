// The post-login action (AUTH_DEDICATED.md section 4): Auth0's Actions,
// generic. An optional service binding ACTIONS to a Worker the instance's
// owner writes; whenever a person gets tokens (signing in, every refresh) it
// is asked
//   POST { email, sub, client_id, audience }  →  { claims: { "https://…": … } }
// and those claims go into the access and id token. Only claims named by an
// https URL (Auth0's custom claims); never a standard one (sub, aud, iss,
// exp, permissions, scope, …) - it can't touch identity, audience or
// permissions, and it can't refuse a sign-in. Failing or slower than 3
// seconds: the tokens go out without its claims, and it's logged. No binding
// (login.kaboutersoft.be): nothing happens.
import type { Env } from './env';

export const ACTION_TIMEOUT_MS = 3000;
// The claims together, as JSON: more is refused (a token travels in headers).
const MAX_CLAIMS_BYTES = 8192;

const RESERVED = new Set(['iss', 'sub', 'aud', 'exp', 'nbf', 'iat', 'jti', 'auth_time', 'nonce', 'acr', 'amr', 'azp', 'scope', 'permissions', 'client_id', 'gty', 'email', 'email_verified', 'name', 'sid']);

function isUrlName(name: string): boolean {
  if (RESERVED.has(name) || !name.startsWith('https://')) return false;
  try {
    return new URL(name).protocol === 'https:';
  } catch {
    return false;
  }
}

function failed(reason: string, clientId: string): Record<string, unknown> {
  console.error(JSON.stringify({ event: 'action_failed', reason, client: clientId }));
  return {};
}

export async function actionClaims(
  env: Env,
  input: { email: string; sub: string; client_id: string; audience: string | null },
  timeoutMs = ACTION_TIMEOUT_MS
): Promise<Record<string, unknown>> {
  if (!env.ACTIONS) return {};
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    const call = env.ACTIONS.fetch('https://actions/', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(input) }).then(async (res) => {
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      return (await res.json()) as { claims?: unknown };
    });
    const timeout = new Promise<never>((_, reject) => {
      timer = setTimeout(() => reject(new Error('timeout')), timeoutMs);
    });
    const body = await Promise.race([call, timeout]);
    const given = body?.claims;
    if (!given || typeof given !== 'object' || Array.isArray(given)) return given === undefined ? {} : failed('claims is not an object', input.client_id);
    const claims: Record<string, unknown> = {};
    const dropped: string[] = [];
    for (const [name, value] of Object.entries(given as Record<string, unknown>)) {
      if (isUrlName(name) && value !== undefined) claims[name] = value;
      else dropped.push(name.slice(0, 60));
    }
    if (dropped.length) console.warn(JSON.stringify({ event: 'action_claims_dropped', names: dropped, client: input.client_id }));
    if (JSON.stringify(claims).length > MAX_CLAIMS_BYTES) return failed('claims too large', input.client_id);
    return claims;
  } catch (err) {
    return failed((err as Error).message === 'timeout' ? 'timeout' : `error: ${(err as Error).message}`.slice(0, 200), input.client_id);
  } finally {
    if (timer) clearTimeout(timer);
  }
}
