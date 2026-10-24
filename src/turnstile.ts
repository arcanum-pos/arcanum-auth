import type { Env } from './env';
import { securityEvent } from './audit';

// Cloudflare Turnstile on the sign-in form (2026-10-24): a script can't make
// this IdP mail sign-in codes to address after address, whatever IP addresses
// it rotates through. On when both TURNSTILE_SITE_KEY and TURNSTILE_SECRET are
// set. Verified server-side (siteverify), for this host and this form's
// action. If siteverify can't be reached at all it lets the form through
// (the rate limits still apply) - an outage at Cloudflare shouldn't lock
// everyone out, and nobody can cause one to get past.
const SITEVERIFY = 'https://challenges.cloudflare.com/turnstile/v0/siteverify';
export const TURNSTILE_SCRIPT = 'https://challenges.cloudflare.com/turnstile/v0/api.js';
export const TURNSTILE_ORIGIN = 'https://challenges.cloudflare.com';

export const turnstileSiteKey = (env: Env): string | null => (env.TURNSTILE_SITE_KEY && env.TURNSTILE_SECRET ? env.TURNSTILE_SITE_KEY : null);

export async function turnstilePasses(env: Env, token: string | undefined, ip: string | null, action: string): Promise<boolean> {
  if (!turnstileSiteKey(env)) return true;
  if (!token) return false;
  let res: Response;
  try {
    const body = new URLSearchParams({ secret: env.TURNSTILE_SECRET!, response: token });
    if (ip) body.set('remoteip', ip);
    res = await fetch(SITEVERIFY, { method: 'POST', body });
  } catch (err) {
    securityEvent('turnstile_unreachable', { error: String(err) });
    return true;
  }
  if (!res.ok) {
    securityEvent('turnstile_unreachable', { status: res.status });
    return true;
  }
  const data = (await res.json().catch(() => null)) as { success?: boolean; hostname?: string; action?: string } | null;
  return !!data?.success && data.hostname === new URL(env.ISSUER).hostname && data.action === action;
}
