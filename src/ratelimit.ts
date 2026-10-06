import type { Env } from './env';
import { json } from './util';

// Requests that write a row without anyone signed in are limited per caller
// in memory (PUBLIC_RATE_LIMITER, 20 a minute per key) — no D1 write to count
// them, so a script can't eat the database's daily write quota with them.
export async function withinLimit(env: Env, key: string): Promise<boolean> {
  if (!env.PUBLIC_RATE_LIMITER) return true;
  return (await env.PUBLIC_RATE_LIMITER.limit({ key })).success;
}

export const tooManyRequests = () => json({ error: 'too_many_requests' }, 429, { 'Retry-After': '60' });
