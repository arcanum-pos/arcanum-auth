import type { Env } from './env';

// Hourly: expired guests go (with their sessions, tokens and links), and old
// protocol state is purged. One batch — children before users (D1 enforces
// the foreign keys). Rows kept a while past expiry where that still matters:
// a revoked refresh token until it would have expired (reuse detection).
export async function cleanup(env: Env, now = new Date()): Promise<Record<string, number>> {
  const iso = now.toISOString();
  const ago = (hours: number) => new Date(now.getTime() - hours * 3600_000).toISOString();
  const expiredGuests = `SELECT id FROM users WHERE guest = 1 AND expires_at <= ?`;
  const steps: [string, string, unknown[]][] = [
    ['login_links', `DELETE FROM login_links WHERE expires_at <= ? OR user_id IN (${expiredGuests})`, [ago(1), iso]],
    ['sessions', `DELETE FROM sessions WHERE expires_at <= ? OR user_id IN (${expiredGuests})`, [iso, iso]],
    ['refresh_tokens', `DELETE FROM refresh_tokens WHERE expires_at <= ? OR user_id IN (${expiredGuests})`, [iso, iso]],
    ['auth_codes', `DELETE FROM auth_codes WHERE expires_at <= ? OR user_id IN (${expiredGuests})`, [ago(1), iso]],
    ['device_codes', `DELETE FROM device_codes WHERE expires_at <= ? OR user_id IN (${expiredGuests})`, [ago(1), iso]],
    ['email_codes', 'DELETE FROM email_codes WHERE expires_at <= ?', [ago(24)]],
    ['oauth_states', 'DELETE FROM oauth_states WHERE expires_at <= ?', [iso]],
    ['attempts', 'DELETE FROM attempts WHERE at <= ?', [ago(24)]],
    ['guests', 'DELETE FROM users WHERE guest = 1 AND expires_at <= ?', [iso]],
  ];
  const results = await env.DB.batch(steps.map(([, sql, params]) => env.DB.prepare(sql).bind(...params)));
  return Object.fromEntries(steps.map(([name], i) => [name, results[i].meta.changes ?? 0]));
}
