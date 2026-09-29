import type { Env } from './env';
import { inSeconds, nowIso, randomToken, sha256, timingSafeEqual } from './util';

export interface User {
  id: string;
  email: string;
  email_verified: number;
  name: string;
  password_hash: string | null;
  google_sub: string | null;
  // A demo visitor without an account: no password, no real e-mail, gone
  // at expires_at (see LIVE_USER).
  guest: number;
  expires_at: string | null;
}

// Only users that still exist: an expired guest is refused everywhere
// (session, every grant, userinfo) from the moment it expires, before the
// cron deletes it.
const LIVE_USER = '(guest = 0 OR expires_at > ?)';

export interface Client {
  id: string;
  secret_hash: string;
  name: string;
  redirect_uris: string[];
  post_logout_redirect_uris: string[];
  instance_url: string | null;
  owner_email: string | null;
  owner_sub: string | null;
}

// --- Users.

export function userById(env: Env, id: string) {
  return env.DB.prepare(`SELECT * FROM users WHERE id = ? AND ${LIVE_USER}`).bind(id, nowIso()).first<User>();
}

export function userByEmail(env: Env, email: string) {
  return env.DB.prepare(`SELECT * FROM users WHERE email = ? AND ${LIVE_USER}`).bind(email, nowIso()).first<User>();
}

// A demo visitor: no password, an address that can't receive mail, and an
// end. `sub` is its id, like any user's.
export async function createGuest(env: Env, name: string, lifetimeHours: number): Promise<User> {
  const id = crypto.randomUUID();
  const now = nowIso();
  await env.DB.prepare(
    `INSERT INTO users (id, email, email_verified, name, created_at, updated_at, guest, expires_at) VALUES (?, ?, 0, ?, ?, ?, 1, ?)`
  )
    .bind(id, `guest-${id}@guest.invalid`, name, now, now, inSeconds(lifetimeHours * 3600))
    .run();
  return (await userById(env, id))!;
}

export async function createUser(env: Env, fields: { email: string; name: string; passwordHash?: string | null; googleSub?: string | null }): Promise<User> {
  const id = crypto.randomUUID();
  const now = nowIso();
  await env.DB.prepare(
    'INSERT INTO users (id, email, email_verified, name, password_hash, google_sub, created_at, updated_at) VALUES (?, ?, 1, ?, ?, ?, ?, ?)'
  )
    .bind(id, fields.email, fields.name, fields.passwordHash ?? null, fields.googleSub ?? null, now, now)
    .run();
  return (await userById(env, id))!;
}

// --- Clients.

interface ClientRow {
  id: string;
  secret_hash: string;
  name: string;
  redirect_uris: string;
  post_logout_redirect_uris: string;
  instance_url: string | null;
  owner_email: string | null;
  owner_sub: string | null;
  disabled_at: string | null;
}

export async function clientById(env: Env, id: string | null | undefined): Promise<Client | null> {
  if (!id) return null;
  const row = await env.DB.prepare('SELECT * FROM clients WHERE id = ?').bind(id).first<ClientRow>();
  if (!row || row.disabled_at) return null;
  return { ...row, redirect_uris: JSON.parse(row.redirect_uris), post_logout_redirect_uris: JSON.parse(row.post_logout_redirect_uris) };
}

export async function clientSecretMatches(client: Client, secret: string | null | undefined): Promise<boolean> {
  return !!secret && timingSafeEqual(await sha256(secret), client.secret_hash);
}

// The token endpoint's client authentication: client_secret_basic or
// client_secret_post (the BFF sends the latter).
export async function authenticateClient(env: Env, request: Request, form: Record<string, string>): Promise<Client | null> {
  let id = form.client_id;
  let secret = form.client_secret;
  const auth = request.headers.get('Authorization') || '';
  if (auth.startsWith('Basic ')) {
    try {
      const [u, p] = atob(auth.slice(6)).split(':');
      id = decodeURIComponent(u);
      secret = decodeURIComponent(p ?? '');
    } catch {
      return null;
    }
  }
  const client = await clientById(env, id);
  return client && (await clientSecretMatches(client, secret)) ? client : null;
}

// --- Browser sessions on the issuer itself.

export const SESSION_COOKIE = 'arcanum_auth';
const SESSION_SECONDS = 60 * 60 * 24 * 14;

// `until`: a guest's session ends with the guest, not after 14 days.
export async function createSession(env: Env, userId: string, authTime: number, until?: string | null): Promise<string> {
  const token = randomToken(32);
  const standard = inSeconds(SESSION_SECONDS);
  const expiresAt = until && until < standard ? until : standard;
  const maxAge = Math.max(0, Math.floor((Date.parse(expiresAt) - Date.now()) / 1000));
  await env.DB.prepare('INSERT INTO sessions (id_hash, user_id, auth_time, created_at, expires_at) VALUES (?, ?, ?, ?, ?)')
    .bind(await sha256(token), userId, authTime, nowIso(), expiresAt)
    .run();
  return `${SESSION_COOKIE}=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function cookieValue(request: Request, name: string): string | null {
  for (const part of (request.headers.get('Cookie') || '').split(';')) {
    const [k, ...v] = part.trim().split('=');
    if (k === name) return v.join('=');
  }
  return null;
}

export async function currentSession(env: Env, request: Request): Promise<{ user: User; authTime: number } | null> {
  const token = cookieValue(request, SESSION_COOKIE);
  if (!token) return null;
  const row = await env.DB.prepare(
    `SELECT users.*, sessions.auth_time AS session_auth_time FROM sessions JOIN users ON users.id = sessions.user_id
     WHERE sessions.id_hash = ? AND sessions.expires_at > ? AND (users.guest = 0 OR users.expires_at > ?)`
  )
    .bind(await sha256(token), nowIso(), nowIso())
    .first<User & { session_auth_time: number }>();
  return row ? { user: row, authTime: row.session_auth_time } : null;
}

export async function endSession(env: Env, request: Request): Promise<string> {
  const token = cookieValue(request, SESSION_COOKIE);
  if (token) await env.DB.prepare('DELETE FROM sessions WHERE id_hash = ?').bind(await sha256(token)).run();
  return `${SESSION_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

// --- Rate limiting: at most `max` failures per key in `windowSeconds`.

export async function tooManyAttempts(env: Env, key: string, max: number, windowSeconds = 900): Promise<boolean> {
  const since = new Date(Date.now() - windowSeconds * 1000).toISOString();
  const row = await env.DB.prepare('SELECT COUNT(*) AS n FROM attempts WHERE key = ? AND at > ?').bind(key, since).first<{ n: number }>();
  return (row?.n ?? 0) >= max;
}

export async function recordAttempt(env: Env, key: string): Promise<void> {
  await env.DB.prepare('INSERT INTO attempts (key, at) VALUES (?, ?)').bind(key, nowIso()).run();
}

export function clientIp(request: Request): string {
  return request.headers.get('CF-Connecting-IP') || 'unknown';
}
