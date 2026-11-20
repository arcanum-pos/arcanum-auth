// People, for the admin (admin.ts; local only, every change in the audit log).
//   POST /admin/users   { id, email, name?, email_verified? (default true) }
//                       or { users: [ … ] } (up to 500) → 201 { created, existing }
//        An import (a move from Auth0): the user gets the id given, so `sub`
//        stays what the applications know (e.g. "google-apps|jan@example.be").
//        No google_sub yet: their first Google sign-in links the Google
//        account by its verified e-mail (account.ts), keeping that id.
//        An id or address that exists already is left as it is.
import type { Env } from './env';
import { isEmail, json, normalizeEmail, nowIso } from './util';

const MAX_IMPORT = 500;

// Printable, no control characters, no surrounding spaces, up to 200 - an
// OIDC `sub` is at most 255 ASCII characters (OIDC Core 2).
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f-\u009f\u2028\u2029]/;
export const validUserId = (id: unknown): id is string => typeof id === 'string' && id.length > 0 && id.length <= 200 && id === id.trim() && !CONTROL.test(id);

interface Imported {
  id: string;
  email: string;
  name: string;
  email_verified: number;
}

function importedOf(value: unknown): Imported | null {
  const u = value as Record<string, unknown> | null;
  if (!u || typeof u !== 'object') return null;
  const email = typeof u.email === 'string' ? normalizeEmail(u.email) : '';
  if (!validUserId(u.id) || !isEmail(email)) return null;
  if (u.email_verified !== undefined && typeof u.email_verified !== 'boolean') return null;
  const name = typeof u.name === 'string' ? u.name.trim().slice(0, 100) : '';
  return { id: u.id, email, name: name || email.split('@')[0], email_verified: u.email_verified === false ? 0 : 1 };
}

export async function adminUsers(request: Request, env: Env, path: string): Promise<Response | null> {
  if (path === '/admin/users' && request.method === 'POST') {
    const body = (await request.json().catch(() => null)) as Record<string, unknown> | null;
    const given = Array.isArray(body?.users) ? body.users : body ? [body] : [];
    if (!given.length || given.length > MAX_IMPORT) return json({ error: `a user { id, email, name?, email_verified? } or users: up to ${MAX_IMPORT} of them` }, 400);
    const users: Imported[] = [];
    for (const u of given) {
      const one = importedOf(u);
      if (!one) return json({ error: 'each user needs an id (1-200 characters, no control characters or surrounding spaces) and a valid email; email_verified true or false' }, 400);
      users.push(one);
    }
    if (new Set(users.map((u) => u.id)).size !== users.length || new Set(users.map((u) => u.email)).size !== users.length) return json({ error: 'an id or e-mail address is in the list twice' }, 400);
    const now = nowIso();
    // One statement (json_each: D1's per-query limits); an existing id or address is skipped.
    const res = await env.DB.prepare(
      `INSERT INTO users (id, email, email_verified, name, created_at, updated_at)
       SELECT json_extract(value, '$.id'), json_extract(value, '$.email'), json_extract(value, '$.email_verified'), json_extract(value, '$.name'), ?, ? FROM json_each(?)
       WHERE true ON CONFLICT DO NOTHING`
    )
      .bind(now, now, JSON.stringify(users))
      .run();
    const created = res.meta.changes ?? 0;
    return json({ created, existing: users.length - created }, 201);
  }
  return null;
}
