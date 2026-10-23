import { unassign, accessRow } from './access';
import { validUris } from './admin';
import type { Env } from './env';
import { clientById, clientSecretMatches, type Client } from './store';
import { isEmail, json, normalizeEmail, nowIso, randomToken, sha256 } from './util';

// Client self-service — an application managing its own client
// with its own credentials (HTTP Basic: client_id:client_secret), never the
// admin key. What the installer uses after setting a custom domain:
//   GET   /clients/self         → its name + URIs
//   PATCH /clients/self         { redirect_uris?, post_logout_redirect_uris? } (replaces each list given)
//   POST  /clients/self/secret  → { client_secret } — a new one; the old stops working
// Who may use it (a restricted client, access.ts) — Arcanum assigns whoever
// it invites, and unassigns them when they leave:
//   GET    /clients/self/users          → { restricted, users: [{ email, status, role }] }
//   POST   /clients/self/users          { users: [{ email, role? }] } or { emails[] } (up to 500) → assigns each, { assigned }
//   PUT    /clients/self/users/:email   { role? } → assigns it (a request becomes an assignment)
//   DELETE /clients/self/users/:email   → unassigns it and revokes its refresh tokens;
//          never an admin it didn't make ({ removed: false, reason: 'admin' })
// role 'admin' makes someone an admin of the client (Arcanum: an admin of
// one of its organisations); 'member' (the default) takes that back — only
// from admins the application made (app_admin), never the owner or one an
// admin chose on /access/:clientId. On an open client, nobody becomes admin
// through the application (its admins would see every address on its list).

const MAX_URIS = 10;
const MAX_BULK = 500;

interface AppUser {
  email: string;
  role: 'admin' | 'member';
}

// [{ email, role? }] → normalized, one per address (the last wins); null when any is wrong.
function usersOf(given: unknown[]): AppUser[] | null {
  const out = new Map<string, AppUser>();
  for (const u of given) {
    const email = typeof (u as { email?: unknown })?.email === 'string' ? normalizeEmail((u as { email: string }).email) : '';
    const role = (u as { role?: unknown }).role ?? 'member';
    if (!isEmail(email) || (role !== 'admin' && role !== 'member')) return null;
    out.set(email, { email, role });
  }
  return [...out.values()];
}

// One statement for all of them (json_each: D1's per-query limits). An
// assignment either way; the role as the application says — but only an
// admin it made itself goes back to member, and on an open client nobody
// becomes admin this way.
async function assignFromApp(env: Env, client: Client, users: AppUser[]): Promise<void> {
  if (!users.length) return;
  const now = nowIso();
  const rows = users.map((u) => ({ email: u.email, role: client.restricted ? u.role : 'member' }));
  await env.DB.prepare(
    `INSERT INTO client_access (client_id, email, status, role, source, app_admin, created_at, updated_at)
     SELECT ?, json_extract(value, '$.email'), 'assigned', json_extract(value, '$.role'), 'app', json_extract(value, '$.role') = 'admin', ?, ? FROM json_each(?)
     WHERE true ON CONFLICT (client_id, email) DO UPDATE SET
       status = 'assigned',
       source = CASE WHEN client_access.status = 'requested' THEN 'app' ELSE client_access.source END,
       role = CASE WHEN excluded.role = 'admin' THEN 'admin' WHEN client_access.app_admin = 1 THEN 'member' ELSE client_access.role END,
       app_admin = CASE
         WHEN excluded.role = 'admin' AND (client_access.role != 'admin' OR client_access.status != 'assigned') THEN 1
         WHEN excluded.role = 'admin' THEN client_access.app_admin
         ELSE 0 END,
       updated_at = excluded.updated_at`
  )
    .bind(client.id, now, now, JSON.stringify(rows))
    .run();
}

async function authenticated(request: Request, env: Env): Promise<Client | null> {
  const auth = request.headers.get('Authorization') || '';
  if (!auth.startsWith('Basic ')) return null;
  try {
    const [id, secret] = atob(auth.slice(6)).split(':').map(decodeURIComponent);
    const client = await clientById(env, id);
    return client && (await clientSecretMatches(client, secret)) ? client : null;
  } catch {
    return null;
  }
}

const view = (c: Client) => ({
  client_id: c.id,
  name: c.name,
  redirect_uris: c.redirect_uris,
  post_logout_redirect_uris: c.post_logout_redirect_uris,
  instance_url: c.instance_url,
});

export async function clientSelf(request: Request, env: Env, path: string): Promise<Response> {
  const client = await authenticated(request, env);
  if (!client) return json({ error: 'invalid_client' }, 401, { 'WWW-Authenticate': 'Basic realm="clients"' });

  if (path === '/clients/self' && request.method === 'GET') return json(view(client));

  if (path === '/clients/self' && request.method === 'PATCH') {
    const body = (await request.json().catch(() => null)) as Record<string, unknown> | null;
    if (!body) return json({ error: 'a JSON body is required' }, 400);
    const redirects = body.redirect_uris === undefined ? client.redirect_uris : validUris(body.redirect_uris);
    const logouts = body.post_logout_redirect_uris === undefined ? client.post_logout_redirect_uris : validUris(body.post_logout_redirect_uris);
    if (!redirects || !logouts || redirects.length === 0 || redirects.length > MAX_URIS || logouts.length > MAX_URIS) {
      return json({ error: `redirect_uris: 1-${MAX_URIS} https URLs; post_logout_redirect_uris: up to ${MAX_URIS}` }, 400);
    }
    await env.DB.prepare('UPDATE clients SET redirect_uris = ?, post_logout_redirect_uris = ? WHERE id = ?')
      .bind(JSON.stringify(redirects), JSON.stringify(logouts), client.id)
      .run();
    return json(view({ ...client, redirect_uris: redirects, post_logout_redirect_uris: logouts }));
  }

  if (path === '/clients/self/users' && request.method === 'GET') {
    const { results } = await env.DB.prepare('SELECT email, status, role FROM client_access WHERE client_id = ? ORDER BY email').bind(client.id).all();
    return json({ restricted: !!client.restricted, users: results || [] });
  }

  if (path === '/clients/self/users' && request.method === 'POST') {
    const body = (await request.json().catch(() => null)) as { users?: unknown; emails?: unknown } | null;
    const given = Array.isArray(body?.users) ? body.users : Array.isArray(body?.emails) ? body.emails.map((email) => ({ email })) : null;
    const users = given ? usersOf(given) : null;
    if (!users || users.length > MAX_BULK) return json({ error: `users: up to ${MAX_BULK} of { email, role? } (role admin or member)` }, 400);
    await assignFromApp(env, client, users);
    return json({ assigned: users.length });
  }

  const one = path.match(/^\/clients\/self\/users\/([^/]+)$/);
  if (one) {
    let email: string;
    try {
      email = normalizeEmail(decodeURIComponent(one[1]));
    } catch {
      return json({ error: 'not an e-mail address' }, 400);
    }
    if (!isEmail(email)) return json({ error: 'not an e-mail address' }, 400);
    if (request.method === 'PUT') {
      const body = (await request.json().catch(() => ({}))) as { role?: unknown } | null;
      const users = usersOf([{ email, role: body?.role }]);
      if (!users) return json({ error: 'role must be admin or member' }, 400);
      await assignFromApp(env, client, users);
      const row = await accessRow(env, client.id, email);
      return json({ email, status: row!.status, role: row!.role });
    }
    if (request.method === 'DELETE') {
      const row = await accessRow(env, client.id, email);
      if (row?.role === 'admin' && row.status === 'assigned' && !row.app_admin) return json({ email, removed: false, reason: 'admin' });
      if (row) await unassign(env, client.id, email);
      return json({ email, removed: !!row });
    }
  }

  if (path === '/clients/self/secret' && request.method === 'POST') {
    const secret = randomToken(32);
    await env.DB.prepare('UPDATE clients SET secret_hash = ? WHERE id = ?').bind(await sha256(secret), client.id).run();
    return json({ client_id: client.id, client_secret: secret });
  }
  return json({ error: 'Not found' }, 404);
}
