import { assign, unassign, accessRow } from './access';
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
//   POST   /clients/self/users          { emails[] } (up to 500) → assigns each, { assigned }
//   PUT    /clients/self/users/:email   → assigns it (a request becomes an assignment)
//   DELETE /clients/self/users/:email   → unassigns it and revokes its refresh tokens;
//          never an admin of the client ({ removed: false, reason: 'admin' })

const MAX_URIS = 10;
const MAX_BULK = 500;

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
      return json({ error: `redirect_uris: 1–${MAX_URIS} https URLs; post_logout_redirect_uris: up to ${MAX_URIS}` }, 400);
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
    const body = (await request.json().catch(() => null)) as { emails?: unknown } | null;
    const emails = Array.isArray(body?.emails) ? [...new Set(body.emails.filter((e): e is string => typeof e === 'string').map(normalizeEmail))] : null;
    if (!emails || emails.length > MAX_BULK || emails.some((e) => !isEmail(e))) return json({ error: `emails: up to ${MAX_BULK} e-mail addresses` }, 400);
    // One statement for all of them (json_each): D1's per-query limits.
    const now = nowIso();
    await env.DB.prepare(
      `INSERT INTO client_access (client_id, email, status, role, source, created_at, updated_at)
       SELECT ?, value, 'assigned', 'member', 'app', ?, ? FROM json_each(?)
       WHERE true ON CONFLICT (client_id, email) DO UPDATE SET status = 'assigned', source = 'app', updated_at = excluded.updated_at WHERE client_access.status != 'assigned'`
    )
      .bind(client.id, now, now, JSON.stringify(emails))
      .run();
    return json({ assigned: emails.length });
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
      await assign(env, client.id, email, 'app', null);
      const row = await accessRow(env, client.id, email);
      return json({ email, status: row!.status, role: row!.role });
    }
    if (request.method === 'DELETE') {
      const row = await accessRow(env, client.id, email);
      if (row?.role === 'admin' && row.status === 'assigned') return json({ email, removed: false, reason: 'admin' });
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
