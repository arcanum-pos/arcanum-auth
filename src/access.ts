import type { Env } from './env';
import { sendMail } from './mail';
import { accessAdminPage, accessPage, messagePage, texts, type AccessItem } from './pages';
import { clientById, currentSession, recordAttempt, tooManyAttempts, type Client, type User } from './store';
import { isEmail, normalizeEmail, nowIso, readForm, redirect, sameOrigin } from './util';

// Restricted clients: only the people assigned to one may sign in to it
// (every grant checks, not only /authorize). Assigned by
//   - one of the client's admins, on /access/:clientId — after a request
//     someone made on the "no access" page, or by adding an address;
//   - the application itself, /clients/self/users (clients.ts) — Arcanum
//     assigns whoever it invites, and unassigns them when they leave.
// By e-mail address, so the application can assign someone without an
// account yet. Admins are assigned too (role 'admin'); the client's owner is
// its first one. Guests never get into a restricted client.
//   GET  /access/:clientId           the client's admins: requests and who's assigned
//   POST /access/:clientId           { action, email } approve | refuse | remove | admin | member | add
//   POST /access/:clientId/request   the signed-in user asks to be added

export interface AccessRow {
  client_id: string;
  email: string;
  status: 'assigned' | 'requested';
  role: 'member' | 'admin';
  source: string;
  decided_by: string | null;
  created_at: string;
  updated_at: string;
}

// Requests per address a day (all clients together): each one mails the admins.
const MAX_REQUESTS_PER_DAY = 5;

export function accessRow(env: Env, clientId: string, email: string) {
  return env.DB.prepare('SELECT * FROM client_access WHERE client_id = ? AND email = ?').bind(clientId, normalizeEmail(email)).first<AccessRow>();
}

export async function mayUse(env: Env, client: Client, user: User): Promise<boolean> {
  if (!client.restricted) return true;
  if (user.guest) return false;
  return (await accessRow(env, client.id, user.email))?.status === 'assigned';
}

// Assigned (by an admin or the application): a request becomes an
// assignment; an admin stays one.
export async function assign(env: Env, clientId: string, email: string, source: string, by: string | null): Promise<void> {
  const now = nowIso();
  await env.DB.prepare(
    `INSERT INTO client_access (client_id, email, status, role, source, decided_by, created_at, updated_at) VALUES (?, ?, 'assigned', 'member', ?, ?, ?, ?)
     ON CONFLICT (client_id, email) DO UPDATE SET status = 'assigned', source = CASE WHEN client_access.status = 'requested' THEN excluded.source ELSE client_access.source END,
       decided_by = COALESCE(excluded.decided_by, client_access.decided_by), updated_at = excluded.updated_at
     WHERE client_access.status != 'assigned'`
  )
    .bind(clientId, normalizeEmail(email), source, by, now, now)
    .run();
}

// Gone from the client: the row, and the refresh tokens it holds for them
// (an access token still runs out within the hour).
export async function unassign(env: Env, clientId: string, email: string): Promise<void> {
  const address = normalizeEmail(email);
  await env.DB.batch([
    env.DB.prepare('DELETE FROM client_access WHERE client_id = ? AND email = ?').bind(clientId, address),
    env.DB.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE client_id = ? AND revoked_at IS NULL AND user_id IN (SELECT id FROM users WHERE email = ?)').bind(nowIso(), clientId, address),
  ]);
}

async function adminsOf(env: Env, client: Client): Promise<string[]> {
  const { results } = await env.DB.prepare("SELECT email FROM client_access WHERE client_id = ? AND role = 'admin' AND status = 'assigned' ORDER BY email")
    .bind(client.id)
    .all<{ email: string }>();
  const admins = (results || []).map((r) => r.email);
  return admins.length ? admins : client.owner_email ? [client.owner_email] : [];
}

// Where an approved person goes: the application's own address, when it has one.
const appUrl = (client: Client) => (client.instance_url?.startsWith('https://') ? client.instance_url : null);

// What someone without access sees (from /authorize or /device): ask to be
// added — or that they already did.
export async function noAccess(request: Request, env: Env, client: Client, user: User): Promise<Response> {
  if (user.guest) return messagePage(request, texts(request).accessGuest(client.name), 403);
  const row = await accessRow(env, client.id, user.email);
  return accessPage(request, { clientId: client.id, clientName: client.name, email: user.email, requested: row?.status === 'requested' }, 403);
}

export async function requestAccess(request: Request, env: Env, clientId: string): Promise<Response> {
  const t = texts(request);
  const session = await currentSession(env, request);
  if (!session) return redirect('/login');
  if (!sameOrigin(request, env.ISSUER)) return messagePage(request, t.errors.request, 403);
  const client = await clientById(env, clientId);
  if (!client || !client.restricted) return messagePage(request, t.errors.request, 404);
  const user = session.user;
  if (user.guest) return messagePage(request, t.accessGuest(client.name), 403);
  const page = (requested: boolean, status = 200) => accessPage(request, { clientId: client.id, clientName: client.name, email: user.email, requested }, status);
  if (await mayUse(env, client, user)) return messagePage(request, t.accessAlready(client.name));
  const key = `access-request:${user.email}`;
  if (await tooManyAttempts(env, key, MAX_REQUESTS_PER_DAY, 86400)) return accessPage(request, { clientId: client.id, clientName: client.name, email: user.email, requested: false, error: 'tooMany' }, 429);

  const now = nowIso();
  const added = await env.DB.prepare(
    `INSERT INTO client_access (client_id, email, status, role, source, created_at, updated_at) VALUES (?, ?, 'requested', 'member', 'request', ?, ?) ON CONFLICT (client_id, email) DO NOTHING`
  )
    .bind(client.id, user.email, now, now)
    .run();
  // Only a new request mails the admins (asking again changes nothing).
  if (added.meta.changes) {
    await recordAttempt(env, key);
    const manage = `${env.ISSUER}/access/${encodeURIComponent(client.id)}`;
    for (const admin of await adminsOf(env, client)) {
      await sendMail(env, admin, t.mailAccessRequestSubject(client.name), t.mailAccessRequest(user.name || user.email, user.email, client.name, manage)).catch((err) =>
        console.error('access request mail failed', err)
      );
    }
  }
  return page(true);
}

// --- The client's admins: /access/:clientId.

async function asAdmin(request: Request, env: Env, clientId: string): Promise<{ client: Client; user: User } | Response> {
  const session = await currentSession(env, request);
  if (!session) return redirect(`/login?continue=${encodeURIComponent(`/access/${clientId}`)}`);
  const client = await clientById(env, clientId);
  const row = client && !session.user.guest ? await accessRow(env, client.id, session.user.email) : null;
  if (!client || row?.status !== 'assigned' || row.role !== 'admin') return messagePage(request, texts(request).errors.notAdmin, 403);
  return { client, user: session.user };
}

async function adminView(request: Request, env: Env, client: Client, user: User, opts: { notice?: string; error?: 'emailInvalid' | 'lastAdmin' } = {}, status = 200) {
  const { results } = await env.DB.prepare(
    `SELECT client_access.email, client_access.status, client_access.role, client_access.created_at, users.name FROM client_access
     LEFT JOIN users ON users.email = client_access.email AND users.guest = 0
     WHERE client_access.client_id = ? ORDER BY client_access.status DESC, client_access.role, client_access.email`
  )
    .bind(client.id)
    .all<AccessItem>();
  return accessAdminPage(request, { clientId: client.id, clientName: client.name, restricted: !!client.restricted, me: user.email, items: results || [], ...opts }, status);
}

export async function manageAccess(request: Request, env: Env, clientId: string): Promise<Response> {
  const t = texts(request);
  const admin = await asAdmin(request, env, clientId);
  if (admin instanceof Response) return admin;
  const { client, user } = admin;
  if (request.method === 'GET') {
    const done = new URL(request.url).searchParams.get('done');
    return adminView(request, env, client, user, { notice: done && done in t.accessDone ? t.accessDone[done as keyof typeof t.accessDone] : undefined });
  }
  if (!sameOrigin(request, env.ISSUER)) return messagePage(request, t.errors.request, 403);
  const form = await readForm(request);
  const email = normalizeEmail(form.email || '');
  const row = email ? await accessRow(env, client.id, email) : null;
  const back = (done: string) => redirect(`/access/${encodeURIComponent(client.id)}?done=${done}`, {}, 303);
  // Never the last admin: someone has to be able to let people in.
  const lastAdmin = async () => row?.role === 'admin' && (await adminsOf(env, client)).filter((a) => a !== email).length === 0;

  switch (form.action) {
    case 'approve':
      if (row?.status !== 'requested') return back('none');
      await assign(env, client.id, email, 'request', user.email);
      await sendMail(env, email, t.mailAccessGrantedSubject(client.name), t.mailAccessGranted(client.name, appUrl(client))).catch((err) => console.error('access granted mail failed', err));
      return back('approved');
    case 'refuse':
      if (row?.status !== 'requested') return back('none');
      await env.DB.prepare("DELETE FROM client_access WHERE client_id = ? AND email = ? AND status = 'requested'").bind(client.id, email).run();
      return back('refused');
    case 'remove':
      if (!row) return back('none');
      if (await lastAdmin()) return adminView(request, env, client, user, { error: 'lastAdmin' }, 409);
      await unassign(env, client.id, email);
      return back('removed');
    case 'admin':
    case 'member':
      if (row?.status !== 'assigned') return back('none');
      if (form.action === 'member' && (await lastAdmin())) return adminView(request, env, client, user, { error: 'lastAdmin' }, 409);
      await env.DB.prepare('UPDATE client_access SET role = ?, updated_at = ? WHERE client_id = ? AND email = ?').bind(form.action, nowIso(), client.id, email).run();
      return back('role');
    case 'add':
      if (!isEmail(email)) return adminView(request, env, client, user, { error: 'emailInvalid' }, 400);
      await assign(env, client.id, email, 'admin', user.email);
      return back('added');
    default:
      return back('none');
  }
}

// The clients someone manages (a link on /account).
export async function managedClients(env: Env, user: User): Promise<{ id: string; name: string }[]> {
  if (user.guest) return [];
  const { results } = await env.DB.prepare(
    `SELECT clients.id, clients.name FROM client_access JOIN clients ON clients.id = client_access.client_id
     WHERE client_access.email = ? AND client_access.role = 'admin' AND client_access.status = 'assigned' AND clients.disabled_at IS NULL ORDER BY clients.name`
  )
    .bind(user.email)
    .all<{ id: string; name: string }>();
  return results || [];
}
