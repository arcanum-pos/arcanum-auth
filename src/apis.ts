// APIs, roles and application access (AUTH_DEDICATED.md section 2, migration
// 0014) - Auth0's model, for a dedicated instance. Unused (no rows) on
// login.kaboutersoft.be, where nothing here changes a token.
//
// A user's access token for audience X (an API's id):
//   permissions = (X's permissions in the user's roles, default roles included)
//               ∩ (X's permissions the application may ask for: kind 'user')
// Worked out on every token issue (refresh too), so a change is in effect
// within one access token's lifetime. A machine client (kind 'client') gets
// its own permissions on X (machine.ts).
//
// Admin API (admin.ts, index.ts: local only, every change in the audit log):
//   GET    /admin/apis                         → [{ id, name, permissions[], clients, roles }]
//   POST   /admin/apis                         { id, name, permissions?: [{ name, description? }] } → 201
//   GET    /admin/apis/:id                     → the API, its permissions, which applications and roles use them
//   PATCH  /admin/apis/:id                     { name }
//   DELETE /admin/apis/:id                     → with its permissions, and every role's and application's grant of them
//   PUT    /admin/apis/:id/permissions/:name   { description? } → adds or describes one
//   DELETE /admin/apis/:id/permissions/:name   → and every grant of it
//   GET    /admin/roles                        → [{ id, name, description, is_default, permissions[], members }]
//   POST   /admin/roles                        { name, description?, is_default?, permissions?: [{ api_id, permission }] } → 201
//   GET    /admin/roles/:id                    → the role with its members
//   PATCH  /admin/roles/:id                    { name?, description?, is_default? }
//   PUT    /admin/roles/:id/permissions        { permissions: [{ api_id, permission }] } → replaces them
//   DELETE /admin/roles/:id                    → with its permissions and members
//   POST   /admin/roles/:id/members            { emails: [] } (up to 500) → { added }
//   DELETE /admin/roles/:id/members/:email
//   GET    /admin/clients/:id/api-access       → [{ api_id, kind, permission }]
//   PUT    /admin/clients/:id/api-access/:api  { user?: [], client?: [] } → replaces each kind given
import type { Env } from './env';
import { isEmail, json, normalizeEmail, nowIso, randomToken } from './util';

const API_ID = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}$/;
const PERMISSION = /^[A-Za-z0-9][A-Za-z0-9._:/*+-]{0,99}$/;
const MAX_LIST = 500;

// --- Tokens.

// May this application ask for `audience` for its users? 'ignored': no API
// has that id, so the audience means nothing here and is left out, as it
// always was (an app on the shared instance sending one isn't refused all
// of a sudden, not even once other apps have APIs). 'refused': that API
// exists and this app has no user access to it.
export async function audienceCheck(env: Env, clientId: string, audience: string): Promise<'ok' | 'refused' | 'ignored'> {
  let row: { api: number; allowed: number } | null;
  try {
    row = await env.DB.prepare(
      `SELECT EXISTS (SELECT 1 FROM apis WHERE id = ?2) AS api,
         EXISTS (SELECT 1 FROM client_api_access a JOIN apis ON apis.id = a.api_id WHERE a.client_id = ?1 AND a.api_id = ?2 AND a.kind = 'user') AS allowed`
    )
      .bind(clientId, audience)
      .first();
  } catch {
    // No tables yet (migration 0014 not applied): as before.
    return 'ignored';
  }
  if (row?.allowed) return 'ok';
  // Refused only for an API that exists and this app may not ask for. An
  // audience no API is called (an app that always sends one, e.g. left from
  // Auth0): ignored, as on an instance without APIs - so creating an API
  // never breaks another app.
  return row?.api ? 'refused' : 'ignored';
}

// Still allowed at a refresh (the app's user access to that API may be gone since).
export async function userAccessTo(env: Env, clientId: string, audience: string): Promise<boolean> {
  const row = await env.DB.prepare(
    "SELECT 1 FROM client_api_access a JOIN apis ON apis.id = a.api_id WHERE a.client_id = ? AND a.api_id = ? AND a.kind = 'user' LIMIT 1"
  )
    .bind(clientId, audience)
    .first();
  return !!row;
}

// The user's permissions on `audience` through this application: roles ∩ the app's user access. One query.
export async function userPermissions(env: Env, clientId: string, email: string, audience: string): Promise<string[]> {
  const { results } = await env.DB.prepare(
    `SELECT DISTINCT rp.permission FROM role_permissions rp JOIN roles r ON r.id = rp.role_id
     WHERE rp.api_id = ?1
       AND (r.is_default = 1 OR EXISTS (SELECT 1 FROM role_members m WHERE m.role_id = r.id AND m.email = ?2))
       AND EXISTS (SELECT 1 FROM client_api_access a WHERE a.client_id = ?3 AND a.api_id = ?1 AND a.kind = 'user' AND a.permission = rp.permission)
       AND EXISTS (SELECT 1 FROM api_permissions p WHERE p.api_id = ?1 AND p.name = rp.permission)
     ORDER BY rp.permission`
  )
    .bind(audience, normalizeEmail(email), clientId)
    .all<{ permission: string }>();
  return (results || []).map((r) => r.permission);
}

// A machine client's own permissions on `audience` (kind 'client'), of that API's.
export async function clientPermissions(env: Env, clientId: string, audience: string): Promise<string[]> {
  const { results } = await env.DB.prepare(
    `SELECT a.permission FROM client_api_access a JOIN api_permissions p ON p.api_id = a.api_id AND p.name = a.permission
     WHERE a.client_id = ? AND a.api_id = ? AND a.kind = 'client' ORDER BY a.permission`
  )
    .bind(clientId, audience)
    .all<{ permission: string }>();
  return (results || []).map((r) => r.permission);
}

// --- Admin API.

type Body = Record<string, unknown> | null;
const bodyOf = async (request: Request): Promise<Body> => (await request.json().catch(() => null)) as Body;
const text = (v: unknown, max: number) => (typeof v === 'string' ? v.trim().slice(0, max) : '');
const decode = (v: string) => {
  try {
    return decodeURIComponent(v);
  } catch {
    return '';
  }
};

// [{ name, description? }] → checked, one per name; null when any is wrong.
function permissionList(value: unknown): { name: string; description: string }[] | null {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > MAX_LIST) return null;
  const out = new Map<string, { name: string; description: string }>();
  for (const p of value) {
    const name = typeof p === 'string' ? p : text((p as { name?: unknown })?.name, 100);
    if (!PERMISSION.test(name)) return null;
    out.set(name, { name, description: typeof p === 'string' ? '' : text((p as { description?: unknown }).description, 300) });
  }
  return [...out.values()];
}

// [{ api_id, permission }] → one each; null when any is malformed.
function grantList(value: unknown): { api_id: string; permission: string }[] | null {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > MAX_LIST) return null;
  const out = new Map<string, { api_id: string; permission: string }>();
  for (const g of value) {
    const api = typeof (g as { api_id?: unknown })?.api_id === 'string' ? (g as { api_id: string }).api_id : '';
    const permission = typeof (g as { permission?: unknown })?.permission === 'string' ? (g as { permission: string }).permission : '';
    if (!API_ID.test(api) || !PERMISSION.test(permission)) return null;
    out.set(`${api} ${permission}`, { api_id: api, permission });
  }
  return [...out.values()];
}

// Do all of these exist (each an API's permission)? One query.
async function grantsExist(env: Env, grants: { api_id: string; permission: string }[]): Promise<boolean> {
  if (!grants.length) return true;
  const row = await env.DB.prepare(
    `SELECT COUNT(*) AS n FROM json_each(?) j WHERE EXISTS (SELECT 1 FROM api_permissions p WHERE p.api_id = json_extract(j.value, '$.api_id') AND p.name = json_extract(j.value, '$.permission'))`
  )
    .bind(JSON.stringify(grants))
    .first<{ n: number }>();
  return row?.n === grants.length;
}

function emailList(value: unknown): string[] | null {
  if (!Array.isArray(value) || !value.length || value.length > MAX_LIST) return null;
  const out = new Set<string>();
  for (const e of value) {
    const email = typeof e === 'string' ? normalizeEmail(e) : '';
    if (!isEmail(email)) return null;
    out.add(email);
  }
  return [...out];
}

const notFound = () => json({ error: 'Not found' }, 404);

async function apiExists(env: Env, id: string): Promise<boolean> {
  return !!(await env.DB.prepare('SELECT 1 FROM apis WHERE id = ?').bind(id).first());
}

async function roleById(env: Env, id: string) {
  return env.DB.prepare('SELECT id, name, description, is_default, created_at FROM roles WHERE id = ?')
    .bind(id)
    .first<{ id: string; name: string; description: string; is_default: number; created_at: string }>();
}

// The routes above; null when the path is none of them (admin.ts goes on).
export async function adminApis(request: Request, env: Env, path: string, by: string): Promise<Response | null> {
  const method = request.method;

  // --- APIs.
  if (path === '/admin/apis' && method === 'GET') {
    const [apis, permissions, clients, roles] = await env.DB.batch([
      env.DB.prepare('SELECT id, name, created_at FROM apis ORDER BY name'),
      env.DB.prepare('SELECT api_id, name, description FROM api_permissions ORDER BY name'),
      env.DB.prepare('SELECT api_id, COUNT(DISTINCT client_id) AS n FROM client_api_access GROUP BY api_id'),
      env.DB.prepare('SELECT api_id, COUNT(DISTINCT role_id) AS n FROM role_permissions GROUP BY api_id'),
    ]);
    const count = (rows: unknown[], id: string) => (rows as { api_id: string; n: number }[]).find((r) => r.api_id === id)?.n ?? 0;
    return json(
      (apis.results as { id: string; name: string; created_at: string }[]).map((a) => ({
        ...a,
        permissions: (permissions.results as { api_id: string; name: string; description: string }[]).filter((p) => p.api_id === a.id).map(({ name, description }) => ({ name, description })),
        clients: count(clients.results, a.id),
        roles: count(roles.results, a.id),
      }))
    );
  }

  if (path === '/admin/apis' && method === 'POST') {
    const body = await bodyOf(request);
    const id = text(body?.id, 200);
    const name = text(body?.name, 100) || id;
    const permissions = permissionList(body?.permissions);
    if (!API_ID.test(id) || !permissions) return json({ error: 'id (the audience: letters, digits and ._:/@+-, up to 200) and permissions [{ name, description? }] are required' }, 400);
    if (await apiExists(env, id)) return json({ error: 'An API with this id exists' }, 409);
    await env.DB.batch([
      env.DB.prepare('INSERT INTO apis (id, name, created_at) VALUES (?, ?, ?)').bind(id, name, nowIso()),
      env.DB.prepare(`INSERT INTO api_permissions (api_id, name, description) SELECT ?, json_extract(value, '$.name'), json_extract(value, '$.description') FROM json_each(?)`).bind(
        id,
        JSON.stringify(permissions)
      ),
    ]);
    return json({ id, name, permissions }, 201);
  }

  const api = path.match(/^\/admin\/apis\/([^/]+)$/);
  if (api) {
    const id = decode(api[1]);
    if (!(await apiExists(env, id))) return notFound();
    if (method === 'GET') {
      const [row, permissions, clients, roles] = await env.DB.batch([
        env.DB.prepare('SELECT id, name, created_at FROM apis WHERE id = ?').bind(id),
        env.DB.prepare('SELECT name, description FROM api_permissions WHERE api_id = ? ORDER BY name').bind(id),
        env.DB.prepare('SELECT a.client_id, c.name, a.kind, a.permission FROM client_api_access a LEFT JOIN clients c ON c.id = a.client_id WHERE a.api_id = ? ORDER BY c.name, a.kind, a.permission').bind(id),
        env.DB.prepare('SELECT rp.role_id, r.name, rp.permission FROM role_permissions rp JOIN roles r ON r.id = rp.role_id WHERE rp.api_id = ? ORDER BY r.name, rp.permission').bind(id),
      ]);
      return json({ ...(row.results[0] as object), permissions: permissions.results, clients: clients.results, roles: roles.results });
    }
    if (method === 'PATCH') {
      const name = text((await bodyOf(request))?.name, 100);
      if (!name) return json({ error: 'name is required' }, 400);
      await env.DB.prepare('UPDATE apis SET name = ? WHERE id = ?').bind(name, id).run();
      return json({ ok: true, id, name });
    }
    if (method === 'DELETE') {
      await env.DB.batch([
        env.DB.prepare('DELETE FROM client_api_access WHERE api_id = ?').bind(id),
        env.DB.prepare('DELETE FROM role_permissions WHERE api_id = ?').bind(id),
        env.DB.prepare('DELETE FROM api_permissions WHERE api_id = ?').bind(id),
        env.DB.prepare('DELETE FROM apis WHERE id = ?').bind(id),
      ]);
      return json({ ok: true });
    }
  }

  const permission = path.match(/^\/admin\/apis\/([^/]+)\/permissions\/([^/]+)$/);
  if (permission) {
    const id = decode(permission[1]);
    const name = decode(permission[2]);
    if (!(await apiExists(env, id))) return notFound();
    if (method === 'PUT') {
      if (!PERMISSION.test(name)) return json({ error: 'A permission: letters, digits and ._:/*+-, up to 100' }, 400);
      const description = text((await bodyOf(request))?.description, 300);
      await env.DB.prepare('INSERT INTO api_permissions (api_id, name, description) VALUES (?, ?, ?) ON CONFLICT (api_id, name) DO UPDATE SET description = excluded.description')
        .bind(id, name, description)
        .run();
      return json({ ok: true, name, description });
    }
    if (method === 'DELETE') {
      const [, , gone] = await env.DB.batch([
        env.DB.prepare('DELETE FROM client_api_access WHERE api_id = ? AND permission = ?').bind(id, name),
        env.DB.prepare('DELETE FROM role_permissions WHERE api_id = ? AND permission = ?').bind(id, name),
        env.DB.prepare('DELETE FROM api_permissions WHERE api_id = ? AND name = ?').bind(id, name),
      ]);
      return gone.meta.changes ? json({ ok: true }) : notFound();
    }
  }

  // --- Roles.
  if (path === '/admin/roles' && method === 'GET') {
    const [roles, grants, members] = await env.DB.batch([
      env.DB.prepare('SELECT id, name, description, is_default, created_at FROM roles ORDER BY name'),
      env.DB.prepare('SELECT role_id, api_id, permission FROM role_permissions ORDER BY api_id, permission'),
      env.DB.prepare('SELECT role_id, COUNT(*) AS n FROM role_members GROUP BY role_id'),
    ]);
    return json(
      (roles.results as { id: string; name: string; description: string; is_default: number; created_at: string }[]).map((r) => ({
        ...r,
        is_default: !!r.is_default,
        permissions: (grants.results as { role_id: string; api_id: string; permission: string }[]).filter((g) => g.role_id === r.id).map(({ api_id, permission }) => ({ api_id, permission })),
        members: (members.results as { role_id: string; n: number }[]).find((m) => m.role_id === r.id)?.n ?? 0,
      }))
    );
  }

  if (path === '/admin/roles' && method === 'POST') {
    const body = await bodyOf(request);
    const name = text(body?.name, 100);
    const grants = grantList(body?.permissions);
    if (!name || !grants || (body?.is_default !== undefined && typeof body.is_default !== 'boolean')) {
      return json({ error: 'name, and permissions [{ api_id, permission }], is_default (true or false) if given' }, 400);
    }
    if (!(await grantsExist(env, grants))) return json({ error: 'Every permission must be one of an API' }, 400);
    if (await env.DB.prepare('SELECT 1 FROM roles WHERE name = ?').bind(name).first()) return json({ error: 'A role with this name exists' }, 409);
    const id = `rol_${randomToken(12)}`;
    await env.DB.batch([
      env.DB.prepare('INSERT INTO roles (id, name, description, is_default, created_at) VALUES (?, ?, ?, ?, ?)').bind(id, name, text(body?.description, 300), body?.is_default ? 1 : 0, nowIso()),
      env.DB.prepare(`INSERT INTO role_permissions (role_id, api_id, permission) SELECT ?, json_extract(value, '$.api_id'), json_extract(value, '$.permission') FROM json_each(?)`).bind(
        id,
        JSON.stringify(grants)
      ),
    ]);
    return json({ id, name, is_default: !!body?.is_default, permissions: grants }, 201);
  }

  const role = path.match(/^\/admin\/roles\/([^/]+)(\/permissions|\/members(?:\/([^/]+))?)?$/);
  if (role) {
    const found = await roleById(env, decode(role[1]));
    if (!found) return notFound();
    const id = found.id;
    const sub = role[2] ?? '';

    if (!sub && method === 'GET') {
      const [grants, members] = await env.DB.batch([
        env.DB.prepare('SELECT api_id, permission FROM role_permissions WHERE role_id = ? ORDER BY api_id, permission').bind(id),
        env.DB.prepare('SELECT email, added_by, created_at FROM role_members WHERE role_id = ? ORDER BY email').bind(id),
      ]);
      return json({ ...found, is_default: !!found.is_default, permissions: grants.results, members: members.results });
    }
    if (!sub && method === 'PATCH') {
      const body = await bodyOf(request);
      const sets: string[] = [];
      const params: unknown[] = [];
      if (body?.name !== undefined) {
        const name = text(body.name, 100);
        if (!name) return json({ error: 'name must not be empty' }, 400);
        if (await env.DB.prepare('SELECT 1 FROM roles WHERE name = ? AND id != ?').bind(name, id).first()) return json({ error: 'A role with this name exists' }, 409);
        sets.push('name = ?');
        params.push(name);
      }
      if (body?.description !== undefined) {
        sets.push('description = ?');
        params.push(text(body.description, 300));
      }
      if (body?.is_default !== undefined) {
        if (typeof body.is_default !== 'boolean') return json({ error: 'is_default must be true or false' }, 400);
        sets.push('is_default = ?');
        params.push(body.is_default ? 1 : 0);
      }
      if (!sets.length) return json({ error: 'name, description or is_default is required' }, 400);
      await env.DB.prepare(`UPDATE roles SET ${sets.join(', ')} WHERE id = ?`).bind(...params, id).run();
      const after = (await roleById(env, id))!;
      return json({ ...after, is_default: !!after.is_default });
    }
    if (!sub && method === 'DELETE') {
      await env.DB.batch([
        env.DB.prepare('DELETE FROM role_permissions WHERE role_id = ?').bind(id),
        env.DB.prepare('DELETE FROM role_members WHERE role_id = ?').bind(id),
        env.DB.prepare('DELETE FROM roles WHERE id = ?').bind(id),
      ]);
      return json({ ok: true });
    }
    if (sub === '/permissions' && method === 'PUT') {
      const body = await bodyOf(request);
      const grants = grantList(body?.permissions);
      if (!grants || !Array.isArray(body?.permissions)) return json({ error: 'permissions [{ api_id, permission }] is required' }, 400);
      if (!(await grantsExist(env, grants))) return json({ error: 'Every permission must be one of an API' }, 400);
      await env.DB.batch([
        env.DB.prepare('DELETE FROM role_permissions WHERE role_id = ?').bind(id),
        env.DB.prepare(`INSERT INTO role_permissions (role_id, api_id, permission) SELECT ?, json_extract(value, '$.api_id'), json_extract(value, '$.permission') FROM json_each(?)`).bind(
          id,
          JSON.stringify(grants)
        ),
      ]);
      return json({ ok: true, permissions: grants });
    }
    if (sub === '/members' && method === 'POST') {
      const emails = emailList((await bodyOf(request))?.emails);
      if (!emails) return json({ error: `emails: 1-${MAX_LIST} e-mail addresses` }, 400);
      await env.DB.prepare(`INSERT INTO role_members (role_id, email, added_by, created_at) SELECT ?, value, ?, ? FROM json_each(?) WHERE true ON CONFLICT (role_id, email) DO NOTHING`)
        .bind(id, by, nowIso(), JSON.stringify(emails))
        .run();
      return json({ ok: true, added: emails.length });
    }
    if (sub.startsWith('/members/') && method === 'DELETE') {
      const email = normalizeEmail(decode(role[3] ?? ''));
      const res = await env.DB.prepare('DELETE FROM role_members WHERE role_id = ? AND email = ?').bind(id, email).run();
      return res.meta.changes ? json({ ok: true }) : notFound();
    }
  }

  // --- An application's access to APIs.
  const access = path.match(/^\/admin\/clients\/([^/]+)\/api-access(?:\/([^/]+))?$/);
  if (access) {
    const clientId = decode(access[1]);
    const client = await env.DB.prepare('SELECT id FROM clients WHERE id = ?').bind(clientId).first();
    if (!client) return notFound();
    if (!access[2] && method === 'GET') {
      const { results } = await env.DB.prepare('SELECT api_id, kind, permission FROM client_api_access WHERE client_id = ? ORDER BY api_id, kind, permission').bind(clientId).all();
      return json(results || []);
    }
    if (access[2] && method === 'PUT') {
      const apiId = decode(access[2]);
      if (!(await apiExists(env, apiId))) return notFound();
      const body = await bodyOf(request);
      const statements: D1PreparedStatement[] = [];
      const kinds = await accessKinds(env, clientId);
      for (const kind of ['user', 'client'] as const) {
        if (body?.[kind] === undefined) continue;
        const list = permissionList(body[kind]);
        if (!list) return json({ error: `${kind}: a list of permission names` }, 400);
        if (list.length && !kinds.includes(kind)) return json({ error: kind === 'user' ? 'A machine client has no users: only client access' : 'Only a machine client gets client access' }, 400);
        const grants = list.map((p) => ({ api_id: apiId, permission: p.name }));
        if (!(await grantsExist(env, grants))) return json({ error: `${kind}: every permission must be one of ${apiId}` }, 400);
        statements.push(
          env.DB.prepare('DELETE FROM client_api_access WHERE client_id = ? AND api_id = ? AND kind = ?').bind(clientId, apiId, kind),
          env.DB.prepare(`INSERT INTO client_api_access (client_id, api_id, kind, permission) SELECT ?, ?, ?, value FROM json_each(?)`).bind(
            clientId,
            apiId,
            kind,
            JSON.stringify(grants.map((g) => g.permission))
          )
        );
      }
      if (!statements.length) return json({ error: 'user or client (a list of permission names) is required' }, 400);
      await env.DB.batch(statements);
      const { results } = await env.DB.prepare('SELECT kind, permission FROM client_api_access WHERE client_id = ? AND api_id = ? ORDER BY kind, permission').bind(clientId, apiId).all<{ kind: string; permission: string }>();
      const rows = results || [];
      return json({ ok: true, api_id: apiId, user: rows.filter((r) => r.kind === 'user').map((r) => r.permission), client: rows.filter((r) => r.kind === 'client').map((r) => r.permission) });
    }
  }
  return null;
}

// Which kinds of API access a client can have: a user client asks on behalf
// of its users, a machine client (machine.ts) only for itself.
async function accessKinds(env: Env, clientId: string): Promise<('user' | 'client')[]> {
  const row = await env.DB.prepare('SELECT kind FROM clients WHERE id = ?').bind(clientId).first<{ kind: string }>();
  return row?.kind === 'machine' ? ['client'] : ['user'];
}
