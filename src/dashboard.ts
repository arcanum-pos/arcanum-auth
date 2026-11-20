// What tools/admin's dashboard reads and does besides clients, APIs and roles
// (AUTH_DEDICATED.md section 6). Admin API, local only like all of /admin/*.
//   GET    /admin/overview                    → counts, active people (30 days), recent admin actions
//   GET    /admin/audit?limit=                → the audit log, newest first (up to 500)
//   GET    /admin/users?q=                    → people (not guests): last sign-in, roles, Google, passkeys (up to 200)
//   POST   /admin/users/:email/sign-out       → every session and refresh token of that person ends
//   GET    /admin/access-requests             → open access requests, every client
//   GET    /admin/clients/:id/users           → who may sign in to it (a restricted client), and requests
//   PUT    /admin/clients/:id/users/:email    → assigned (a request becomes an assignment)
//   DELETE /admin/clients/:id/users/:email    → unassigned (its refresh tokens revoked); an open request refused
import { assign, unassign } from './access';
import { securityEvent } from './audit';
import type { Env } from './env';
import { isEmail, json, normalizeEmail, nowIso } from './util';

const decode = (v: string) => {
  try {
    return decodeURIComponent(v);
  } catch {
    return '';
  }
};

export async function adminDashboard(request: Request, env: Env, path: string, by: string): Promise<Response | null> {
  const method = request.method;
  const url = new URL(request.url);
  const since30 = new Date(Date.now() - 30 * 86400_000).toISOString();

  if (path === '/admin/overview' && method === 'GET') {
    const [counts, recent] = await env.DB.batch([
      env.DB.prepare(
        `SELECT
           (SELECT COUNT(*) FROM clients WHERE disabled_at IS NULL AND kind = 'user') AS applications,
           (SELECT COUNT(*) FROM clients WHERE disabled_at IS NULL AND kind = 'machine') AS machine_clients,
           (SELECT COUNT(*) FROM users WHERE guest = 0) AS people,
           (SELECT COUNT(DISTINCT user_id) FROM client_users WHERE last_used_at > ?) AS active_30_days,
           (SELECT COUNT(*) FROM client_access WHERE status = 'requested') AS access_requests,
           (SELECT COUNT(*) FROM apis) AS apis,
           (SELECT COUNT(*) FROM roles) AS roles`
      ).bind(since30),
      env.DB.prepare('SELECT at, name, by, detail FROM audit_log ORDER BY id DESC LIMIT 8'),
    ]);
    return json({ ...(counts.results[0] as object), recent: auditRows(recent.results) });
  }

  if (path === '/admin/audit' && method === 'GET') {
    const limit = Math.min(500, Math.max(1, Number(url.searchParams.get('limit')) || 200));
    const { results } = await env.DB.prepare('SELECT at, name, by, detail FROM audit_log ORDER BY id DESC LIMIT ?').bind(limit).all();
    return json(auditRows(results || []));
  }

  if (path === '/admin/users' && method === 'GET') {
    const q = (url.searchParams.get('q') || '').trim().toLowerCase().slice(0, 100);
    const like = `%${q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
    const { results } = await env.DB.prepare(
      `SELECT u.id, u.email, u.name, u.created_at, u.google_sub IS NOT NULL AS google,
         (SELECT COUNT(*) FROM passkeys p WHERE p.user_id = u.id) AS passkeys,
         MAX(COALESCE((SELECT MAX(last_used_at) FROM client_users c WHERE c.user_id = u.id), ''), COALESCE((SELECT MAX(created_at) FROM sessions s WHERE s.user_id = u.id), '')) AS last_seen,
         (SELECT json_group_array(r.name) FROM role_members m JOIN roles r ON r.id = m.role_id WHERE m.email = u.email) AS roles
       FROM users u WHERE u.guest = 0 AND (? = '' OR u.email LIKE ? ESCAPE '\\' OR lower(u.name) LIKE ? ESCAPE '\\')
       ORDER BY last_seen DESC, u.email LIMIT 200`
    )
      .bind(q, like, like)
      .all<{ id: string; email: string; name: string; created_at: string; google: number; passkeys: number; last_seen: string; roles: string }>();
    return json(
      (results || []).map((u) => ({ ...u, google: !!u.google, last_seen: u.last_seen || null, roles: (JSON.parse(u.roles || '[]') as string[]).sort() }))
    );
  }

  const signOut = path.match(/^\/admin\/users\/([^/]+)\/sign-out$/);
  if (signOut && method === 'POST') {
    const email = normalizeEmail(decode(signOut[1]));
    const user = await env.DB.prepare('SELECT id FROM users WHERE email = ? AND guest = 0').bind(email).first<{ id: string }>();
    if (!user) return json({ error: 'Not found' }, 404);
    const [sessions, tokens] = await env.DB.batch([
      env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
      env.DB.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').bind(nowIso(), user.id),
    ]);
    securityEvent('signed_out_everywhere', { user: user.id, by });
    return json({ ok: true, sessions: sessions.meta.changes ?? 0, refresh_tokens: tokens.meta.changes ?? 0 });
  }

  if (path === '/admin/access-requests' && method === 'GET') {
    const { results } = await env.DB.prepare(
      `SELECT a.client_id, c.name AS client_name, a.email, a.created_at FROM client_access a JOIN clients c ON c.id = a.client_id
       WHERE a.status = 'requested' AND c.disabled_at IS NULL ORDER BY a.created_at DESC LIMIT 500`
    ).all();
    return json(results || []);
  }

  const users = path.match(/^\/admin\/clients\/([^/]+)\/users(?:\/([^/]+))?$/);
  if (users) {
    const clientId = decode(users[1]);
    const client = await env.DB.prepare("SELECT id, restricted FROM clients WHERE id = ? AND kind != 'machine'").bind(clientId).first<{ id: string; restricted: number }>();
    if (!client) return json({ error: 'Not found' }, 404);
    if (!users[2] && method === 'GET') {
      const { results } = await env.DB.prepare('SELECT email, status, role, source, created_at FROM client_access WHERE client_id = ? ORDER BY status, email').bind(clientId).all();
      return json({ restricted: !!client.restricted, users: results || [] });
    }
    if (users[2]) {
      const email = normalizeEmail(decode(users[2]));
      if (!isEmail(email)) return json({ error: 'not an e-mail address' }, 400);
      if (method === 'PUT') {
        await assign(env, clientId, email, 'admin', by);
        return json({ ok: true, email, status: 'assigned' });
      }
      if (method === 'DELETE') {
        const row = await env.DB.prepare('SELECT 1 FROM client_access WHERE client_id = ? AND email = ?').bind(clientId, email).first();
        if (!row) return json({ error: 'Not found' }, 404);
        await unassign(env, clientId, email);
        return json({ ok: true, email, removed: true });
      }
    }
  }
  return null;
}

function auditRows(rows: unknown[]) {
  return (rows as { at: string; name: string; by: string | null; detail: string }[]).map((r) => {
    let detail: unknown = {};
    try {
      detail = JSON.parse(r.detail);
    } catch {
      // kept as nothing
    }
    return { at: r.at, name: r.name, by: r.by, detail };
  });
}
