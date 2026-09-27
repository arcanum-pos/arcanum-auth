import type { Env } from './env';
import { json, nowIso, randomToken, sha256, timingSafeEqual } from './util';

// Clients (one per Arcanum installation), managed by the installer with
// ADMIN_API_KEY:
//   POST   /admin/clients      { name, redirect_uris[], post_logout_redirect_uris[]? }
//          → 201 { client_id, client_secret, ... }  (the secret is shown only here)
//   GET    /admin/clients      → [{ client_id, name, redirect_uris, ... }]
//   DELETE /admin/clients/:id  → disables it (tokens it issued simply expire)

function authorized(request: Request, env: Env): boolean {
  const auth = request.headers.get('Authorization') || '';
  return !!env.ADMIN_API_KEY && auth.startsWith('Bearer ') && timingSafeEqual(auth.slice(7), env.ADMIN_API_KEY);
}

function validUris(value: unknown): string[] | null {
  if (!Array.isArray(value)) return null;
  const uris = value.filter((v): v is string => typeof v === 'string');
  if (uris.length !== value.length) return null;
  for (const uri of uris) {
    try {
      const u = new URL(uri);
      const local = u.hostname === 'localhost' || u.hostname === '127.0.0.1';
      if (u.hash || (u.protocol !== 'https:' && !(local && u.protocol === 'http:'))) return null;
    } catch {
      return null;
    }
  }
  return uris;
}

export async function admin(request: Request, env: Env, path: string): Promise<Response> {
  if (!authorized(request, env)) return json({ error: 'Unauthorized' }, 401);

  if (path === '/admin/clients' && request.method === 'POST') {
    const body = (await request.json().catch(() => null)) as Record<string, unknown> | null;
    const name = typeof body?.name === 'string' ? body.name.trim().slice(0, 100) : '';
    const redirects = validUris(body?.redirect_uris);
    const logouts = validUris(body?.post_logout_redirect_uris ?? []);
    if (!name || !redirects?.length || !logouts) return json({ error: 'name and redirect_uris (https URLs) are required' }, 400);
    const clientId = `arc_${randomToken(12)}`;
    const secret = randomToken(32);
    await env.DB.prepare('INSERT INTO clients (id, secret_hash, name, redirect_uris, post_logout_redirect_uris, created_at) VALUES (?, ?, ?, ?, ?, ?)')
      .bind(clientId, await sha256(secret), name, JSON.stringify(redirects), JSON.stringify(logouts), nowIso())
      .run();
    return json({ client_id: clientId, client_secret: secret, name, redirect_uris: redirects, post_logout_redirect_uris: logouts, issuer: env.ISSUER }, 201);
  }

  if (path === '/admin/clients' && request.method === 'GET') {
    const { results } = await env.DB.prepare('SELECT id, name, redirect_uris, post_logout_redirect_uris, created_at, disabled_at FROM clients ORDER BY created_at').all<{
      id: string;
      name: string;
      redirect_uris: string;
      post_logout_redirect_uris: string;
      created_at: string;
      disabled_at: string | null;
    }>();
    return json(
      (results || []).map((c) => ({
        client_id: c.id,
        name: c.name,
        redirect_uris: JSON.parse(c.redirect_uris),
        post_logout_redirect_uris: JSON.parse(c.post_logout_redirect_uris),
        created_at: c.created_at,
        disabled_at: c.disabled_at,
      }))
    );
  }

  const one = path.match(/^\/admin\/clients\/([^/]+)$/);
  if (one && request.method === 'DELETE') {
    const res = await env.DB.prepare('UPDATE clients SET disabled_at = ? WHERE id = ? AND disabled_at IS NULL').bind(nowIso(), decodeURIComponent(one[1])).run();
    return res.meta.changes ? json({ ok: true }) : json({ error: 'Not found' }, 404);
  }
  return json({ error: 'Not found' }, 404);
}
