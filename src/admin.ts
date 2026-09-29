import type { Env } from './env';
import { createGuest, userById } from './store';
import { inSeconds, json, nowIso, randomToken, sha256, timingSafeEqual } from './util';

const LOGIN_LINK_SECONDS = 60;

// An absolute https URL whose origin some (enabled) client registered a
// redirect URI on — so a login link can never become an open redirect.
export async function isRegisteredOrigin(env: Env, target: string): Promise<boolean> {
  let origin: string;
  try {
    const u = new URL(target);
    if (u.protocol !== 'https:' && !(u.protocol === 'http:' && (u.hostname === 'localhost' || u.hostname === '127.0.0.1'))) return false;
    origin = u.origin;
  } catch {
    return false;
  }
  const { results } = await env.DB.prepare('SELECT redirect_uris FROM clients WHERE disabled_at IS NULL').all<{ redirect_uris: string }>();
  return (results || []).some((c) => (JSON.parse(c.redirect_uris) as string[]).some((uri) => new URL(uri).origin === origin));
}

// Clients (one per Arcanum installation), managed by the installer with
// ADMIN_API_KEY:
//   POST   /admin/clients      { name, redirect_uris[], post_logout_redirect_uris[]? }
//          → 201 { client_id, client_secret, ... }  (the secret is shown only here)
//   GET    /admin/clients      → [{ client_id, name, redirect_uris, ... }]
//   DELETE /admin/clients/:id  → disables it (tokens it issued simply expire)
// Demo visitors without an account (the bootstrapper's "Direct proberen"):
//   POST   /admin/guests       { name?, lifetime_hours? (default 5, max 24) }
//          → 201 { sub, email, name, expires_at }
//   POST   /admin/login-links  { sub, continue_to } — a guest only; continue_to
//          must be on an origin some client registered a redirect URI for
//          → 201 { url, expires_in }  (single use, 60 s)

function authorized(request: Request, env: Env): boolean {
  const auth = request.headers.get('Authorization') || '';
  return !!env.ADMIN_API_KEY && auth.startsWith('Bearer ') && timingSafeEqual(auth.slice(7), env.ADMIN_API_KEY);
}

export function validUris(value: unknown): string[] | null {
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
    // Which installation it's for and who set it up — for support.
    const text = (v: unknown, max: number) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, max) : null);
    const instanceUrl = text(body?.instance_url, 300);
    const ownerEmail = text(body?.owner_email, 254)?.toLowerCase() ?? null;
    const ownerSub = text(body?.owner_sub, 200);
    const clientId = `arc_${randomToken(12)}`;
    const secret = randomToken(32);
    await env.DB.prepare(
      'INSERT INTO clients (id, secret_hash, name, redirect_uris, post_logout_redirect_uris, created_at, instance_url, owner_email, owner_sub) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    )
      .bind(clientId, await sha256(secret), name, JSON.stringify(redirects), JSON.stringify(logouts), nowIso(), instanceUrl, ownerEmail, ownerSub)
      .run();
    return json(
      { client_id: clientId, client_secret: secret, name, redirect_uris: redirects, post_logout_redirect_uris: logouts, instance_url: instanceUrl, owner_email: ownerEmail, owner_sub: ownerSub, issuer: env.ISSUER },
      201
    );
  }

  if (path === '/admin/clients' && request.method === 'GET') {
    const { results } = await env.DB.prepare(
      'SELECT id, name, redirect_uris, post_logout_redirect_uris, instance_url, owner_email, owner_sub, created_at, disabled_at FROM clients ORDER BY created_at'
    ).all<{
      id: string;
      name: string;
      redirect_uris: string;
      post_logout_redirect_uris: string;
      instance_url: string | null;
      owner_email: string | null;
      owner_sub: string | null;
      created_at: string;
      disabled_at: string | null;
    }>();
    return json(
      (results || []).map((c) => ({
        client_id: c.id,
        name: c.name,
        redirect_uris: JSON.parse(c.redirect_uris),
        post_logout_redirect_uris: JSON.parse(c.post_logout_redirect_uris),
        instance_url: c.instance_url,
        owner_email: c.owner_email,
        owner_sub: c.owner_sub,
        created_at: c.created_at,
        disabled_at: c.disabled_at,
      }))
    );
  }

  if (path === '/admin/guests' && request.method === 'POST') {
    const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
    const hours = Number(body.lifetime_hours ?? 5);
    if (!Number.isFinite(hours) || hours <= 0 || hours > 24) return json({ error: 'lifetime_hours must be > 0 and at most 24' }, 400);
    const name = typeof body.name === 'string' && body.name.trim() ? body.name.trim().slice(0, 100) : 'Gast';
    const guest = await createGuest(env, name, hours);
    return json({ sub: guest.id, email: guest.email, name: guest.name, expires_at: guest.expires_at, issuer: env.ISSUER }, 201);
  }

  if (path === '/admin/login-links' && request.method === 'POST') {
    const body = (await request.json().catch(() => ({}))) as Record<string, unknown>;
    const user = typeof body.sub === 'string' ? await userById(env, body.sub) : null;
    // Guests only: a real account signs in itself.
    if (!user || !user.guest) return json({ error: 'sub must be a live guest' }, 400);
    const target = typeof body.continue_to === 'string' ? body.continue_to : '';
    if (!(await isRegisteredOrigin(env, target))) return json({ error: 'continue_to must be an https URL on an origin a client registered' }, 400);
    const token = randomToken(32);
    await env.DB.prepare('INSERT INTO login_links (token_hash, user_id, continue_to, expires_at) VALUES (?, ?, ?, ?)')
      .bind(await sha256(token), user.id, target, inSeconds(LOGIN_LINK_SECONDS))
      .run();
    return json({ url: `${env.ISSUER}/login/once?token=${encodeURIComponent(token)}`, expires_in: LOGIN_LINK_SECONDS }, 201);
  }

  const one = path.match(/^\/admin\/clients\/([^/]+)$/);
  if (one && request.method === 'DELETE') {
    const res = await env.DB.prepare('UPDATE clients SET disabled_at = ? WHERE id = ? AND disabled_at IS NULL').bind(nowIso(), decodeURIComponent(one[1])).run();
    return res.meta.changes ? json({ ok: true }) : json({ error: 'Not found' }, 404);
  }
  return json({ error: 'Not found' }, 404);
}
