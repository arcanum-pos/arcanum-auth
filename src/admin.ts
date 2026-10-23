import type { Env } from './env';
import { currentMail, mailProvider, sendMail, sendTestMail } from './mail';
import { deleteSetting, mailSummary, readSetting, SECRET_FIELDS, writeSetting, type MailSetting } from './settings';
import { clientById, createGuest, userById } from './store';
import { texts } from './pages';
import { inSeconds, json, newEmailCode, nowIso, randomToken, sha256, timingSafeEqual } from './util';

const LOGIN_LINK_SECONDS = 60;

// What the platform's mailer can send with (cloudflare: its send_email binding).
const PLATFORM_MAIL_SERVICES = ['smtp', 'gmail_api', 'brevo', 'resend', 'cloudflare'];

// Test mails (/admin/mail/test): at most 10 an hour — counted in this
// isolate's memory, best effort (only the bootstrapper's admins get here).
const testMailsSent: number[] = [];
function overTestLimit(now = Date.now()): boolean {
  while (testMailsSent.length && now - testMailsSent[0] >= 3600_000) testMailsSent.shift();
  if (testMailsSent.length >= 10) return true;
  testMailsSent.push(now);
  return false;
}

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

// Clients (one per application, e.g. per installation), managed by the bootstrapper with
// ADMIN_API_KEY:
//   POST   /admin/clients      { name, redirect_uris[], post_logout_redirect_uris[]?, owner_email?, restricted? (default true) }
//          → 201 { client_id, client_secret, ... }  (the secret is shown only here)
//          The owner becomes the client's first admin (access.ts).
//   GET    /admin/clients      → [{ client_id, name, redirect_uris, restricted, ... }]
//   PATCH  /admin/clients/:id  { restricted?, redirect_uris?, post_logout_redirect_uris? } → open or restrict
//          it; each URI list given replaces the old one (the bootstrapper's Applicaties)
//   DELETE /admin/clients/:id[?by=<email>]  → disables it (tokens it issued simply expire);
//          its owner gets a mail when someone else (by) did it
//   DELETE /admin/clients/:id?hard=1        → a disabled client gone for good: its
//          access list and protocol state too (409 while it isn't disabled)
//   GET lists each with last_used_at and active_users (signed in through it in the last 30 days)
// Demo visitors without an account (the bootstrapper's "Direct proberen"):
//   POST   /admin/guests       { name?, lifetime_hours? (default 5, max 24) }
//          → 201 { sub, email, name, expires_at }
//   POST   /admin/login-links  { sub, continue_to } — a guest only; continue_to
//          must be on an origin some client registered a redirect URI for
//          → 201 { url, expires_in }  (single use, 60 s)
// The platform's mail account (the bootstrapper's /admin/e-mail; MAIL.md):
//   GET    /admin/mail       → { canStore, active, stored, secret } — never a secret's value
//   PUT    /admin/mail       { provider, settings{}, keep[]? } — keep: secret
//          fields to take over from the stored account (same service)
//   DELETE /admin/mail       → back to MAIL_CONFIG / MAIL_SMTP
//   POST   /admin/mail/test  { to } → the mailer's answer (a sign-in code mail; 10 an hour)

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
    const restricted = body?.restricted !== false;
    const clientId = `arc_${randomToken(12)}`;
    const secret = randomToken(32);
    const now = nowIso();
    await env.DB.batch([
      env.DB.prepare(
        'INSERT INTO clients (id, secret_hash, name, redirect_uris, post_logout_redirect_uris, created_at, instance_url, owner_email, owner_sub, restricted) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
      ).bind(clientId, await sha256(secret), name, JSON.stringify(redirects), JSON.stringify(logouts), now, instanceUrl, ownerEmail, ownerSub, restricted ? 1 : 0),
      ...(ownerEmail
        ? [
            env.DB.prepare("INSERT INTO client_access (client_id, email, status, role, source, created_at, updated_at) VALUES (?, ?, 'assigned', 'admin', 'owner', ?, ?)").bind(
              clientId,
              ownerEmail,
              now,
              now
            ),
          ]
        : []),
    ]);
    return json(
      { client_id: clientId, client_secret: secret, name, redirect_uris: redirects, post_logout_redirect_uris: logouts, instance_url: instanceUrl, owner_email: ownerEmail, owner_sub: ownerSub, restricted, issuer: env.ISSUER },
      201
    );
  }

  if (path === '/admin/clients' && request.method === 'GET') {
    const { results } = await env.DB.prepare(
      `SELECT id, name, redirect_uris, post_logout_redirect_uris, instance_url, owner_email, owner_sub, restricted, created_at, disabled_at, last_used_at,
         (SELECT COUNT(DISTINCT user_id) FROM refresh_tokens WHERE refresh_tokens.client_id = clients.id AND refresh_tokens.created_at > ?) AS active_users
       FROM clients ORDER BY created_at`
    )
      .bind(new Date(Date.now() - 30 * 86400_000).toISOString())
      .all<{
      id: string;
      name: string;
      redirect_uris: string;
      post_logout_redirect_uris: string;
      instance_url: string | null;
      owner_email: string | null;
      owner_sub: string | null;
      restricted: number;
      created_at: string;
      disabled_at: string | null;
      last_used_at: string | null;
      active_users: number;
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
        restricted: !!c.restricted,
        last_used_at: c.last_used_at,
        active_users: c.active_users,
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

  if (path === '/admin/mail' && request.method === 'GET') {
    const [stored, active] = await Promise.all([readSetting<MailSetting>(env, 'mail'), currentMail(env)]);
    const secret = mailProvider(env);
    const { type, ...fromSecret } = secret ?? { type: '' };
    return json({
      canStore: !!env.SETTINGS_KEY,
      active: active?.source ?? null,
      stored: stored ? { ...mailSummary(stored.value), updatedAt: stored.updatedAt } : null,
      secret: secret ? mailSummary({ provider: type, ...fromSecret }) : null,
    });
  }

  if (path === '/admin/mail' && request.method === 'PUT') {
    if (!env.SETTINGS_KEY) return json({ error: 'SETTINGS_KEY is not set' }, 409);
    const body = (await request.json().catch(() => null)) as { provider?: unknown; settings?: unknown; keep?: unknown } | null;
    const provider = typeof body?.provider === 'string' ? body.provider : '';
    if (!PLATFORM_MAIL_SERVICES.includes(provider)) return json({ error: `provider must be one of ${PLATFORM_MAIL_SERVICES.join(', ')}` }, 400);
    const settings = body?.settings && typeof body.settings === 'object' ? (body.settings as Record<string, unknown>) : {};
    const config: MailSetting = { provider };
    for (const [k, v] of Object.entries(settings)) {
      if (k === 'provider' || k === 'type') continue;
      if (typeof v === 'number' && Number.isFinite(v)) config[k] = v;
      else if (typeof v === 'string' && v.trim()) config[k] = k === 'privateKey' ? v : v.trim();
    }
    const previous = (await readSetting<MailSetting>(env, 'mail'))?.value;
    const keep = Array.isArray(body?.keep) ? body.keep.filter((k): k is string => typeof k === 'string' && SECRET_FIELDS.includes(k)) : [];
    for (const k of keep) if (config[k] === undefined && previous?.provider === provider && previous[k]) config[k] = previous[k];
    await writeSetting(env, 'mail', config);
    return json({ ok: true, ...mailSummary(config) });
  }

  if (path === '/admin/mail' && request.method === 'DELETE') {
    await deleteSetting(env, 'mail');
    return json({ ok: true });
  }

  if (path === '/admin/mail/test' && request.method === 'POST') {
    const body = (await request.json().catch(() => ({}))) as { to?: unknown };
    const to = typeof body.to === 'string' ? body.to.trim() : '';
    if (!/^[^@\s]+@[^@\s]+$/.test(to)) return json({ error: 'to must be an e-mail address' }, 400);
    if (overTestLimit()) return json({ ok: false, code: 'too_many_test_mails', error: 'At most 10 test mails an hour' }, 429);
    // A real sign-in code mail (with a code that opens nothing), in the
    // asker's language — what people get, so a checker scores what matters —
    // marked as a test, so nobody takes it for a real one.
    const t = texts(request);
    const result = await sendTestMail(env, to, `${t.mailTestSubject} - ${t.mailCodeSubject}`, `${t.mailTestNote(new URL(env.ISSUER).host)}\n\n${t.mailCode(newEmailCode(), `${env.ISSUER}/login`)}`);
    return json(result.body, result.status === 200 ? 200 : result.status);
  }

  const one = path.match(/^\/admin\/clients\/([^/]+)$/);
  if (one && request.method === 'PATCH') {
    const body = (await request.json().catch(() => null)) as { restricted?: unknown; redirect_uris?: unknown; post_logout_redirect_uris?: unknown } | null;
    const sets: string[] = [];
    const params: unknown[] = [];
    if (body?.restricted !== undefined) {
      if (typeof body.restricted !== 'boolean') return json({ error: 'restricted must be true or false' }, 400);
      sets.push('restricted = ?');
      params.push(body.restricted ? 1 : 0);
    }
    // Each list given replaces the old one (exact URIs, https — as at creation).
    for (const [field, min] of [['redirect_uris', 1], ['post_logout_redirect_uris', 0]] as const) {
      if (body?.[field] === undefined) continue;
      const uris = validUris(body[field]);
      if (!uris || uris.length < min || uris.length > 10) return json({ error: `${field}: ${min}-10 https URLs` }, 400);
      sets.push(`${field} = ?`);
      params.push(JSON.stringify(uris));
    }
    if (!sets.length) return json({ error: 'restricted, redirect_uris or post_logout_redirect_uris is required' }, 400);
    const res = await env.DB.prepare(`UPDATE clients SET ${sets.join(', ')} WHERE id = ? AND disabled_at IS NULL`).bind(...params, decodeURIComponent(one[1])).run();
    if (!res.meta.changes) return json({ error: 'Not found' }, 404);
    const client = await clientById(env, decodeURIComponent(one[1]));
    return json({ ok: true, restricted: !!client!.restricted, redirect_uris: client!.redirect_uris, post_logout_redirect_uris: client!.post_logout_redirect_uris });
  }
  if (one && request.method === 'DELETE') {
    const id = decodeURIComponent(one[1]);
    const query = new URL(request.url).searchParams;
    const row = await env.DB.prepare('SELECT name, owner_email, disabled_at FROM clients WHERE id = ?').bind(id).first<{ name: string; owner_email: string | null; disabled_at: string | null }>();
    if (!row) return json({ error: 'Not found' }, 404);
    if (query.get('hard') === '1') {
      // Two steps: only a client that's disabled already can go for good.
      if (!row.disabled_at) return json({ error: 'Disable the client first' }, 409);
      await env.DB.batch([
        env.DB.prepare('DELETE FROM refresh_tokens WHERE client_id = ?').bind(id),
        env.DB.prepare('DELETE FROM auth_codes WHERE client_id = ?').bind(id),
        env.DB.prepare('DELETE FROM device_codes WHERE client_id = ?').bind(id),
        env.DB.prepare('DELETE FROM client_access WHERE client_id = ?').bind(id),
        env.DB.prepare('DELETE FROM clients WHERE id = ?').bind(id),
      ]);
      return json({ ok: true, deleted: true });
    }
    const res = await env.DB.prepare('UPDATE clients SET disabled_at = ? WHERE id = ? AND disabled_at IS NULL').bind(nowIso(), id).run();
    if (!res.meta.changes) return json({ error: 'Not found' }, 404);
    // Someone else's: its owner hears of it — a client never disappears silently.
    const by = (query.get('by') || '').trim().toLowerCase();
    if (row.owner_email && by && row.owner_email.toLowerCase() !== by) {
      const t = texts(request);
      await sendMail(env, row.owner_email, t.mailClientDisabledSubject(row.name), t.mailClientDisabled(row.name, by)).catch((err) => console.error('client disabled mail failed', err));
    }
    return json({ ok: true });
  }
  return json({ error: 'Not found' }, 404);
}
