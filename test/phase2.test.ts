import { env, SELF } from 'cloudflare:test';
import { decodeJwt } from 'jose';
import { describe, expect, it } from 'vitest';
import { cleanup } from '../src/cleanup';
import { sendMail } from '../src/mail';

// Guests + one-time sign-in links (the bootstrapper's "Direct proberen"),
// client self-service (an installation managing its own client), client
// metadata, the clean-up cron, and mail through either provider.

const ISSUER = 'https://login.kaboutersoft.be';
const APP = 'https://demo-app.test';
const REDIRECT = `${APP}/callback`;
const ADMIN = { Authorization: 'Bearer test-admin-key', 'Content-Type': 'application/json' };

const call = (path: string, init: RequestInit = {}) => SELF.fetch(`${ISSUER}${path}`, { redirect: 'manual', ...init });
const adminPost = (path: string, body: unknown) => call(path, { method: 'POST', headers: ADMIN, body: JSON.stringify(body) });
const basic = (id: string, secret: string) => ({ Authorization: `Basic ${btoa(`${id}:${secret}`)}` });
const cookieOf = (res: Response) => (res.headers.get('Set-Cookie') || '').split(';')[0];

async function newClient(extra: Record<string, unknown> = {}) {
  const res = await adminPost('/admin/clients', { name: 'Demo instance', redirect_uris: [REDIRECT], post_logout_redirect_uris: [APP], ...extra });
  expect(res.status).toBe(201);
  return (await res.json()) as { client_id: string; client_secret: string; instance_url: string | null; owner_email: string | null };
}

async function newGuest(hours?: number) {
  const res = await adminPost('/admin/guests', { name: 'Proefpersoon', ...(hours ? { lifetime_hours: hours } : {}) });
  expect(res.status).toBe(201);
  return (await res.json()) as { sub: string; email: string; name: string; expires_at: string };
}

async function pkce() {
  const verifier = 'v'.repeat(20) + crypto.randomUUID().replace(/-/g, '');
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier));
  return { verifier, challenge: btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') };
}

const authorizeUrl = (clientId: string, challenge: string, redirectUri = REDIRECT) =>
  `/authorize?${new URLSearchParams({ response_type: 'code', client_id: clientId, redirect_uri: redirectUri, scope: 'openid profile email offline_access', state: 's', code_challenge: challenge, code_challenge_method: 'S256' })}`;

// A guest signed in through a one-time link → its session cookie.
async function guestSession(continueTo = `${APP}/console`) {
  const guest = await newGuest();
  const link = await adminPost('/admin/login-links', { sub: guest.sub, continue_to: continueTo });
  expect(link.status).toBe(201);
  const { url } = (await link.json()) as { url: string };
  const res = await SELF.fetch(url, { redirect: 'manual' });
  expect(res.status).toBe(302);
  expect(res.headers.get('Location')).toBe(continueTo);
  return { guest, cookie: cookieOf(res), url };
}

describe('guests and one-time sign-in links', () => {
  it('need the admin key', async () => {
    expect((await call('/admin/guests', { method: 'POST', body: '{}' })).status).toBe(401);
    expect((await call('/admin/login-links', { method: 'POST', body: '{}' })).status).toBe(401);
  });

  it('a guest signs in once through the link and gets ordinary tokens (unverified guest e-mail)', async () => {
    const client = await newClient();
    const { guest, cookie, url } = await guestSession();
    expect(guest.email).toMatch(/^guest-.+@guest\.invalid$/);

    // Single use.
    expect((await SELF.fetch(url, { redirect: 'manual' })).status).toBe(400);

    const { verifier, challenge } = await pkce();
    const auth = await call(authorizeUrl(client.client_id, challenge), { headers: { Cookie: cookie } });
    const code = new URL(auth.headers.get('Location')!).searchParams.get('code')!;
    const tokens = await call('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: client.client_id, client_secret: client.client_secret, code_verifier: verifier }),
    });
    expect(tokens.status).toBe(200);
    const body = (await tokens.json()) as Record<string, string>;
    expect(decodeJwt(body.id_token)).toMatchObject({ sub: guest.sub, email: guest.email, email_verified: false, name: 'Proefpersoon' });
  });

  it('only for a guest, and only to an origin a client registered', async () => {
    await newClient();
    const guest = await newGuest();
    expect((await adminPost('/admin/login-links', { sub: guest.sub, continue_to: 'https://evil.test/' })).status).toBe(400);
    expect((await adminPost('/admin/login-links', { sub: guest.sub, continue_to: 'javascript:alert(1)' })).status).toBe(400);
    // A real account can't be signed in this way.
    const real = await env.DB.prepare("INSERT INTO users (id, email, email_verified, name, created_at, updated_at) VALUES (?, ?, 1, 'R', ?, ?) RETURNING id")
      .bind(crypto.randomUUID(), `real-${crypto.randomUUID()}@example.test`, new Date().toISOString(), new Date().toISOString())
      .first<{ id: string }>();
    expect((await adminPost('/admin/login-links', { sub: real!.id, continue_to: `${APP}/console` })).status).toBe(400);
  });

  it('an expired link does nothing', async () => {
    await newClient();
    const guest = await newGuest();
    const { url } = (await (await adminPost('/admin/login-links', { sub: guest.sub, continue_to: `${APP}/x` })).json()) as { url: string };
    await env.DB.prepare('UPDATE login_links SET expires_at = ?').bind(new Date(Date.now() - 1000).toISOString()).run();
    expect((await SELF.fetch(url, { redirect: 'manual' })).status).toBe(400);
  });

  it('an expired guest is refused everywhere at once, and the cron removes it', async () => {
    const client = await newClient();
    const { guest, cookie } = await guestSession();
    // Tokens while alive.
    const { verifier, challenge } = await pkce();
    const code = new URL((await call(authorizeUrl(client.client_id, challenge), { headers: { Cookie: cookie } })).headers.get('Location')!).searchParams.get('code')!;
    const tokens = (await (
      await call('/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: REDIRECT, client_id: client.client_id, client_secret: client.client_secret, code_verifier: verifier }),
      })
    ).json()) as Record<string, string>;

    await env.DB.prepare('UPDATE users SET expires_at = ? WHERE id = ?').bind(new Date(Date.now() - 1000).toISOString(), guest.sub).run();

    // Session: back to sign-in. Refresh: refused. Userinfo: refused.
    const again = await pkce();
    const auth = await call(authorizeUrl(client.client_id, again.challenge), { headers: { Cookie: cookie } });
    expect(new URL(auth.headers.get('Location')!, ISSUER).pathname).toBe('/login');
    const refresh = await call('/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: client.client_id, client_secret: client.client_secret }),
    });
    expect(((await refresh.json()) as Record<string, string>).error).toBe('invalid_grant');
    expect((await call('/userinfo', { headers: { Authorization: `Bearer ${tokens.access_token}` } })).status).toBe(401);

    const report = await cleanup(env);
    expect(report.guests).toBeGreaterThanOrEqual(1);
    expect(await env.DB.prepare('SELECT 1 FROM users WHERE id = ?').bind(guest.sub).first()).toBeNull();
    expect(await env.DB.prepare('SELECT 1 FROM sessions WHERE user_id = ?').bind(guest.sub).first()).toBeNull();
    expect(await env.DB.prepare('SELECT 1 FROM refresh_tokens WHERE user_id = ?').bind(guest.sub).first()).toBeNull();
  });

  it('a live guest and real users are left alone by the cron', async () => {
    const guest = await newGuest(5);
    await cleanup(env);
    expect(await env.DB.prepare('SELECT 1 FROM users WHERE id = ?').bind(guest.sub).first()).not.toBeNull();
  });

  it('lifetime is bounded', async () => {
    expect((await adminPost('/admin/guests', { lifetime_hours: 48 })).status).toBe(400);
    const g = await newGuest(5);
    const hours = (Date.parse(g.expires_at) - Date.now()) / 3600_000;
    expect(hours).toBeGreaterThan(4.9);
    expect(hours).toBeLessThanOrEqual(5);
  });
});

describe('client self-service', () => {
  it('an installation reads and changes its own URIs with its own credentials', async () => {
    const client = await newClient({ instance_url: APP, owner_email: 'Owner@Example.test', owner_sub: 'sub-1' });
    expect(client).toMatchObject({ instance_url: APP, owner_email: 'owner@example.test' });
    expect((await call('/clients/self')).status).toBe(401);
    expect((await call('/clients/self', { headers: basic(client.client_id, 'wrong') })).status).toBe(401);
    const self = (await (await call('/clients/self', { headers: basic(client.client_id, client.client_secret) })).json()) as Record<string, unknown>;
    expect(self).toMatchObject({ client_id: client.client_id, redirect_uris: [REDIRECT], instance_url: APP });
    expect(self).not.toHaveProperty('client_secret');

    // After a custom domain: both addresses.
    const custom = 'https://kassa.mijnclub.test/callback';
    const patched = await call('/clients/self', {
      method: 'PATCH',
      headers: { ...basic(client.client_id, client.client_secret), 'Content-Type': 'application/json' },
      body: JSON.stringify({ redirect_uris: [REDIRECT, custom], post_logout_redirect_uris: [APP, 'https://kassa.mijnclub.test'] }),
    });
    expect(patched.status).toBe(200);
    // The new callback works at /authorize (it redirects there, not an error page).
    const { challenge } = await pkce();
    const cookie = (await guestSession()).cookie;
    const auth = await call(authorizeUrl(client.client_id, challenge, custom), { headers: { Cookie: cookie } });
    expect(new URL(auth.headers.get('Location')!).origin).toBe('https://kassa.mijnclub.test');
  });

  it('refuses non-https and empty redirect lists', async () => {
    const client = await newClient();
    const patch = (body: unknown) =>
      call('/clients/self', { method: 'PATCH', headers: { ...basic(client.client_id, client.client_secret), 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    expect((await patch({ redirect_uris: ['http://evil.test/cb'] })).status).toBe(400);
    expect((await patch({ redirect_uris: [] })).status).toBe(400);
  });

  it('rotates its secret: the old one stops working', async () => {
    const client = await newClient();
    const res = await call('/clients/self/secret', { method: 'POST', headers: basic(client.client_id, client.client_secret) });
    const { client_secret: fresh } = (await res.json()) as { client_secret: string };
    expect(fresh).not.toBe(client.client_secret);
    expect((await call('/clients/self', { headers: basic(client.client_id, client.client_secret) })).status).toBe(401);
    expect((await call('/clients/self', { headers: basic(client.client_id, fresh) })).status).toBe(200);
  });
});

describe('admin: client metadata', () => {
  it('lists which installation a client belongs to', async () => {
    const client = await newClient({ instance_url: 'https://arcanum-bff.club.workers.dev', owner_email: 'jan@club.test', owner_sub: 'abc' });
    const list = (await (await call('/admin/clients', { headers: ADMIN })).json()) as Record<string, unknown>[];
    expect(list.find((c) => c.client_id === client.client_id)).toMatchObject({ instance_url: 'https://arcanum-bff.club.workers.dev', owner_email: 'jan@club.test', owner_sub: 'abc' });
  });
});

describe('mail providers', () => {
  it('MAIL_CONFIG picks the provider (here the Gmail API), MAIL_SMTP stays the fallback', async () => {
    const gmail = { clientEmail: 'svc@proj.iam.gserviceaccount.com', privateKey: 'k', impersonatedUser: 'noreply@kaboutersoft.be' };
    await sendMail({ ...env, MAIL_CONFIG: JSON.stringify({ provider: 'gmail_api', credentials: gmail }) }, 'to@example.test', 'Onderwerp', 'Tekst');
    await sendMail(env, 'to2@example.test', 'Onderwerp', 'Tekst');
    const calls = (await (await env.MAILER!.fetch('https://mailer/__calls')).json()) as { body: Record<string, unknown> }[];
    expect(calls.find((c) => c.body.to === 'to@example.test')!.body).toMatchObject({ provider: 'gmail_api', credentials: gmail });
    expect(calls.find((c) => c.body.to === 'to2@example.test')!.body).toMatchObject({ provider: 'smtp', credentials: { host: 'smtp.test' } });
  });
});
