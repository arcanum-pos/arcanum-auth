// The security review's fixes (2026-10): per-address limits on mailed codes,
// in-memory rate limits on what writes a row without anyone signed in, the
// admin API only over the bootstrapper's service binding, HSTS everywhere.
// (The __Host- session cookie and Google's browser-bound state: auth.test.ts.)
import { env, SELF } from 'cloudflare:test';
import { login } from '../src/account';
import { turnstilePasses } from '../src/turnstile';
import { describe, expect, it } from 'vitest';
import { askCode, lastCodeFor, signInWithCode } from './signin';

const ISSUER = 'https://login.kaboutersoft.be';
const FORM = { 'Content-Type': 'application/x-www-form-urlencoded', Origin: ISSUER };
let seq = 0;
const uniqueEmail = (tag: string) => `${tag}-${Date.now()}-${++seq}@example.test`;
const ip = () => `10.${(seq += 1) % 250}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;
const call = (path: string, init: RequestInit = {}) => SELF.fetch(`${ISSUER}${path}`, { redirect: 'manual', ...init });
const post = (path: string, fields: Record<string, string>, headers: Record<string, string> = {}) =>
  call(path, { method: 'POST', headers: { ...FORM, 'CF-Connecting-IP': ip(), ...headers }, body: new URLSearchParams(fields) });

const signUp = (email: string) => signInWithCode(post, email);

describe('mailed codes: limits per address, not only per IP (many IPs, one address)', () => {
  it('at most 5 codes an hour for one address, from however many IPs', async () => {
    const email = uniqueEmail('codes');
    for (let i = 0; i < 5; i++) expect((await post('/login', { email, continue: '/account' })).status).toBe(302);
    expect((await post('/login', { email, continue: '/account' })).status).toBe(429);
  });

  it('10 wrong codes an hour for one address, across all its codes - then even the right one waits', async () => {
    const email = uniqueEmail('guess');
    await signUp(email);
    const codes: { id: string; code: string }[] = [];
    for (let i = 0; i < 3; i++) codes.push({ id: (await askCode(post, email)).id, code: await lastCodeFor(email) });
    const wrong = (c: { id: string; code: string }) => post('/login/code', { id: c.id, code: c.code === '000000' ? '111111' : '000000' });
    for (const [c, times] of [[codes[0], 4], [codes[1], 4], [codes[2], 2]] as const) for (let i = 0; i < times; i++) expect((await wrong(c)).status).toBe(400);
    const right = await post('/login/code', { id: codes[2].id, code: codes[2].code });
    expect(right.status).toBe(400);
    expect(await right.text()).toMatch(/klopt niet of is verlopen/);
  });
});

describe('what writes a row without anyone signed in is rate-limited in memory', () => {
  it('Google sign-ins and passkey challenges: per IP', async () => {
    const from = ip();
    let google = 0;
    for (let i = 0; i < 22; i++) if ((await call('/google', { headers: { 'CF-Connecting-IP': from } })).status === 429) google++;
    expect(google).toBeGreaterThan(0);
    let passkey = 0;
    for (let i = 0; i < 22; i++) {
      const res = await call('/passkey/login/options', { method: 'POST', headers: { 'Content-Type': 'application/json', Origin: ISSUER, 'CF-Connecting-IP': from }, body: '{}' });
      if (res.status === 429) passkey++;
    }
    expect(passkey).toBeGreaterThan(0);
  });

  it('device codes: per client (the kassas come through their bff - shared addresses)', async () => {
    const created = await call('/admin/clients', {
      method: 'POST',
      headers: { Authorization: 'Bearer test-admin-key', 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Flooded', redirect_uris: ['https://flood.test/callback'] }),
    });
    const { client_id } = (await created.json()) as { client_id: string };
    const statuses: number[] = [];
    for (let i = 0; i < 22; i++) {
      statuses.push((await call('/device/code', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'CF-Connecting-IP': ip() }, body: new URLSearchParams({ client_id, scope: 'openid' }) })).status);
    }
    expect(statuses.slice(0, 20).every((s) => s === 200)).toBe(true);
    expect(statuses).toContain(429);
  });
});

describe('the admin API', () => {
  it('only over a service binding - from the internet (CF-Connecting-IP) not even with the right key', async () => {
    const body = JSON.stringify({ name: 'X', redirect_uris: ['https://x.test/callback'] });
    const headers = { Authorization: 'Bearer test-admin-key', 'Content-Type': 'application/json' };
    expect((await call('/admin/clients', { method: 'POST', headers: { ...headers, 'CF-Connecting-IP': '203.0.113.9' }, body })).status).toBe(404);
    expect((await call('/admin/clients', { method: 'POST', headers, body })).status).toBe(201);
  });
});

describe('headers on every answer', () => {
  it('on pages, redirects and JSON answers', async () => {
    for (const res of [await call('/login'), await call('/'), await call('/.well-known/openid-configuration'), await call('/token', { method: 'POST' })]) {
      expect(res.headers.get('Strict-Transport-Security')).toBe('max-age=31536000');
      expect(res.headers.get('X-Content-Type-Options')).toBe('nosniff');
    }
  });

  it('pages switch off what they never use, but not passkeys', async () => {
    const policy = (await call('/login')).headers.get('Permissions-Policy')!;
    expect(policy).toContain('camera=()');
    expect(policy).not.toContain('publickey-credentials');
  });
});

// Turnstile on the sign-in form (2026-10-24): no code is mailed without a
// passed check, for this host and this form; siteverify down lets it through.
describe('Turnstile on the sign-in form', () => {
  const on = { ...env, TURNSTILE_SITE_KEY: 'site-key', TURNSTILE_SECRET: 'turnstile-secret' };

  it('verifies the token server-side: success, this host, this action', async () => {
    expect(await turnstilePasses(on, 'good', '203.0.113.1', 'login')).toBe(true);
    for (const token of ['bad', 'elsewhere', 'other-action', '', undefined]) expect(await turnstilePasses(on, token, null, 'login')).toBe(false);
    // Unreachable: through (the rate limits still apply).
    expect(await turnstilePasses(on, 'down', null, 'login')).toBe(true);
    // Off (no keys): no check.
    expect(await turnstilePasses(env, undefined, null, 'login')).toBe(true);
  });

  it('the form shows the widget (its script allowed for this page only), and a refused check mails nothing', async () => {
    const page = await login(new Request(`${ISSUER}/login`), on);
    const html = await page.text();
    expect(html).toContain('data-sitekey="site-key"');
    expect(page.headers.get('Content-Security-Policy')).toContain('frame-src https://challenges.cloudflare.com');
    expect((await call('/login')).headers.get('Content-Security-Policy')).not.toContain('challenges.cloudflare.com');

    const email = uniqueEmail('bot');
    const ask = (token: string) =>
      login(new Request(`${ISSUER}/login`, { method: 'POST', headers: { ...FORM, 'CF-Connecting-IP': ip() }, body: new URLSearchParams({ email, continue: '/account', 'cf-turnstile-response': token }) }), on);
    const refused = await ask('bad');
    expect(refused.status).toBe(403);
    expect(await refused.text()).toContain('geen robot');
    const mailed = await env.DB.prepare('SELECT COUNT(*) AS n FROM email_codes WHERE email = ?').bind(email).first<{ n: number }>();
    expect(mailed!.n).toBe(0);
    expect((await ask('good')).status).toBe(302);
  });
});

describe('the in-memory limit before any database write on the public forms', () => {
  it('per IP on the sign-in forms; calls without an IP (service bindings) are not limited', async () => {
    const from = ip();
    const statuses: number[] = [];
    for (let i = 0; i < 24; i++) statuses.push((await post('/login/code', { id: 'nope', code: '123456' }, { 'CF-Connecting-IP': from })).status);
    expect(statuses).toContain(429);
    expect(statuses.slice(0, 15).every((s) => s !== 429)).toBe(true);
  });
});

// Hardening phase 4 (2026-10-24): sessions end after 7 idle days, and are
// listed on /account - one ended, or all others plus every app's tokens.
describe('sessions', () => {
  const browser = (ua: string) => ({ 'User-Agent': ua });
  const MAC = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Safari/605.1.15';
  const WIN = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36';

  it('end after 7 days without use, however much of their 14 days is left', async () => {
    const { cookie } = await signInWithCode(post, uniqueEmail('idle'));
    expect((await call('/account', { headers: { Cookie: cookie } })).status).toBe(200);
    await env.DB.prepare('UPDATE sessions SET last_seen_at = ? WHERE id_hash = ?')
      .bind(new Date(Date.now() - 8 * 86400_000).toISOString(), await hash(cookie.split('=')[1]))
      .run();
    expect((await call('/account', { headers: { Cookie: cookie } })).status).toBe(302);
  });

  it('are listed on /account (which browser, how); one ended, or all others and every app', async () => {
    const email = uniqueEmail('sessions');
    const mac = (await signInWithCode((p, f, h) => post(p, f, { ...h, ...browser(MAC) }), email)).cookie;
    const win = (await signInWithCode((p, f, h) => post(p, f, { ...h, ...browser(WIN) }), email)).cookie;
    const third = (await signInWithCode(post, email)).cookie;
    const page = await (await call('/account', { headers: { Cookie: mac } })).text();
    expect(page).toContain('Safari · macOS (deze browser)');
    expect(page).toContain('Chrome · Windows');
    expect(page).toContain('met een code via e-mail');
    // End the Windows one from the Mac.
    const winId = page.match(/Chrome · Windows[\s\S]*?name="id" value="([^"]+)"/)![1];
    expect((await post('/account/sessions', { action: 'end', id: winId }, { Cookie: mac })).headers.get('Location')).toBe('/account');
    expect((await call('/account', { headers: { Cookie: win } })).status).toBe(302);
    // Someone else's id does nothing; another site is refused.
    expect((await post('/account/sessions', { action: 'everywhere' }, { Cookie: mac, Origin: 'https://evil.test' })).status).toBe(403);

    // An app's refresh token, then everywhere: only this browser stays.
    const created = await call('/admin/clients', { method: 'POST', headers: { Authorization: 'Bearer test-admin-key', 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'App', redirect_uris: ['https://app.test/cb'], restricted: false }) });
    const client = (await created.json()) as { client_id: string };
    const userId = (await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first<{ id: string }>())!.id;
    await env.DB.prepare("INSERT INTO refresh_tokens (token_hash, client_id, user_id, scope, auth_time, created_at, expires_at) VALUES (?, ?, ?, 'openid', 0, ?, ?)")
      .bind(`t-${Date.now()}`, client.client_id, userId, new Date().toISOString(), new Date(Date.now() + 86400_000).toISOString())
      .run();
    const everywhere = await post('/account/sessions', { action: 'everywhere' }, { Cookie: mac });
    expect(everywhere.headers.get('Location')).toBe('/account?ended=everywhere');
    expect((await call('/account', { headers: { Cookie: third } })).status).toBe(302);
    expect(await (await call('/account?ended=everywhere', { headers: { Cookie: mac } })).text()).toContain('Je bent overal afgemeld, behalve hier.');
    const live = await env.DB.prepare('SELECT COUNT(*) AS n FROM refresh_tokens WHERE user_id = ? AND revoked_at IS NULL').bind(userId).first<{ n: number }>();
    expect(live!.n).toBe(0);
  });
});

describe('sessions, continued', () => {
  it('signing in again in the same browser ends its previous session (no unused ones piling up)', async () => {
    const email = uniqueEmail('again');
    const first = (await signInWithCode(post, email)).cookie;
    // The same browser (it sends its cookie along) signs in once more.
    const second = (await signInWithCode((p, f, h) => post(p, f, { ...h, Cookie: first }), email)).cookie;
    expect(second).not.toBe(first);
    expect((await call('/account', { headers: { Cookie: first } })).status).toBe(302);
    const userId = (await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first<{ id: string }>())!.id;
    const n = await env.DB.prepare('SELECT COUNT(*) AS n FROM sessions WHERE user_id = ?').bind(userId).first<{ n: number }>();
    expect(n!.n).toBe(1);
  });

  it('a session from before browsers and sign-in methods were kept: "Unknown browser", only what is known', async () => {
    const email = uniqueEmail('old-session');
    const now = (await signInWithCode(post, email)).cookie;
    const userId = (await env.DB.prepare('SELECT id FROM users WHERE email = ?').bind(email).first<{ id: string }>())!.id;
    await env.DB.prepare("INSERT INTO sessions (id_hash, user_id, auth_time, created_at, expires_at) VALUES ('old-one', ?, 0, ?, ?)")
      .bind(userId, new Date().toISOString(), new Date(Date.now() + 86400_000).toISOString())
      .run();
    const html = await (await call('/account', { headers: { Cookie: now, 'Accept-Language': 'en' } })).text();
    const old = html.match(/Unknown browser<\/div><div class="key-meta">([^<]*)</)![1];
    expect(old).toMatch(/^Since [^·]+$/);
    expect(html).not.toContain('>?<');
  });
});

async function hash(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return btoa(String.fromCharCode(...new Uint8Array(digest))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
