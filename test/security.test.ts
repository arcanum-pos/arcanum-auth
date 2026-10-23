// The security review's fixes (2026-10): per-address limits on mailed codes,
// in-memory rate limits on what writes a row without anyone signed in, the
// admin API only over the bootstrapper's service binding, HSTS everywhere.
// (The __Host- session cookie and Google's browser-bound state: auth.test.ts.)
import { SELF } from 'cloudflare:test';
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
