// Phase 3 of AUTH_DEDICATED.md: machine clients, grant_type=client_credentials,
// and their secrets (rotation with overlap, revoke now, prefix, never in a
// URL or a log, rate limited).
import { env } from 'cloudflare:test';
import { decodeJwt } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Env } from '../src/env';
import { admin, call, codeFlow, form, googleSignIn, newClient, unique, withEnv } from './dedicated';

const API = 'zaracloud-api';
type Machine = { client_id: string; client_secret: string };

async function setUp() {
  expect((await admin(env, 'POST', '/admin/apis', { id: API, name: 'Zaracloud', permissions: ['read:shows', 'write:shows', 'admin:all'] })).status).toBe(201);
  expect((await admin(env, 'POST', '/admin/apis', { id: 'other-api', name: 'Other', permissions: ['x'] })).status).toBe(201);
}
let once: Promise<void> | null = null;
const ready = () => (once ??= setUp());

async function newMachine(permissions = ['read:shows', 'write:shows']): Promise<Machine> {
  await ready();
  const res = await admin<Machine & { kind: string }>(env, 'POST', '/admin/clients', { kind: 'machine', name: `zara worker ${Date.now()}` });
  expect(res.status).toBe(201);
  expect(res.body.kind).toBe('machine');
  if (permissions.length) expect((await admin(env, 'PUT', `/admin/clients/${res.body.client_id}/api-access/${API}`, { client: permissions })).status).toBe(200);
  return res.body;
}

function credentials(m: { client_id: string; client_secret: string }, extra: Record<string, string> = {}, e: Env = env, headers: Record<string, string> = {}) {
  return form(e, '/token', { grant_type: 'client_credentials', client_id: m.client_id, client_secret: m.client_secret, audience: API, ...extra }, headers);
}

const result = async (res: Response) => ({ status: res.status, body: (await res.json()) as Record<string, unknown> });

afterEach(() => vi.restoreAllMocks());

describe('client credentials', () => {
  it('a machine client gets a token: aud, sub <id>@clients, gty, its permissions in permissions and scope; no id or refresh token', async () => {
    const m = await newMachine();
    expect(m.client_secret).toMatch(/^scs_[A-Za-z0-9_-]{43}$/);
    const { status, body } = await result(await credentials(m));
    expect(status).toBe(200);
    expect(body).toMatchObject({ token_type: 'Bearer', expires_in: 3600, scope: 'read:shows write:shows' });
    expect(body.id_token).toBeUndefined();
    expect(body.refresh_token).toBeUndefined();
    const at = decodeJwt(String(body.access_token));
    expect(at).toMatchObject({ aud: API, sub: `${m.client_id}@clients`, gty: 'client-credentials', permissions: ['read:shows', 'write:shows'], scope: 'read:shows write:shows', iss: 'https://login.kaboutersoft.be' });
    expect(Number(at.exp) - Number(at.iat)).toBe(3600);
    // It names no user: /userinfo refuses it.
    expect((await call(env, '/userinfo', { headers: { Authorization: `Bearer ${body.access_token}` } })).status).toBe(401);
  });

  it('HTTP Basic works as well as the body', async () => {
    const m = await newMachine();
    const basic = `Basic ${btoa(`${encodeURIComponent(m.client_id)}:${encodeURIComponent(m.client_secret)}`)}`;
    const res = await form(env, '/token', { grant_type: 'client_credentials', audience: API }, { Authorization: basic });
    expect(res.status).toBe(200);
  });

  it('refused: no audience, an API it has no access to, a wrong secret', async () => {
    const m = await newMachine();
    expect((await result(await credentials(m, { audience: '' }))).body.error).toBe('invalid_request');
    expect(await result(await credentials(m, { audience: 'other-api' }))).toMatchObject({ status: 403, body: { error: 'access_denied' } });
    expect(await result(await credentials(m, { audience: 'unknown-api' }))).toMatchObject({ status: 403 });
    expect(await result(await credentials({ ...m, client_secret: 'scs_wrong' }))).toMatchObject({ status: 401, body: { error: 'invalid_client' } });
  });

  it('a machine client without any access gets nothing', async () => {
    const m = await newMachine([]);
    expect((await credentials(m)).status).toBe(403);
  });

  it('a user client may not use client credentials, and may not be given client access', async () => {
    await ready();
    const app = await newClient(env);
    expect((await result(await credentials(app))).body.error).toBe('unauthorized_client');
    expect((await admin(env, 'PUT', `/admin/clients/${app.client_id}/api-access/${API}`, { client: ['read:shows'] })).status).toBe(400);
  });

  it('a machine client can not sign anyone in: no authorize, no device code, no other grant, no user access, no addresses, no self-service', async () => {
    const m = await newMachine();
    const { cookie } = await googleSignIn(env, unique('person'));
    const authorize = await call(env, `/authorize?${new URLSearchParams({ response_type: 'code', client_id: m.client_id, redirect_uri: 'https://scorpio-app.test/callback', code_challenge: 'x'.repeat(43), code_challenge_method: 'S256' })}`, { headers: { Cookie: cookie } });
    expect(authorize.status).toBe(400);
    expect((await form(env, '/device/code', { client_id: m.client_id })).status).toBe(401);
    for (const grant of ['authorization_code', 'refresh_token']) {
      expect((await result(await form(env, '/token', { grant_type: grant, client_id: m.client_id, client_secret: m.client_secret, code: 'x', refresh_token: 'x' }))).body.error).toBe('unauthorized_client');
    }
    expect((await admin(env, 'PUT', `/admin/clients/${m.client_id}/api-access/${API}`, { user: ['read:shows'] })).status).toBe(400);
    expect((await admin(env, 'PATCH', `/admin/clients/${m.client_id}`, { redirect_uris: ['https://evil.test/cb'] })).status).toBe(400);
    expect((await call(env, '/clients/self', { headers: { Authorization: `Basic ${btoa(`${m.client_id}:${m.client_secret}`)}` } })).status).toBe(401);
    // The code flow of a user client is untouched.
    const app = await newClient(env);
    expect((await codeFlow(env, app, cookie)).status).toBe(200);
  });

  it('client_secret in the URL query string is refused, even with the right one', async () => {
    const m = await newMachine();
    const res = await call(env, `/token?client_secret=${encodeURIComponent(m.client_secret)}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'client_credentials', client_id: m.client_id, client_secret: m.client_secret, audience: API }),
    });
    expect(await result(res)).toMatchObject({ status: 400, body: { error: 'invalid_request' } });
  });

  it('a disabled machine client gets no new token at once', async () => {
    const m = await newMachine();
    expect((await credentials(m)).status).toBe(200);
    expect((await admin(env, 'DELETE', `/admin/clients/${m.client_id}`)).status).toBe(200);
    expect((await credentials(m)).status).toBe(401);
  });

  it('limits: failures per IP and per client id; a stranger can not lock out the right secret', async () => {
    const m = await newMachine();
    const keys: string[] = [];
    // Every failure bucket full (a stranger flooding this client id from everywhere).
    const flooded = withEnv({ CLIENT_CREDENTIALS_RATE_LIMITER: { limit: async ({ key }: { key: string }) => (keys.push(key), { success: !key.startsWith('cc-fail') }) } });
    const wrong = await credentials({ ...m, client_secret: 'scs_wrong' }, {}, flooded, { 'CF-Connecting-IP': '2001:db8:1:2:3:4:5:6' });
    expect(wrong.status).toBe(429);
    expect(keys).toEqual(['cc-fail-ip:2001:db8:1:2::/64']);
    // The right secret still gets its token, from the same address.
    keys.length = 0;
    expect((await credentials(m, {}, flooded, { 'CF-Connecting-IP': '2001:db8:1:2:3:4:5:6' })).status).toBe(200);
    expect(keys).toEqual([`cc-ok:${m.client_id}`]);
    // Per client id too.
    const perClient = withEnv({ CLIENT_CREDENTIALS_RATE_LIMITER: { limit: async ({ key }: { key: string }) => ({ success: key !== `cc-fail:${m.client_id}` }) } });
    expect((await credentials({ ...m, client_secret: 'scs_wrong' }, {}, perClient)).status).toBe(429);
    expect((await credentials(m, {}, perClient)).status).toBe(200);
  });

  it('the right secret has its own limit (a worker stuck in a loop)', async () => {
    const m = await newMachine();
    const loop = withEnv({ CLIENT_CREDENTIALS_RATE_LIMITER: { limit: async ({ key }: { key: string }) => ({ success: !key.startsWith('cc-ok:') }) } });
    expect((await credentials(m, {}, loop)).status).toBe(429);
  });

  it('failures reach the audit log once per client per window, never for an unknown or disabled client', async () => {
    const m = await newMachine();
    for (let i = 0; i < 4; i++) expect((await credentials({ ...m, client_secret: `scs_wrong-${i}` })).status).toBe(401);
    const count = async (id: string) =>
      (await env.DB.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE name = 'client_credentials_failed' AND detail = ?").bind(JSON.stringify({ client: id })).first<{ n: number }>())!.n;
    expect(await count(m.client_id)).toBe(1);
    await credentials({ client_id: 'arc_nobody', client_secret: 'scs_x' });
    expect(await count('arc_nobody')).toBe(0);
    const gone = await newMachine();
    await admin(env, 'DELETE', `/admin/clients/${gone.client_id}`);
    await credentials({ ...gone, client_secret: 'scs_x' });
    expect(await count(gone.client_id)).toBe(0);
  });

  it('IPv6 callers are bucketed per /64', async () => {
    const { ipBucket } = await import('../src/ratelimit');
    expect(ipBucket('203.0.113.7')).toBe('203.0.113.7');
    expect(ipBucket('2001:db8:1:2:3:4:5:6')).toBe('2001:db8:1:2::/64');
    expect(ipBucket('2001:DB8:0001:0002:ffff::1')).toBe('2001:db8:1:2::/64');
    expect(ipBucket('2001:db8::1')).toBe('2001:db8:0:0::/64');
    expect(ipBucket('::1')).toBe('0:0:0:0::/64');
  });

  it('the machine client shows as used', async () => {
    const m = await newMachine();
    await credentials(m);
    const list = await admin<{ client_id: string; last_used_at: string | null; kind: string }[]>(env, 'GET', '/admin/clients');
    expect(list.body.find((c) => c.client_id === m.client_id)).toMatchObject({ kind: 'machine' });
    expect(list.body.find((c) => c.client_id === m.client_id)!.last_used_at).not.toBeNull();
  });
});

describe('machine secrets', () => {
  it('rotation: the new secret works, the old one for 24 hours, then not', async () => {
    const m = await newMachine();
    const rotated = await admin<{ client_secret: string; previous_secret_expires_at: string }>(env, 'POST', `/admin/clients/${m.client_id}/secret`);
    expect(rotated.status).toBe(200);
    expect(rotated.body.client_secret).toMatch(/^scs_/);
    expect(rotated.body.client_secret).not.toBe(m.client_secret);
    expect(Date.parse(rotated.body.previous_secret_expires_at) - Date.now()).toBeGreaterThan(23.9 * 3600_000);
    expect((await credentials({ ...m, client_secret: rotated.body.client_secret })).status).toBe(200);
    expect((await credentials(m)).status).toBe(200);
    // The overlap is over.
    await env.DB.prepare('UPDATE clients SET previous_secret_expires_at = ? WHERE id = ?').bind(new Date(Date.now() - 1000).toISOString(), m.client_id).run();
    expect((await credentials(m)).status).toBe(401);
    expect((await credentials({ ...m, client_secret: rotated.body.client_secret })).status).toBe(200);
  });

  it('"revoke now" ends the old secret at once', async () => {
    const m = await newMachine();
    const rotated = await admin<{ client_secret: string }>(env, 'POST', `/admin/clients/${m.client_id}/secret`);
    expect((await credentials(m)).status).toBe(200);
    expect((await admin(env, 'DELETE', `/admin/clients/${m.client_id}/secret/previous`)).body).toMatchObject({ revoked: true });
    expect((await credentials(m)).status).toBe(401);
    expect((await credentials({ ...m, client_secret: rotated.body.client_secret })).status).toBe(200);
  });

  it('a user client can be rotated the same way (its old secret overlaps too)', async () => {
    await ready();
    const app = await newClient(env);
    const rotated = await admin<{ client_secret: string }>(env, 'POST', `/admin/clients/${app.client_id}/secret`);
    const self = (secret: string) => call(env, '/clients/self', { headers: { Authorization: `Basic ${btoa(`${app.client_id}:${secret}`)}` } });
    expect((await self(app.client_secret)).status).toBe(200);
    expect((await self(rotated.body.client_secret)).status).toBe(200);
  });

  it('the secret never appears in a log line or the audit log; rotations, revocations and failures are audited', async () => {
    const lines: string[] = [];
    for (const level of ['log', 'warn', 'error', 'info'] as const) vi.spyOn(console, level).mockImplementation((...args: unknown[]) => void lines.push(args.map(String).join(' ')));
    const m = await newMachine();
    await credentials(m);
    const rotated = await admin<{ client_secret: string }>(env, 'POST', `/admin/clients/${m.client_id}/secret`);
    await credentials({ ...m, client_secret: rotated.body.client_secret });
    await credentials({ ...m, client_secret: 'scs_wrong-secret-value' });
    await admin(env, 'DELETE', `/admin/clients/${m.client_id}/secret/previous`);
    const { results } = await env.DB.prepare('SELECT name, detail FROM audit_log').all<{ name: string; detail: string }>();
    const everything = [...lines, ...results.map((r) => `${r.name} ${r.detail}`)].join('\n');
    for (const secret of [m.client_secret, rotated.body.client_secret, 'scs_wrong-secret-value']) expect(everything).not.toContain(secret);
    const mine = results.filter((r) => r.detail.includes(m.client_id)).map((r) => r.name);
    expect(mine).toEqual(expect.arrayContaining(['client_secret_rotated', 'client_secret_revoked', 'client_credentials_failed']));
    expect(lines.some((l) => l.includes('"name":"client_credentials_failed"'))).toBe(true);
  });

  it('the list shows the secret\'s age and the overlap, never a hash', async () => {
    const m = await newMachine();
    await admin(env, 'POST', `/admin/clients/${m.client_id}/secret`);
    const c = (await admin<Record<string, unknown>[]>(env, 'GET', '/admin/clients')).body.find((x) => x.client_id === m.client_id)!;
    expect(typeof c.secret_created_at).toBe('string');
    expect(typeof c.previous_secret_expires_at).toBe('string');
    expect(JSON.stringify(c)).not.toMatch(/hash/);
  });
});
