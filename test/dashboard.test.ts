// Phase 6 of AUTH_DEDICATED.md: what tools/admin's new dashboard reads and
// does (overview, audit log, users, sign out everywhere, who may sign in,
// access requests, renaming a client).
import { env } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { admin, authorizePath, call, codeFlow, googleSignIn, newClient, pkce, unique, withEnv } from './dedicated';

describe('the dashboard\'s admin routes', () => {
  it('overview: counts and the recent admin actions', async () => {
    const before = (await admin<Record<string, number>>(env, 'GET', '/admin/overview')).body;
    await newClient(env);
    await admin(env, 'POST', '/admin/clients', { kind: 'machine', name: 'worker' });
    const { cookie } = await googleSignIn(env, unique('active'));
    const app = await newClient(env);
    await codeFlow(env, app, cookie);
    const after = (await admin<Record<string, number> & { recent: { name: string; by: string; detail: { path: string } }[] }>(env, 'GET', '/admin/overview')).body;
    expect(after.applications).toBe(before.applications + 2);
    expect(after.machine_clients).toBe(before.machine_clients + 1);
    expect(after.people).toBeGreaterThan(before.people);
    expect(after.active_30_days).toBeGreaterThanOrEqual(1);
    expect(after.recent[0]).toMatchObject({ name: 'admin', by: 'key' });
    expect(after.recent[0].detail.path).toBe('/admin/clients');
  });

  it('audit log: newest first, with a limit', async () => {
    await admin(env, 'POST', '/admin/apis', { id: `audit-${Date.now()}`, name: 'A' });
    const log = (await admin<{ name: string; detail: { path: string; method: string } }[]>(env, 'GET', '/admin/audit?limit=1')).body;
    expect(log).toHaveLength(1);
    expect(log[0].detail).toMatchObject({ method: 'POST', path: '/admin/apis' });
  });

  it('users: searchable, with roles, last sign-in and how they sign in', async () => {
    const email = unique('listed');
    const role = await admin<{ id: string }>(env, 'POST', '/admin/roles', { name: `r-${Date.now()}` });
    await admin(env, 'POST', `/admin/roles/${role.body.id}/members`, { emails: [email] });
    await googleSignIn(env, email);
    const list = (await admin<{ email: string; roles: string[]; google: boolean; last_seen: string | null }[]>(env, 'GET', `/admin/users?q=${encodeURIComponent(email.slice(0, 12))}`)).body;
    const me = list.find((u) => u.email === email)!;
    expect(me.google).toBe(true);
    expect(me.roles).toHaveLength(1);
    expect(me.last_seen).not.toBeNull();
    expect((await admin<unknown[]>(env, 'GET', '/admin/users?q=nobody-has-this-%25')).body).toEqual([]);
  });

  it('sign out everywhere: sessions and refresh tokens end', async () => {
    const email = unique('everywhere');
    const { cookie } = await googleSignIn(env, email);
    const app = await newClient(env);
    const flow = await codeFlow(env, app, cookie);
    const res = await admin<{ sessions: number; refresh_tokens: number }>(env, 'POST', `/admin/users/${encodeURIComponent(email)}/sign-out`);
    expect(res.body).toMatchObject({ sessions: 1, refresh_tokens: 1 });
    expect((await call(env, '/account', { headers: { Cookie: cookie } })).status).toBe(302);
    expect(await env.DB.prepare('SELECT revoked_at FROM refresh_tokens WHERE client_id = ?').bind(app.client_id).first<{ revoked_at: string | null }>()).not.toEqual({ revoked_at: null });
    expect(flow.status).toBe(200);
    expect((await admin(env, 'POST', '/admin/users/nobody%40example.test/sign-out')).status).toBe(404);
  });

  it('who may sign in to a restricted client: add, list, remove - with Google only too', async () => {
    const G = withEnv({ SIGN_IN: 'google' });
    const app = await newClient(G, { restricted: true });
    const email = unique('allowed');
    const { cookie } = await googleSignIn(G, email);
    const { challenge } = await pkce();
    const authorize = () => call(G, authorizePath(app.client_id, challenge), { headers: { Cookie: cookie } });
    expect((await authorize()).status).toBe(403);
    expect((await admin(G, 'PUT', `/admin/clients/${app.client_id}/users/${encodeURIComponent(email)}`)).status).toBe(200);
    expect((await admin<{ restricted: boolean; users: { email: string; status: string }[] }>(G, 'GET', `/admin/clients/${app.client_id}/users`)).body).toMatchObject({ restricted: true, users: [{ email, status: 'assigned' }] });
    expect((await codeFlow(G, app, cookie)).status).toBe(200);
    expect((await admin(G, 'DELETE', `/admin/clients/${app.client_id}/users/${encodeURIComponent(email)}`)).status).toBe(200);
    expect((await authorize()).status).toBe(403);
    expect((await admin(G, 'PUT', `/admin/clients/${app.client_id}/users/not-an-address`)).status).toBe(400);
  });

  it('access requests across clients (the shared instance), approved here', async () => {
    const app = await newClient(env, { restricted: true });
    const email = unique('asker');
    const { cookie } = await googleSignIn(env, email);
    const asked = await call(env, `/access/${app.client_id}/request`, { method: 'POST', headers: { Cookie: cookie, Origin: 'https://login.kaboutersoft.be' } });
    expect(asked.status).toBe(200);
    const requests = (await admin<{ client_id: string; email: string }[]>(env, 'GET', '/admin/access-requests')).body;
    expect(requests).toContainEqual(expect.objectContaining({ client_id: app.client_id, email }));
    await admin(env, 'PUT', `/admin/clients/${app.client_id}/users/${encodeURIComponent(email)}`);
    expect((await admin<{ client_id: string }[]>(env, 'GET', '/admin/access-requests')).body.some((r) => r.client_id === app.client_id)).toBe(false);
  });

  it('a client can be renamed', async () => {
    const app = await newClient(env);
    expect((await admin(env, 'PATCH', `/admin/clients/${app.client_id}`, { name: 'my-scorpio (BFF)' })).status).toBe(200);
    expect((await admin<{ client_id: string; name: string }[]>(env, 'GET', '/admin/clients')).body.find((c) => c.client_id === app.client_id)!.name).toBe('my-scorpio (BFF)');
    expect((await admin(env, 'PATCH', `/admin/clients/${app.client_id}`, { name: ' ' })).status).toBe(400);
  });

  it('every dashboard route: 401 without an admin', async () => {
    for (const [method, path] of [
      ['GET', '/admin/overview'],
      ['GET', '/admin/audit'],
      ['GET', '/admin/users'],
      ['POST', '/admin/users/a%40b.test/sign-out'],
      ['GET', '/admin/access-requests'],
      ['GET', '/admin/clients/x/users'],
      ['PUT', '/admin/clients/x/users/a%40b.test'],
      ['DELETE', '/admin/clients/x/users/a%40b.test'],
      ['POST', '/admin/clients/x/secret'],
      ['DELETE', '/admin/clients/x/secret/previous'],
    ]) {
      expect([path, (await admin(env, method, path, undefined, { Authorization: 'Bearer nope' })).status]).toEqual([path, 401]);
    }
  });
});
