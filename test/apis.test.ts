// Phase 2 of AUTH_DEDICATED.md: APIs, roles, application access, the
// audience on /authorize and in the tokens; importing users (a move from
// Auth0) and linking them to Google by e-mail.
import { env } from 'cloudflare:test';
import { decodeJwt } from 'jose';
import { describe, expect, it } from 'vitest';
import { admin, call, codeFlow, form, googleSignIn, newClient, unique, withEnv } from './dedicated';

const ZARA = 'zaracloud-api';
const MY = 'my-scorpio-api';
type Tokens = { access_token: string; id_token: string; refresh_token: string };

async function setUp() {
  expect((await admin(env, 'POST', '/admin/apis', { id: ZARA, name: 'Zaracloud', permissions: [{ name: 'read:shows', description: 'See shows' }, 'write:shows', 'admin:all'] })).status).toBe(201);
  expect((await admin(env, 'POST', '/admin/apis', { id: MY, name: 'My Scorpio', permissions: ['read:forms'] })).status).toBe(201);
  const everyone = await admin<{ id: string }>(env, 'POST', '/admin/roles', { name: 'default_access', is_default: true, permissions: [{ api_id: ZARA, permission: 'read:shows' }] });
  const editors = await admin<{ id: string }>(env, 'POST', '/admin/roles', {
    name: 'muziek_redactie',
    permissions: [
      { api_id: ZARA, permission: 'write:shows' },
      { api_id: ZARA, permission: 'admin:all' },
      { api_id: MY, permission: 'read:forms' },
    ],
  });
  expect(everyone.status).toBe(201);
  expect(editors.status).toBe(201);
  const app = await newClient(env);
  const access = await admin(env, 'PUT', `/admin/clients/${app.client_id}/api-access/${ZARA}`, { user: ['read:shows', 'write:shows'] });
  expect(access.status).toBe(200);
  expect(access.body).toMatchObject({ user: ['read:shows', 'write:shows'], client: [] });
  return { app, everyone: everyone.body.id, editors: editors.body.id };
}

// Once, on first use (the schema is applied before the tests run, not at import).
let once: ReturnType<typeof setUp> | null = null;
const readyOnce = () => (once ??= setUp());

describe('the audience on /authorize', () => {
  it('a token for the API: aud is the API, permissions = roles ∩ the app\'s user access, email', async () => {
    const { app, editors } = await readyOnce();
    const email = unique('editor');
    expect((await admin(env, 'POST', `/admin/roles/${editors}/members`, { emails: [email.toUpperCase()] })).body).toMatchObject({ added: 1 });
    const { cookie } = await googleSignIn(env, email);
    const flow = await codeFlow(env, app, cookie, { audience: ZARA });
    expect(flow.status).toBe(200);
    const at = decodeJwt(String(flow.body.access_token));
    expect(at.aud).toBe(ZARA);
    // admin:all is the role's, but the app may not ask for it.
    expect(at.permissions).toEqual(['read:shows', 'write:shows']);
    expect(at.email).toBe(email);
    // The id token stays the app's.
    expect(decodeJwt(String(flow.body.id_token)).aud).toBe(app.client_id);
    // /userinfo keeps accepting it.
    expect((await call(env, '/userinfo', { headers: { Authorization: `Bearer ${flow.body.access_token}` } })).status).toBe(200);
  });

  it('the default role applies without a row: someone new gets its permissions', async () => {
    const { app } = await readyOnce();
    const { cookie } = await googleSignIn(env, unique('newcomer'));
    const flow = await codeFlow(env, app, cookie, { audience: ZARA });
    expect(decodeJwt(String(flow.body.access_token)).permissions).toEqual(['read:shows']);
  });

  it('an unknown audience, or one the app has no user access to, is refused (invalid_request)', async () => {
    const { app } = await readyOnce();
    const { cookie } = await googleSignIn(env, unique('refused'));
    for (const audience of ['nope-api', MY]) {
      const flow = await codeFlow(env, app, cookie, { audience });
      expect(flow.status).toBe(0);
      expect(flow.authorize.searchParams.get('error')).toBe('invalid_request');
      expect(flow.authorize.searchParams.get('state')).toBe('st4te');
    }
  });

  it('without an audience everything as before: aud is the client, no permissions or email in the access token', async () => {
    const { app } = await readyOnce();
    const { cookie } = await googleSignIn(env, unique('plain'));
    const at = decodeJwt(String((await codeFlow(env, app, cookie)).body.access_token));
    expect(at.aud).toBe(app.client_id);
    expect(at.permissions).toBeUndefined();
    expect(at.email).toBeUndefined();
  });

  it('a token for API A is only for A (a single aud)', async () => {
    const { app } = await readyOnce();
    const { cookie } = await googleSignIn(env, unique('one-aud'));
    expect(decodeJwt(String((await codeFlow(env, app, cookie, { audience: ZARA })).body.access_token)).aud).toBe(ZARA);
  });

  it('a refresh keeps the audience and reads the permissions again', async () => {
    const { app, editors } = await readyOnce();
    const email = unique('refresher');
    const { cookie } = await googleSignIn(env, email);
    const first = (await codeFlow(env, app, cookie, { audience: ZARA })).body as unknown as Tokens;
    expect(decodeJwt(first.access_token).permissions).toEqual(['read:shows']);
    // Made an editor: the next refresh has it.
    await admin(env, 'POST', `/admin/roles/${editors}/members`, { emails: [email] });
    const refresh = async (token: string) => {
      const res = await form(env, '/token', { grant_type: 'refresh_token', refresh_token: token, client_id: app.client_id, client_secret: app.client_secret });
      return { status: res.status, body: (await res.json()) as Tokens & { error?: string } };
    };
    const second = await refresh(first.refresh_token);
    expect(second.status).toBe(200);
    expect(decodeJwt(second.body.access_token).aud).toBe(ZARA);
    expect(decodeJwt(second.body.access_token).permissions).toEqual(['read:shows', 'write:shows']);
    // Taken off again.
    expect((await admin(env, 'DELETE', `/admin/roles/${editors}/members/${encodeURIComponent(email)}`)).status).toBe(200);
    const third = await refresh(second.body.refresh_token);
    expect(decodeJwt(third.body.access_token).permissions).toEqual(['read:shows']);
  });

  it('a refresh is refused once the app has no user access to the audience any more', async () => {
    const { everyone } = await readyOnce();
    const other = await newClient(env);
    await admin(env, 'PUT', `/admin/clients/${other.client_id}/api-access/${ZARA}`, { user: ['read:shows'] });
    const { cookie } = await googleSignIn(env, unique('cut'));
    const tokens = (await codeFlow(env, other, cookie, { audience: ZARA })).body as unknown as Tokens;
    await admin(env, 'PUT', `/admin/clients/${other.client_id}/api-access/${ZARA}`, { user: [] });
    const res = await form(env, '/token', { grant_type: 'refresh_token', refresh_token: tokens.refresh_token, client_id: other.client_id, client_secret: other.client_secret });
    expect(((await res.json()) as { error: string }).error).toBe('invalid_grant');
    expect(everyone).toBeTruthy();
  });
});

describe('the admin API for APIs, roles and access', () => {
  it('lists APIs with their permissions and use, and one API with who uses it', async () => {
    await readyOnce();
    const list = await admin<{ id: string; permissions: unknown[]; clients: number; roles: number }[]>(env, 'GET', '/admin/apis');
    const zara = list.body.find((a) => a.id === ZARA)!;
    expect(zara.permissions).toContainEqual({ name: 'read:shows', description: 'See shows' });
    expect(zara.clients).toBeGreaterThanOrEqual(1);
    expect(zara.roles).toBe(2);
    const one = await admin<{ clients: { kind: string }[]; roles: { name: string }[] }>(env, 'GET', `/admin/apis/${ZARA}`);
    expect(one.body.roles.map((r) => r.name)).toContain('muziek_redactie');
  });

  it('refuses a permission that is not an API\'s, a bad id, and a role name twice', async () => {
    const { app } = await readyOnce();
    expect((await admin(env, 'POST', '/admin/roles', { name: 'x', permissions: [{ api_id: ZARA, permission: 'fly:away' }] })).status).toBe(400);
    expect((await admin(env, 'PUT', `/admin/clients/${app.client_id}/api-access/${ZARA}`, { user: ['fly:away'] })).status).toBe(400);
    expect((await admin(env, 'POST', '/admin/apis', { id: 'has space', name: 'x' })).status).toBe(400);
    expect((await admin(env, 'POST', '/admin/apis', { id: ZARA, name: 'again' })).status).toBe(409);
    expect((await admin(env, 'POST', '/admin/roles', { name: 'default_access' })).status).toBe(409);
    expect((await admin(env, 'GET', '/admin/roles/rol_nothing')).status).toBe(404);
  });

  it('removing a permission removes every grant of it; deleting an API removes it all', async () => {
    const api = `tmp-${Date.now()}`;
    await admin(env, 'POST', '/admin/apis', { id: api, name: 'Tmp', permissions: ['a', 'b'] });
    const role = await admin<{ id: string }>(env, 'POST', '/admin/roles', { name: `tmp-${Date.now()}`, permissions: [{ api_id: api, permission: 'a' }, { api_id: api, permission: 'b' }] });
    expect((await admin(env, 'PUT', `/admin/apis/${api}/permissions/c`, { description: 'Cee' })).status).toBe(200);
    expect((await admin(env, 'DELETE', `/admin/apis/${api}/permissions/a`)).status).toBe(200);
    expect((await admin<{ permissions: unknown[] }>(env, 'GET', `/admin/roles/${role.body.id}`)).body.permissions).toEqual([{ api_id: api, permission: 'b' }]);
    expect((await admin(env, 'DELETE', `/admin/apis/${api}`)).status).toBe(200);
    expect((await admin<{ permissions: unknown[] }>(env, 'GET', `/admin/roles/${role.body.id}`)).body.permissions).toEqual([]);
    expect((await admin(env, 'GET', `/admin/apis/${api}`)).status).toBe(404);
  });

  it('a role: rename, replace its permissions, default on and off, delete', async () => {
    const role = await admin<{ id: string }>(env, 'POST', '/admin/roles', { name: `forms-${Date.now()}` });
    const id = role.body.id;
    expect((await admin(env, 'PATCH', `/admin/roles/${id}`, { name: `forms_access-${Date.now()}`, is_default: false, description: 'Forms' })).status).toBe(200);
    expect((await admin(env, 'PUT', `/admin/roles/${id}/permissions`, { permissions: [{ api_id: MY, permission: 'read:forms' }] })).body).toMatchObject({ ok: true });
    expect((await admin(env, 'PATCH', `/admin/roles/${id}`, { is_default: 'yes' })).status).toBe(400);
    expect((await admin(env, 'POST', `/admin/roles/${id}/members`, { emails: ['not an address'] })).status).toBe(400);
    expect((await admin(env, 'DELETE', `/admin/roles/${id}`)).status).toBe(200);
    expect((await admin(env, 'GET', `/admin/roles/${id}`)).status).toBe(404);
  });

  it('every new route: 401 without an admin, 404 from the internet', async () => {
    const { app } = await readyOnce();
    const { cookie } = await googleSignIn(env, unique('nobody'));
    const userToken = String((await codeFlow(env, app, cookie)).body.access_token);
    const routes: [string, string][] = [
      ['GET', '/admin/apis'],
      ['POST', '/admin/apis'],
      ['GET', `/admin/apis/${ZARA}`],
      ['PATCH', `/admin/apis/${ZARA}`],
      ['DELETE', `/admin/apis/${ZARA}`],
      ['PUT', `/admin/apis/${ZARA}/permissions/x`],
      ['DELETE', `/admin/apis/${ZARA}/permissions/read:shows`],
      ['GET', '/admin/roles'],
      ['POST', '/admin/roles'],
      ['GET', '/admin/roles/x'],
      ['PATCH', '/admin/roles/x'],
      ['DELETE', '/admin/roles/x'],
      ['PUT', '/admin/roles/x/permissions'],
      ['POST', '/admin/roles/x/members'],
      ['DELETE', '/admin/roles/x/members/a@b.test'],
      ['GET', `/admin/clients/${app.client_id}/api-access`],
      ['PUT', `/admin/clients/${app.client_id}/api-access/${ZARA}`],
      ['POST', '/admin/users'],
      ['GET', '/admin/instance'],
    ];
    for (const [method, path] of routes) {
      for (const auth of [{ Authorization: `Bearer ${userToken}` }, { Authorization: 'Bearer wrong-key' }, {} as Record<string, string>]) {
        expect([method, path, (await admin(env, method, path, method === 'GET' || method === 'DELETE' ? undefined : {}, auth)).status]).toEqual([method, path, 401]);
      }
      const internet = await call(env, path, { method, headers: { Authorization: 'Bearer test-admin-key', 'CF-Connecting-IP': '203.0.113.9' } });
      expect([method, path, internet.status]).toEqual([method, path, 404]);
    }
    // Still there.
    expect((await admin(env, 'GET', `/admin/apis/${ZARA}`)).status).toBe(200);
  });

  it('changes are in the audit log (who, what, how it went); reads are not', async () => {
    await readyOnce();
    const { results } = await env.DB.prepare("SELECT name, by, detail FROM audit_log WHERE detail LIKE '%/admin/roles%' ORDER BY id").all<{ name: string; by: string; detail: string }>();
    expect(results.length).toBeGreaterThan(0);
    expect(results[0]).toMatchObject({ name: 'admin', by: 'key' });
    expect(JSON.parse(results[0].detail)).toMatchObject({ method: 'POST', path: '/admin/roles', status: 201 });
    expect(results.some((r) => JSON.parse(r.detail).method === 'GET')).toBe(false);
  });
});

describe('importing users (from Auth0) and their first Google sign-in', () => {
  const SCORPIO = withEnv({ SIGN_IN: 'google', GOOGLE_HOSTED_DOMAIN: 'radioscorpio.test' });

  it('an imported user keeps the id given: their first Google sign-in links by e-mail, sub unchanged', async () => {
    const email = unique('imported', 'radioscorpio.test');
    const id = `google-apps|${email}`;
    const created = await admin(SCORPIO, 'POST', '/admin/users', { id, email, name: 'Imported Person' });
    expect(created).toMatchObject({ status: 201, body: { created: 1, existing: 0 } });
    const app = await newClient(SCORPIO);
    const { res, cookie } = await googleSignIn(SCORPIO, `hd:radioscorpio.test:${email}`);
    expect(res.status).toBe(302);
    const flow = await codeFlow(SCORPIO, app, cookie);
    expect(decodeJwt(String(flow.body.id_token)).sub).toBe(id);
    const row = await env.DB.prepare('SELECT id, google_sub, email_verified FROM users WHERE email = ?').bind(email).first();
    expect(row).toEqual({ id, google_sub: `google-${email}`, email_verified: 1 });
    // Imported again: left as it is.
    expect((await admin(SCORPIO, 'POST', '/admin/users', { users: [{ id, email }] })).body).toEqual({ created: 0, existing: 1 });
  });

  it('not linked when Google does not vouch for the address, or the Workspace differs', async () => {
    const email = unique('careful', 'radioscorpio.test');
    await admin(SCORPIO, 'POST', '/admin/users', { id: `google-apps|${email}`, email, email_verified: false });
    expect((await googleSignIn(SCORPIO, `hd:radioscorpio.test:unverified-${email}`)).res.status).toBe(400);
    expect((await googleSignIn(SCORPIO, `hd:elsewhere.test:${email}`)).res.status).toBe(403);
    expect(await env.DB.prepare('SELECT google_sub FROM users WHERE email = ?').bind(email).first()).toEqual({ google_sub: null });
  });

  it('never re-linked to another Google account: refused, the account untouched', async () => {
    const email = unique('linked', 'radioscorpio.test');
    await admin(SCORPIO, 'POST', '/admin/users', { id: `google-apps|${email}`, email });
    await env.DB.prepare('UPDATE users SET google_sub = ? WHERE email = ?').bind('google-someone-before', email).run();
    const { res, cookie } = await googleSignIn(SCORPIO, `hd:radioscorpio.test:${email}`);
    expect(res.status).toBe(403);
    expect(cookie).not.toMatch(/^__Host-session=./);
    expect(await env.DB.prepare('SELECT google_sub FROM users WHERE email = ?').bind(email).first()).toEqual({ google_sub: 'google-someone-before' });
  });

  it('validates what is imported', async () => {
    for (const bad of [{ id: '', email: 'a@b.test' }, { id: 'x\u0000y', email: 'a@b.test' }, { id: ' padded', email: 'a@b.test' }, { id: 'x'.repeat(201), email: 'a@b.test' }, { id: 'ok', email: 'nope' }, { id: 'ok', email: 'a@b.test', email_verified: 'yes' }]) {
      expect((await admin(SCORPIO, 'POST', '/admin/users', bad)).status).toBe(400);
    }
    expect((await admin(SCORPIO, 'POST', '/admin/users', { users: [{ id: 'same', email: 'one@b.test' }, { id: 'same', email: 'two@b.test' }] })).status).toBe(400);
  });
});
