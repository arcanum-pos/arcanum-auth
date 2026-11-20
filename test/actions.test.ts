// Phase 4 of AUTH_DEDICATED.md: the post-login action (ACTIONS binding).
import { env } from 'cloudflare:test';
import { decodeJwt } from 'jose';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { actionClaims } from '../src/actions';
import { codeFlow, form, googleSignIn, newClient, unique, withEnv } from './dedicated';

const GROUPS = 'https://my.radioscorpio.be/groups';
const input = { email: 'jan@radioscorpio.test', sub: 'google-apps|jan@radioscorpio.test', client_id: 'arc_x', audience: null };

// A stand-in for the owner's actions Worker.
function actions(answer: (body: Record<string, unknown>) => Response | Promise<Response>) {
  const calls: Record<string, unknown>[] = [];
  const binding = {
    fetch: async (_url: string, init: RequestInit) => {
      const body = JSON.parse(String(init.body)) as Record<string, unknown>;
      calls.push(body);
      return answer(body);
    },
  };
  return { binding: binding as unknown as Fetcher, calls };
}

afterEach(() => vi.restoreAllMocks());

describe('actionClaims', () => {
  it('without a binding: nothing, and nothing called', async () => {
    expect(await actionClaims(env, input)).toEqual({});
  });

  it('takes only claims named by an https URL, never a standard one', async () => {
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {});
    const { binding } = actions(() =>
      Response.json({ claims: { [GROUPS]: ['shows@radioscorpio.test'], sub: 'someone-else', aud: 'x', permissions: ['admin:all'], scope: 'admin', email: 'x@y.test', groups: ['plain'], 'http://insecure.test/x': 1, 'https://': 2 } })
    );
    expect(await actionClaims(withEnv({ ACTIONS: binding }), input)).toEqual({ [GROUPS]: ['shows@radioscorpio.test'] });
    expect(warn).toHaveBeenCalled();
  });

  it('fails soft: an error answer, a throw, bad JSON, no object, too much, too slow - no claims, logged', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    const answers: (() => Response | Promise<Response>)[] = [
      () => new Response('boom', { status: 500 }),
      () => {
        throw new Error('down');
      },
      () => new Response('not json'),
      () => Response.json({ claims: ['a'] }),
      () => Response.json({ claims: { [GROUPS]: 'x'.repeat(9000) } }),
      () => new Promise<Response>((resolve) => setTimeout(() => resolve(Response.json({ claims: { [GROUPS]: ['late'] } })), 200)),
    ];
    for (const answer of answers) expect(await actionClaims(withEnv({ ACTIONS: actions(answer).binding }), input, 50)).toEqual({});
    expect(error).toHaveBeenCalledTimes(answers.length);
    expect(error.mock.calls.some((c) => String(c[0]).includes('"reason":"timeout"'))).toBe(true);
  });
});

describe('the action on token issue', () => {
  it('is asked on sign-in and on every refresh with { email, sub, client_id, audience }; its claims in both tokens', async () => {
    const { binding, calls } = actions((body) => Response.json({ claims: { [GROUPS]: [`shows-of-${body.email}`], sub: 'hijack' } }));
    const e = withEnv({ ACTIONS: binding });
    const client = await newClient(e);
    const email = unique('actions');
    const { cookie } = await googleSignIn(e, email);
    const flow = await codeFlow(e, client, cookie);
    expect(flow.status).toBe(200);
    const at = decodeJwt(String(flow.body.access_token));
    const id = decodeJwt(String(flow.body.id_token));
    expect(at[GROUPS]).toEqual([`shows-of-${email}`]);
    expect(id[GROUPS]).toEqual([`shows-of-${email}`]);
    expect(at.sub).not.toBe('hijack');
    expect(at.aud).toBe(client.client_id);
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({ email, sub: at.sub, client_id: client.client_id, audience: null });

    const refreshed = await form(e, '/token', { grant_type: 'refresh_token', refresh_token: String(flow.body.refresh_token), client_id: client.client_id, client_secret: client.client_secret });
    expect(decodeJwt(String(((await refreshed.json()) as Record<string, unknown>).access_token))[GROUPS]).toEqual([`shows-of-${email}`]);
    expect(calls).toHaveLength(2);
  });

  it('a failing action: the tokens go out without its claims', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    const e = withEnv({ ACTIONS: actions(() => new Response('no', { status: 503 })).binding });
    const client = await newClient(e);
    const { cookie } = await googleSignIn(e, unique('failing'));
    const flow = await codeFlow(e, client, cookie);
    expect(flow.status).toBe(200);
    expect(decodeJwt(String(flow.body.access_token))[GROUPS]).toBeUndefined();
  });

  it('not for tools/admin\'s own client', async () => {
    const { binding, calls } = actions(() => Response.json({ claims: { [GROUPS]: ['x'] } }));
    const e = withEnv({ ACTIONS: binding, SIGN_IN: 'google' });
    const { cookie } = await googleSignIn(e, 'third@example.test');
    const flow = await codeFlow(e, { client_id: 'arcanum-auth-admin' }, cookie, { scope: 'openid email' }, 'http://127.0.0.1:8799/callback');
    expect(flow.status).toBe(200);
    expect(calls).toHaveLength(0);
  });

  it('without the binding (the shared instance): no extra claims', async () => {
    const client = await newClient(env);
    const { cookie } = await googleSignIn(env, unique('none'));
    const at = decodeJwt(String((await codeFlow(env, client, cookie)).body.access_token));
    expect(Object.keys(at).filter((k) => k.startsWith('https://'))).toEqual([]);
  });
});
