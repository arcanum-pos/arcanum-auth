import { validUris } from './admin';
import type { Env } from './env';
import { clientById, clientSecretMatches, type Client } from './store';
import { json, randomToken, sha256 } from './util';

// Client self-service — an application managing its own client
// with its own credentials (HTTP Basic: client_id:client_secret), never the
// admin key. What the installer uses after setting a custom domain:
//   GET   /clients/self         → its name + URIs
//   PATCH /clients/self         { redirect_uris?, post_logout_redirect_uris? } (replaces each list given)
//   POST  /clients/self/secret  → { client_secret } — a new one; the old stops working

const MAX_URIS = 10;

async function authenticated(request: Request, env: Env): Promise<Client | null> {
  const auth = request.headers.get('Authorization') || '';
  if (!auth.startsWith('Basic ')) return null;
  try {
    const [id, secret] = atob(auth.slice(6)).split(':').map(decodeURIComponent);
    const client = await clientById(env, id);
    return client && (await clientSecretMatches(client, secret)) ? client : null;
  } catch {
    return null;
  }
}

const view = (c: Client) => ({
  client_id: c.id,
  name: c.name,
  redirect_uris: c.redirect_uris,
  post_logout_redirect_uris: c.post_logout_redirect_uris,
  instance_url: c.instance_url,
});

export async function clientSelf(request: Request, env: Env, path: string): Promise<Response> {
  const client = await authenticated(request, env);
  if (!client) return json({ error: 'invalid_client' }, 401, { 'WWW-Authenticate': 'Basic realm="clients"' });

  if (path === '/clients/self' && request.method === 'GET') return json(view(client));

  if (path === '/clients/self' && request.method === 'PATCH') {
    const body = (await request.json().catch(() => null)) as Record<string, unknown> | null;
    if (!body) return json({ error: 'a JSON body is required' }, 400);
    const redirects = body.redirect_uris === undefined ? client.redirect_uris : validUris(body.redirect_uris);
    const logouts = body.post_logout_redirect_uris === undefined ? client.post_logout_redirect_uris : validUris(body.post_logout_redirect_uris);
    if (!redirects || !logouts || redirects.length === 0 || redirects.length > MAX_URIS || logouts.length > MAX_URIS) {
      return json({ error: `redirect_uris: 1–${MAX_URIS} https URLs; post_logout_redirect_uris: up to ${MAX_URIS}` }, 400);
    }
    await env.DB.prepare('UPDATE clients SET redirect_uris = ?, post_logout_redirect_uris = ? WHERE id = ?')
      .bind(JSON.stringify(redirects), JSON.stringify(logouts), client.id)
      .run();
    return json(view({ ...client, redirect_uris: redirects, post_logout_redirect_uris: logouts }));
  }

  if (path === '/clients/self/secret' && request.method === 'POST') {
    const secret = randomToken(32);
    await env.DB.prepare('UPDATE clients SET secret_hash = ? WHERE id = ?').bind(await sha256(secret), client.id).run();
    return json({ client_id: client.id, client_secret: secret });
  }
  return json({ error: 'Not found' }, 404);
}
