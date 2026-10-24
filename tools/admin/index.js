// The admin API from your laptop (tools/admin/README.md): arcanum-auth only
// answers /admin/* without CF-Connecting-IP - calls from another Worker, never
// from the internet. Run with `wrangler dev`, this Worker reaches the deployed
// arcanum-auth through a remote service binding, which carries no such header.
//   /, /callback   the page (page.html); signing in comes back to /callback
//   /oidc          where to sign in (arcanum-auth's discovery document)
//   /exchange      the sign-in's code for a token (the built-in admin client,
//                  no secret - PKCE; arcanum-auth's /token has no CORS)
//   /admin/*       passed on as a fresh request: the path, the method,
//                  Authorization, Content-Type and the body - nothing else
import PAGE from './page.html';

// arcanum-auth knows this address as the admin client's one return address
// (store.ts ADMIN_TOOL_CALLBACK): the page lives on exactly this origin.
const ORIGIN = 'http://127.0.0.1:8799';
const ADMIN_CLIENT_ID = 'arcanum-auth-admin';
// Only as localhost: a web page elsewhere can't use this through a DNS name
// pointed at 127.0.0.1 (DNS rebinding). The token or key never leaves the
// page's own tab (sessionStorage), and another site can't set Authorization
// without CORS.
const LOCAL = new Set(['127.0.0.1', 'localhost', '[::1]']);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const host = (request.headers.get('Host') || '').replace(/:\d+$/, '');
    if (!LOCAL.has(host)) return new Response('Open this on 127.0.0.1.', { status: 403 });
    // One origin, or the sign-in's state (sessionStorage) is in another tab's storage.
    if (host !== '127.0.0.1') return Response.redirect(`${ORIGIN}${url.pathname}${url.search}`, 302);

    if ((url.pathname === '/' || url.pathname === '/callback') && request.method === 'GET') {
      return new Response(PAGE, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'no-referrer' } });
    }
    if (url.pathname === '/oidc' && request.method === 'GET') {
      const res = await env.AUTH.fetch(new Request('https://arcanum-auth/.well-known/openid-configuration'));
      if (!res.ok) return Response.json({ error: `arcanum-auth answered ${res.status}` }, { status: 502 });
      const d = await res.json();
      return Response.json({ issuer: d.issuer, authorization_endpoint: d.authorization_endpoint, client_id: ADMIN_CLIENT_ID, redirect_uri: `${ORIGIN}/callback` });
    }
    if (url.pathname === '/exchange' && request.method === 'POST') {
      // Only from this page (a form elsewhere can't send JSON without CORS).
      if (request.headers.get('Content-Type') !== 'application/json') return Response.json({ error: 'JSON only' }, { status: 415 });
      const { code, verifier } = await request.json();
      const body = new URLSearchParams({ grant_type: 'authorization_code', code: String(code || ''), code_verifier: String(verifier || ''), client_id: ADMIN_CLIENT_ID, redirect_uri: `${ORIGIN}/callback` });
      const res = await env.AUTH.fetch(new Request('https://arcanum-auth/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body }));
      const data = await res.json().catch(() => ({}));
      // Only what the page needs: the access token and how long it lasts.
      return Response.json(res.ok ? { access_token: data.access_token, expires_in: data.expires_in } : { error: data.error_description || data.error || `HTTP ${res.status}` }, { status: res.ok ? 200 : 400 });
    }
    if (!url.pathname.startsWith('/admin/')) return Response.json({ error: 'Only /admin/… goes through' }, { status: 404 });
    const headers = new Headers();
    for (const name of ['Authorization', 'Content-Type']) {
      const value = request.headers.get(name);
      if (value) headers.set(name, value);
    }
    const body = request.method === 'GET' || request.method === 'HEAD' ? undefined : await request.arrayBuffer();
    // The host is arcanum-auth's own business (it uses its ISSUER); a binding ignores it.
    return env.AUTH.fetch(new Request(`https://arcanum-auth${url.pathname}${url.search}`, { method: request.method, headers, body }));
  },
};
