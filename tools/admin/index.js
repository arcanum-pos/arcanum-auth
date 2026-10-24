// The admin API from your laptop (tools/admin/README.md): arcanum-auth only
// answers /admin/* without CF-Connecting-IP - calls from another Worker, never
// from the internet. Run with `wrangler dev`, this Worker reaches the deployed
// arcanum-auth through a remote service binding, which carries no such header.
// `/` is a small page for it (page.html); `/admin/*` is passed on as a fresh
// request: the path, the method, Authorization, Content-Type and the body -
// nothing else of what reached it.
import PAGE from './page.html';

// Only as localhost: a web page elsewhere can't use this through a DNS name
// pointed at 127.0.0.1 (DNS rebinding). The key never leaves the page's own
// tab (sessionStorage), and another site can't set Authorization without CORS.
const LOCAL = new Set(['127.0.0.1', 'localhost', '[::1]']);

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const host = (request.headers.get('Host') || '').replace(/:\d+$/, '');
    if (!LOCAL.has(host)) return new Response('Open this on localhost.', { status: 403 });
    if (url.pathname === '/' && request.method === 'GET') {
      return new Response(PAGE, { headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY' } });
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
