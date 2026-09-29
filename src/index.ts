// arcanum-auth: a small OpenID Connect provider for Arcanum — the default
// identity provider of every installation (login.kaboutersoft.be), in place
// of Auth0. Exactly what arcanum-bff needs, and no more:
//   - authorization code + PKCE (the console, the chooser)
//   - device authorization grant, RFC 8628 (the kassa's QR login)
//   - refresh tokens (offline_access), rotated on use
//   - id_token + /userinfo with sub, email, email_verified, name
//   - discovery, JWKS, RP-initiated logout
// Users sign in with e-mail + password (address verified by a mailed code)
// or with Google; both link to one user (and one `sub`) by verified e-mail.
// Clients — one per installation — are created by the installer via /admin.
import { account, devicePage, deviceConfirm, googleCallback, googleStart, login, loginOnce, resetConfirm, resetRequest, signup, verify } from './account';
import { admin } from './admin';
import { cleanup } from './cleanup';
import { clientSelf } from './clients';
import type { Env } from './env';
import { authorize, deviceAuthorization, discovery, jwks, logout, token, userinfo } from './oidc';
import { messagePage, texts } from './pages';
import { json, redirect } from './util';

export type { Env };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, '') || '/';
    const method = request.method;
    try {
      if (path === '/.well-known/openid-configuration' && method === 'GET') return discovery(env);
      if (path === '/.well-known/jwks.json' && method === 'GET') return jwks(env);
      if (path === '/authorize' && method === 'GET') return authorize(request, env);
      if (path === '/token' && method === 'POST') return token(request, env);
      if (path === '/device/code' && method === 'POST') return deviceAuthorization(request, env);
      if (path === '/userinfo' && (method === 'GET' || method === 'POST')) return userinfo(request, env);
      if (path === '/logout' && method === 'GET') return logout(request, env);

      if (path === '/login' && (method === 'GET' || method === 'POST')) return login(request, env);
      if (path === '/signup' && (method === 'GET' || method === 'POST')) return signup(request, env);
      if (path === '/verify' && (method === 'GET' || method === 'POST')) return verify(request, env);
      if (path === '/reset' && (method === 'GET' || method === 'POST')) return resetRequest(request, env);
      if (path === '/reset/confirm' && method === 'POST') return resetConfirm(request, env);
      if (path === '/google' && method === 'GET') return googleStart(request, env);
      if (path === '/callback/google' && method === 'GET') return googleCallback(request, env);
      if (path === '/device' && (method === 'GET' || method === 'POST')) return devicePage(request, env);
      if (path === '/device/confirm' && method === 'POST') return deviceConfirm(request, env);
      if (path === '/account' && method === 'GET') return account(request, env);
      if (path === '/login/once' && method === 'GET') return loginOnce(request, env);
      if (path === '/clients/self' || path === '/clients/self/secret') return clientSelf(request, env, path);
      if (path.startsWith('/admin/')) return admin(request, env, path);
      if (path === '/' && method === 'GET') return redirect('/account');
      if (path === '/health') return json({ ok: true });
      return messagePage(request, texts(request).errors.request, 404);
    } catch (err) {
      console.error('arcanum-auth error', err);
      return json({ error: 'server_error' }, 500);
    }
  },

  // Hourly (triggers.crons): expired guests and old protocol state.
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    console.log(JSON.stringify({ event: 'arcanum-auth cleanup', deleted: await cleanup(env) }));
  },
};
