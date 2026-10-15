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
// A passkey (passkeys.ts) is one more way into that same user.
// Clients — one per installation — are created by the installer via /admin.
import { account, devicePage, deviceConfirm, googleCallback, googleStart, login, loginCode, loginLink, loginName, loginOnce } from './account';
import { admin } from './admin';
import { cleanup } from './cleanup';
import { clientSelf } from './clients';
import type { Env } from './env';
import { authorize, deviceAuthorization, discovery, jwks, logout, token, userinfo } from './oidc';
import { messagePage, texts } from './pages';
import { managePasskey, passkeyLogin, passkeyLoginOptions, passkeyOffer, passkeyRegister, passkeyRegisterOptions } from './passkeys';
import { PASSKEY_SCRIPT } from './passkey-script';
import { json, redirect, safeContinue } from './util';
import { tooManyRequests, withinLimit } from './ratelimit';

export type { Env };

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const response = await handle(request, env);
    // Browsers only ever reach this over https; and no answer is ever read
    // as another type than it says it is.
    const out = new Response(response.body, response);
    if (!out.headers.has('Strict-Transport-Security')) out.headers.set('Strict-Transport-Security', 'max-age=31536000');
    out.headers.set('X-Content-Type-Options', 'nosniff');
    return out;
  },

  // Hourly (triggers.crons): expired guests and old protocol state.
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    console.log(JSON.stringify({ event: 'arcanum-auth cleanup', deleted: await cleanup(env) }));
  },
};

const tooMany = tooManyRequests;

async function handle(request: Request, env: Env): Promise<Response> {
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
      if (path === '/login/code' && (method === 'GET' || method === 'POST')) return loginCode(request, env);
      if (path === '/login/link' && (method === 'GET' || method === 'POST')) return loginLink(request, env);
      if (path === '/login/name' && method === 'POST') return loginName(request, env);
      // No passwords anymore: the old sign-up, verify and reset pages lead to sign-in.
      if (path === '/signup' || path === '/verify' || path === '/reset' || path === '/reset/confirm') {
        return redirect(`/login?continue=${encodeURIComponent(safeContinue(url.searchParams.get('continue')))}`, {}, 303);
      }
      if (path === '/google' && method === 'GET') {
        if (!(await withinLimit(env, `google:${request.headers.get('CF-Connecting-IP') ?? 'unknown'}`))) return tooMany();
        return googleStart(request, env);
      }
      if (path === '/callback/google' && method === 'GET') return googleCallback(request, env);
      if (path === '/device' && (method === 'GET' || method === 'POST')) return devicePage(request, env);
      if (path === '/device/confirm' && method === 'POST') return deviceConfirm(request, env);
      if (path === '/account' && method === 'GET') return account(request, env);
      if (path === '/login/once' && method === 'GET') return loginOnce(request, env);
      if (path === '/passkey/login/options' && method === 'POST') {
        if (!(await withinLimit(env, `passkey-options:${request.headers.get('CF-Connecting-IP') ?? 'unknown'}`))) return tooMany();
        return passkeyLoginOptions(request, env);
      }
      if (path === '/passkey/login' && method === 'POST') return passkeyLogin(request, env);
      if (path === '/passkey/register/options' && method === 'POST') return passkeyRegisterOptions(request, env);
      if (path === '/passkey/register' && method === 'POST') return passkeyRegister(request, env);
      if (path === '/passkey/offer' && (method === 'GET' || method === 'POST')) return passkeyOffer(request, env);
      if (path === '/account/passkeys' && method === 'POST') return managePasskey(request, env);
      if (path === '/passkey.js' && method === 'GET') {
        return new Response(PASSKEY_SCRIPT, { headers: { 'Content-Type': 'text/javascript; charset=utf-8', 'Cache-Control': 'public, max-age=300', 'X-Content-Type-Options': 'nosniff' } });
      }
      if (path === '/clients/self' || path === '/clients/self/secret') return clientSelf(request, env, path);
      // The admin API is for the bootstrapper, over its service binding —
      // never from the internet (Cloudflare marks those with
      // CF-Connecting-IP; a service binding's calls don't carry it), even
      // with the right key.
      if (path.startsWith('/admin/')) {
        if (request.headers.has('CF-Connecting-IP')) return json({ error: 'Not found' }, 404);
        return admin(request, env, path);
      }
      if (path === '/' && method === 'GET') return redirect('/account');
      if (path === '/health') return json({ ok: true });
      return messagePage(request, texts(request).errors.request, 404);
    } catch (err) {
      console.error('arcanum-auth error', err);
      return json({ error: 'server_error' }, 500);
    }
}
