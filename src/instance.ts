import type { Env } from './env';
import { adminEmails } from './store';

// What this instance is set up for (AUTH_DEDICATED.md, section 1). Every
// setting is off unless it's set: login.kaboutersoft.be sets none of them
// and behaves exactly as before.
//   SIGN_IN=google        only Google: no mailed codes, passkeys, device flow,
//                         enrollment, client self-service or access requests
//   GOOGLE_HOSTED_DOMAIN  only accounts of that Google Workspace (hd)
//   PRODUCT_NAME          the name on the sign-in pages (else the host)
//   AUTH0_COMPAT=true     Auth0's paths and JSON bodies (oidc.ts)
//   ACTIONS               a post-login action Worker (actions.ts)

export const googleOnly = (env: Env): boolean => env.SIGN_IN?.trim().toLowerCase() === 'google';

export const auth0Compat = (env: Env): boolean => env.AUTH0_COMPAT?.trim().toLowerCase() === 'true';

export const hostedDomain = (env: Env): string | null => env.GOOGLE_HOSTED_DOMAIN?.trim().toLowerCase() || null;

export const productName = (env: Env): string | null => env.PRODUCT_NAME?.trim() || null;

// ISSUER as given goes into `iss` (tokens, discovery, the authorization
// response) - Auth0's issuers end in a slash, and APIs compare it exactly.
// Every URL is built from it without that slash.
export const issuerUrl = (env: Env): string => env.ISSUER.replace(/\/+$/, '');

// The instance's settings for the admin dashboard (GET /admin/instance):
// what's on, never a secret's value.
export function instanceSettings(env: Env) {
  return {
    issuer: env.ISSUER,
    sign_in: googleOnly(env) ? 'google' : 'all',
    sign_in_methods: googleOnly(env) ? ['google'] : ['email_code', 'passkey', ...(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET ? ['google'] : [])],
    google: !!(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET),
    google_hosted_domain: hostedDomain(env),
    product_name: productName(env),
    auth0_compat: auth0Compat(env),
    actions: !!env.ACTIONS,
    self_service: !googleOnly(env),
    device_flow: !googleOnly(env),
    admin_emails: adminEmails(env).length,
  };
}
