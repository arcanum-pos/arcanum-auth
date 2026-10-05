# arcanum-auth

Arcanum's own OpenID Connect provider — the default identity provider of
every installation, at **https://login.kaboutersoft.be**, in place of Auth0.
One Cloudflare Worker + one D1 database.

It does exactly what `arcanum-bff` needs:

| | |
|---|---|
| **Authorization code + PKCE (S256)** | the console and the chooser (`/login` in arcanum-bff) |
| **Device authorization grant** (RFC 8628) | the kassa's QR login (`/device` in arcanum-bff) |
| **Refresh tokens** (`offline_access`) | rotated on every use; reusing an old one revokes them all |
| **id_token + /userinfo** | `sub`, `email`, `email_verified`, `name` (RS256, JWKS published) |
| **Discovery, JWKS, RP-initiated logout** | `/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/logout` |

People sign in with **e-mail + password** (the address is proven with a
6-digit code sent by mail before the account exists) or **with Google**.
Both lead to the same user — the same `sub` — when the verified e-mail is
the same, so switching sign-in method never breaks an Arcanum membership.

**Passkeys** are one more way into that same user (`src/passkeys.ts`,
verified with `@simplewebauthn/server`): fingerprint, face or the device's
PIN, no password, no e-mail to type. Nothing changes for the installations
— same `sub`, same claims.
- **Adding one:** on `/account` → *Passkey toevoegen*; and once after
  signing in another way (password, mailed code, Google), a page offers it
  (*Niet nu* = not asked again for 30 days; a browser without passkeys
  skips the page). The owner gets a mail whenever one is added.
- **Signing in:** *Aanmelden met een passkey* on the login page, or the
  browser's own suggestion in the e-mail field (`autocomplete="username
  webauthn"`). Discoverable credentials, so no e-mail is asked.
- **Relying party = the ISSUER's host** (`login.kaboutersoft.be`). A passkey
  only works there: changing that host would leave every passkey unusable
  (people fall back to their password, Google or a reset).
- User verification required, attestation `none`, single-use challenges
  (5 minutes), the signature counter kept and checked, the user handle
  must match. Guests can't add one. `/account` lists, renames and removes
  them.
- The pages' only script is `/passkey.js` (`src/passkey-script.ts`, plain
  ES2017), on the pages that offer passkeys; the CSP allows scripts and
  fetches from this origin only. Without it every page still works.

**Guests** are for the demo's "Direct proberen": the bootstrapper creates
one and a one-time sign-in link for it (both with the admin key). An expired
guest is refused everywhere at once (session, every grant, userinfo); an
hourly cron (`triggers.crons`) deletes expired guests with their sessions,
tokens and links, and purges old protocol state.

**One client per Arcanum installation**, used for both grants. Clients are
created through the admin API (`/admin/clients`, bearer `ADMIN_API_KEY`) —
what the installer will call when it sets up a new instance.

## Endpoints

| Path | What |
|---|---|
| `GET /.well-known/openid-configuration` | discovery |
| `GET /.well-known/jwks.json` | public signing key(s) |
| `GET /authorize` | authorization code flow (PKCE S256 required) |
| `POST /token` | `authorization_code`, `refresh_token`, `urn:ietf:params:oauth:grant-type:device_code`; client auth `client_secret_post` or `client_secret_basic` |
| `POST /device/code` | device authorization (`client_id` + `scope`; the secret is checked at `/token`) |
| `GET /userinfo` | the user behind an access token |
| `GET /logout` | ends the session; back to a *registered* `post_logout_redirect_uri` |
| `/login`, `/signup`, `/verify`, `/reset`, `/google`, `/device`, `/account` | the pages people see (nl/fr/en from the browser, light/dark) |
| `POST /passkey/login/options`, `POST /passkey/login` | sign in with a passkey (JSON from this origin) → `{ redirect }` + session cookie |
| `POST /passkey/register/options`, `POST /passkey/register` | add a passkey (signed in; JSON from this origin) |
| `GET/POST /passkey/offer` | the one-time offer after signing in another way (POST = "not now") |
| `POST /account/passkeys` | rename (`action=rename`) or remove (`action=delete`) one of your own |
| `GET /passkey.js` | the pages' one script (WebAuthn in the browser) |
| `POST/GET /admin/clients`, `DELETE /admin/clients/:id` | manage clients (bearer `ADMIN_API_KEY`); a client can carry `instance_url`, `owner_email`, `owner_sub` |
| `POST /admin/guests` | a **guest** — a demo visitor without an account: no password, `guest-…@guest.invalid` (unverified), gone after `lifetime_hours` (default 5, max 24) |
| `POST /admin/login-links` | a **one-time sign-in link** for a guest (single use, 60 s) that continues to an address on an origin some client registered |
| `GET /login/once?token=…` | where that link leads: starts the guest's session, then continues |
| `GET/PATCH /clients/self`, `POST /clients/self/secret` | **client self-service** with the client's own id + secret (HTTP Basic): read/replace its redirect and logout URIs, rotate its secret — what an installation's installer uses after setting a custom domain |

## Deploy (Cloudflare, your account)

1. **Database**
   ```sh
   npx wrangler d1 create arcanum-auth
   ```
   Put the printed `database_id` in `wrangler.jsonc`, then:
   ```sh
   npx wrangler d1 migrations apply arcanum-auth --remote
   ```
2. **Secrets**
   ```sh
   npm run generate-key --silent | npx wrangler secret put SIGNING_KEY
   openssl rand -base64 32 | npx wrangler secret put ADMIN_API_KEY   # note it down for the installer
   ```
   Optional, for **Sign in with Google**: create an OAuth client ("Web
   application") in Google Cloud Console with redirect URI
   `https://login.kaboutersoft.be/callback/google`, then
   `npx wrangler secret put GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`.

   For **verification and reset mails** (without them, codes are only
   written to the Worker's log — `npx wrangler tail` — fine for testing, not
   for real users): `MAILER_INTERNAL_KEY` (the same value arcanum-mailer has)
   and `MAIL_CONFIG` as JSON, either provider arcanum-mailer supports:
   - SMTP: `{"provider":"smtp","credentials":{"host":"…","port":465,"username":"…","password":"…","fromAddress":"noreply@kaboutersoft.be","fromName":"Arcanum"}}`
   - Gmail API (a Google service account with domain-wide delegation):
     `{"provider":"gmail_api","credentials":{"clientEmail":"…@….iam.gserviceaccount.com","privateKey":"-----BEGIN PRIVATE KEY-----\n…","impersonatedUser":"noreply@kaboutersoft.be","fromName":"Arcanum"}}`

   (`MAIL_SMTP` with only the SMTP credentials still works.)
   The `MAILER` service binding in `wrangler.jsonc` points at `arcanum-mailer`
   on the same account; remove it if that Worker isn't there.
3. **Deploy.** Push to `main` with Workers Builds connected, or
   `npx wrangler deploy`. `wrangler.jsonc` claims `login.kaboutersoft.be` as
   a custom domain (the `kaboutersoft.be` zone must be on the same account).
   `workers_dev` is off.

The issuer is `ISSUER` in `wrangler.jsonc`: `https://login.kaboutersoft.be`,
**no trailing slash**. Clients must be configured with exactly that string —
arcanum-bff compares the id_token's `iss` to it character for character.

## Test it

### 1. Automated tests
```sh
npm install
npm test          # 33 tests: every flow end to end, incl. the security checks,
                  # guests + one-time links, client self-service, the clean-up
npm run typecheck
```
They run the Worker in workerd with a local D1, a throwaway signing key, a
recording stand-in for arcanum-mailer and a fake Google token endpoint.

### 2. The deployed issuer on its own
```sh
curl -s https://login.kaboutersoft.be/.well-known/openid-configuration | jq
curl -s https://login.kaboutersoft.be/.well-known/jwks.json | jq
```
Create an account: open https://login.kaboutersoft.be/signup, enter a name,
e-mail and password, then the 6-digit code (from the mail, or
`npx wrangler tail` if no mailer is configured). You end on "Aangemeld als …".
Sign out and in again; try "Wachtwoord vergeten"; try "Aanmelden met Google".

**Authorization code flow**, with https://oidcdebugger.com as the client —
register it once:
```sh
curl -s -X POST https://login.kaboutersoft.be/admin/clients \
  -H "Authorization: Bearer $ADMIN_API_KEY" -H 'Content-Type: application/json' \
  -d '{"name":"oidcdebugger","redirect_uris":["https://oidcdebugger.com/debug"]}' | jq
```
On oidcdebugger.com: Authorize URI `https://login.kaboutersoft.be/authorize`,
Redirect URI `https://oidcdebugger.com/debug`, your client id, scope
`openid profile email offline_access`, response type `code`, **Use PKCE**
(SHA-256). Send the request, sign in, and you get a `code`. Exchange it
(the debugger shows the code verifier):
```sh
curl -s https://login.kaboutersoft.be/token \
  -d grant_type=authorization_code -d code=… -d code_verifier=… \
  -d redirect_uri=https://oidcdebugger.com/debug \
  -d client_id=… -d client_secret=… | jq
```
Paste the `id_token` into https://jwt.io to see its claims; call
`curl -s https://login.kaboutersoft.be/userinfo -H "Authorization: Bearer <access_token>"`.

**Device flow** (what the kassa does):
```sh
curl -s https://login.kaboutersoft.be/device/code -d client_id=… -d 'scope=openid profile email offline_access' | jq
# open verification_uri_complete on your phone, sign in, "Toestaan"; meanwhile poll:
curl -s https://login.kaboutersoft.be/token \
  -d grant_type=urn:ietf:params:oauth:grant-type:device_code \
  -d device_code=… -d client_id=… -d client_secret=… | jq
```
`authorization_pending` until you approve (`slow_down` if you poll faster
than every 5 s), then the tokens.

### 3. Arcanum against it (locally — production stays on Auth0)
Arcanum's default identity provider comes from arcanum-backend's
`DEFAULT_IDP_ISSUER_URL` / `DEFAULT_IDP_CLIENT_ID` / `DEFAULT_IDP_CLIENT_SECRET`,
written into the database **once**, the first time it's needed. So test with
a local Arcanum and a fresh local database (see `LOCAL_DEV.md`):
1. Create a client for the local BFF:
   `ADMIN_API_KEY=… node scripts/create-client.mjs "Arcanum local" http://localhost:8787`
   (localhost may use http).
2. In arcanum-backend's `.dev.vars`: `DEFAULT_IDP_ISSUER_URL=https://login.kaboutersoft.be`
   plus that `client_id` / `client_secret`. Start backend, bff, frontends,
   devicehub, mailer as `LOCAL_DEV.md` describes.
3. http://localhost:8787/console → you're sent to login.kaboutersoft.be → sign
   in → back in the console. Then a kassa: open the chooser on a second
   browser, `/device`, scan the QR with your phone, approve.

## Before switching production from Auth0

Not done yet — and it needs a plan, because **every Arcanum membership is
bound to `(issuer, sub)`**: moving the platform default from Auth0 to this
issuer gives every user a new issuer *and* a new `sub`, which would lock
everyone out (admins included). The way through: at cutover, reset those
memberships to "pending" (keeping role + e-mail) so they re-activate by
e-mail on the next login (`reconcilePendingInvites`), and update the
platform-default organisation's `identity_providers` row (the
`DEFAULT_IDP_*` secrets are only read when that row is first created). See
arcanum's `CLAUDE.md` ("No self-service … way to change an org's identity
provider").

## Notes

- **Passwords**: PBKDF2-SHA256 through WebCrypto, 100 000 iterations — the
  maximum Workers allows. The iteration count is stored with each hash, so
  it can change later. On the Workers Free plan (10 ms CPU per request) a
  sign-in or sign-up may occasionally be cut off; lower `PBKDF2_ITERATIONS`
  only if that actually happens, and watch it in the Worker's metrics.
- **Rate limits**: 10 wrong passwords per address and 30 per IP per quarter
  hour; 10 mails per IP per hour; 5 tries per mailed code; 20 wrong device
  codes per IP per quarter hour.
- **Key rotation**: generate a new key; put the *old* key's public JWK (no
  `d`/`p`/`q`/…) in `PREVIOUS_PUBLIC_KEYS` as a JSON array; replace
  `SIGNING_KEY`. Remove the old one after an hour (the longest access/id
  token lifetime).
- **Not (yet) here**: two-factor authentication, an admin UI, account
  deletion, dynamic client registration, consent screens (every client is
  first-party).

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE).
