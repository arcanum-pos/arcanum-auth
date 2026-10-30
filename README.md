# arcanum-auth

[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/16083/badge)](https://www.bestpractices.dev/projects/16083)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/arcanum-pos/arcanum-auth/badge)](https://scorecard.dev/viewer/?uri=github.com/arcanum-pos/arcanum-auth)

A small OpenID Connect provider at **https://login.kaboutersoft.be**, for
any application that registers a client — the default identity provider of
the POS installations, among others. Its pages and mails name only
themselves (the host), never a product: several applications may use it.
One Cloudflare Worker + one D1 database.

It does exactly this:

| | |
|---|---|
| **Authorization code + PKCE (S256)** | the console and the chooser (`/login` in arcanum-bff) |
| **Device authorization grant** (RFC 8628) | the kassa's QR login (`/device` in arcanum-bff) |
| **Refresh tokens** (`offline_access`) | rotated on every use; reusing an old one revokes them all |
| **id_token + /userinfo** | `sub`, `email`, `email_verified`, `name` (RS256, JWKS published) |
| **Discovery, JWKS, RP-initiated logout** | `/.well-known/openid-configuration`, `/.well-known/jwks.json`, `/logout` |

**No passwords** (since 2026-10). People sign in with **a mailed code**,
**a passkey** or **Google**. Every way leads to the same user — the same
`sub` — for the same verified e-mail, so switching sign-in method never
breaks an Arcanum membership.

**Signing in with a mailed code** is one flow for signing in and signing
up (`/login` → `/login/code`): the address gets a 6-digit code and a link,
both valid 15 minutes. The code typed on the page, or the button behind the
link, signs in; an address without an account first answers one question,
its name (`/login/name`), and then exists. The page never says whether an
address has an account.
- The link never signs in on opening it (mail scanners open links): it
  shows a button. Opened in another browser than the one that asked (a
  `__Host-arcanum_signin` cookie tells), it says so — type the code there,
  or sign in here.
- `/signup`, `/verify`, `/reset` lead to `/login`. The `users.password_hash`
  column stays (no destructive migration) but nothing reads it; it was
  emptied by hand.

**Passkeys** are one more way into that same user (`src/passkeys.ts`,
verified with `@simplewebauthn/server`): fingerprint, face or the device's
PIN, no password, no e-mail to type. Nothing changes for the installations
— same `sub`, same claims.
- **Adding one:** on `/account` → *Passkey toevoegen*; and once after
  signing in another way (mailed code, Google), a page offers it
  (*Niet nu* = not asked again for 30 days; a browser without passkeys
  skips the page). The owner gets a mail whenever one is added.
- **Signing in:** *Aanmelden met een passkey* on the login page, or the
  browser's own suggestion in the e-mail field (`autocomplete="username
  webauthn"`). Discoverable credentials, so no e-mail is asked.
- **Relying party = the ISSUER's host** (`login.kaboutersoft.be`). A passkey
  only works there: changing that host would leave every passkey unusable
  (people fall back to a mailed code or Google).
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
created through the admin API (`/admin/clients`, bearer `ADMIN_API_KEY`,
only over the bootstrapper's service binding) — by the bootstrapper when it
sets up an installation, or by hand there for another application
(`/admin/installaties` → "Andere toepassing koppelen").

## Security notes

- **Sessions** on the issuer: `__Host-session` (until 2026-10
  `__Host-arcanum_auth`, still read; Secure, HttpOnly,
  SameSite=Lax, Path=/, no Domain — no sibling subdomain can plant one).
- **Form posts and the passkey JSON** only from this exact origin.
- **Mailed codes** (signing in): 6 digits, 5 tries per code, and per
  e-mail address at most 5 codes and 10 wrong tries an hour (across all its
  codes) — on top of the per-IP limits (10 codes an hour), so many IPs
  can't guess together. Code, link and the name step each work once.
- **What writes a row without anyone signed in** — a device code (per
  client), a Google sign-in's state and a passkey challenge (per IP) — is
  limited in memory (`PUBLIC_RATE_LIMITER`, 20 a minute), so it can't eat
  D1's daily write quota.
- **Google sign-in** finishes only in the browser that started it (its state
  in a `__Host-` cookie): no login CSRF.
- **The admin API** (`/admin/*`) only over a service binding (the
  bootstrapper's): a request from the internet (`CF-Connecting-IP`) gets a
  404, even with the right key.
- **HSTS** on every answer; a CSP and no framing on every page.
- **Turnstile** (Cloudflare's free bot check) on the sign-in form, when
  `TURNSTILE_SITE_KEY` and `TURNSTILE_SECRET` are set: no code is mailed
  without a passed check (verified server-side, this host, action `login`).
  If siteverify can't be reached the form goes through; the limits still
  apply. Every public form post that writes a row is first limited per IP
  in memory, before D1 sees it.
- **OAuth details (RFC 9700):** a code used twice revokes that user's
  refresh tokens for the client; every authorization response carries
  `iss` (RFC 9207); a refresh token used again after its 30-second grace
  revokes them all and mails the user. `/logout` without the app's own
  `id_token_hint` (for whoever is signed in; an expired one is fine) asks
  first - any page could send a browser there.
- **Security events**: one JSON line each in Workers Logs, `"event":
  "security"` - `refresh_reuse`, `code_reuse`, `turnstile_failed`,
  `login_limited`, `code_guesses_limited`, `rate_limited`, `admin`,
  `client_self`, `admin_from_internet`, `admin_signin_refused` (tools/admin, an address not on `ADMIN_EMAILS`), and once an hour (the cron)
  `protection_off` when Turnstile isn't set (`turnstile`), its keys are
  test keys or malformed (`turnstile_keys`), siteverify refuses its secret
  (`turnstile_secret`), mail is switched
  off (`mail_off`) or has no mailer or account (`mail_unset`). Search them in the dashboard
  (Workers → arcanum-auth → Logs); never a token or secret in them.
- **Passkey required** per client (its admins switch it on `/access/:id`,
  or the admin API's `require_passkey`): only a session made with a passkey
  gets a code or a device sign-in for it; someone without one adds their
  first on the spot. Sessions remember how they were made (`amr`: a mailed
  code, Google, a passkey), and the id_token says so (`amr`: `otp`, `fed`,
  or `hwk` + `mfa` for a passkey). Once someone has a passkey, adding or
  removing one - and managing a client that requires one - takes a passkey
  sign-in, so a mailbox alone can't swap them. All lost: a platform admin
  removes them (`DELETE /admin/users/:email/passkeys`), and the user is told.
- **Sessions** end after 7 days without use (14 at most). `/account` lists
  them (browser, since when, how), ends one, or signs out everywhere else -
  every application's refresh tokens included.
- **CI** (`.github/workflows/ci.yml`): typecheck, tests, `npm audit` of the
  deployed dependencies, Semgrep, and OWASP ZAP's passive baseline against
  a local copy (findings triaged in `.zap/rules.tsv`, each with its reason;
  anything new fails) - on every push and weekly. Dependabot proposes
  updates. Locally: `nerdctl run --rm -v "$PWD/.zap:/zap/wrk" ghcr.io/zaproxy/zaproxy:stable zap-baseline.py -t http://host.docker.internal:8788/login -c rules.tsv`
  against `npm run dev`.

## Restricted clients

Every client is **restricted** unless created with `restricted: false` (or
opened with `PATCH /admin/clients/:id`): only the people assigned to it can
sign in — every grant checks (`/authorize`, the device page, and the token
endpoint for a code, a refresh and a device code). Open on
login.kaboutersoft.be: the bootstrapper's own client and the demo instance's
(anyone may start there). Assignments are per client and **e-mail address**
(`client_access`, migration 0008), so an address can be assigned before it
has an account. Guests never get into a restricted client.

- **Someone asks** — without access, `/authorize` (or `/device`) shows "Request
  access"; the client's admins get a mail with a link to
  `/access/:clientId`, where they approve or refuse, remove people, make
  someone an admin, or add an address. Approved people get a mail (with the
  client's `instance_url`). Five requests per address a day; one nobody
  answered goes after 90 days.
- **The application assigns** — with its own id + secret,
  `/clients/self/users` (advertised as `client_users_endpoint` in
  discovery). Arcanum assigns whoever it invites and unassigns them when
  their last membership goes. Unassigning revokes the person's refresh
  tokens for that client; an access token runs out within the hour. An
  admin of the client is never unassigned by the application.
- **Its addresses** — `/access/:clientId` shows the host names of a
  client's redirect URIs (which installation it is) under its name, here
  and on `/account`. For an application's own client its admins edit the
  redirect and logout URIs there (https, 1–10, exact); every change mails
  the other admins. An installation's (`instance_url` set) are shown
  read-only: its installer keeps them up to date.
- **Admins** — the owner (`owner_email`) is a client's first admin; there is
  always at least one. `/account` links to the clients you manage. The
  application can name admins too (`role: "admin"` on `/clients/self/users`
  — Arcanum: whoever is an admin of one of its organisations) and take that
  back (`role: "member"`, or unassigning), but only for admins it made
  itself (`client_access.app_admin`, migration 0009): never the owner, and
  never someone an admin made admin or member on `/access/:clientId`. On an
  open client the application names no admins.

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
| `POST/GET /admin/clients`, `PATCH/DELETE /admin/clients/:id` | manage clients (bearer `ADMIN_API_KEY`); a client can carry `instance_url`, `owner_email`, `owner_sub`, `restricted` (default true); the list says each one's `last_used_at` (tokens handed out, at most hourly — migration 0010) and `active_users` (last 30 days). DELETE disables (`?by=` mails the owner when it's someone else); `?hard=1` deletes a disabled one for good |
| `POST /admin/guests` | a **guest** — a demo visitor without an account: no password, `guest-…@guest.invalid` (unverified), gone after `lifetime_hours` (default 5, max 24) |
| `POST /admin/login-links` | a **one-time sign-in link** for a guest (single use, 60 s) that continues to an address on an origin some client registered |
| `GET /login/once?token=…` | where that link leads: starts the guest's session, then continues |
| `GET/POST /access/:clientId`, `POST /access/:clientId/request` | a restricted client's admin page; asking for access (see Restricted clients) |
| `GET/POST /clients/self/users`, `PUT/DELETE /clients/self/users/:email` | who may use a restricted client, and who manages it (`role`) — the application itself, HTTP Basic with its id + secret (bulk: up to 500 `{ email, role? }`) |
| `GET/PATCH /clients/self`, `POST /clients/self/secret` | **client self-service** with the client's own id + secret (HTTP Basic): read/replace its redirect and logout URIs, rotate its secret — what an installation's installer uses after setting a custom domain |

## Deploy (Cloudflare, your account)

The admin API (clients, mail, passkey resets) only answers another Worker on
the same account - the bootstrapper on kaboutersoft's, **`tools/admin`**
(its README) from your laptop on any account. There you sign in with a
passkey if your address is in the variable **`ADMIN_EMAILS`**
(comma-separated); `ADMIN_API_KEY` stays the way back in.

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
   openssl rand -base64 32 | npx wrangler secret put CODE_HASH_KEY   # keys the mailed codes' hashes
   ```
   `CODE_HASH_KEY` keeps a copy of the database from giving away the
   6-digit codes (a plain hash of one of a million is reversed at once).
   Changing it only spoils the codes mailed in the last 15 minutes.
   Optional, for **Sign in with Google**: create an OAuth client ("Web
   application") in Google Cloud Console with redirect URI
   `https://login.kaboutersoft.be/callback/google`, then
   `npx wrangler secret put GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`.

   For **verification and reset mails** (without them, codes are only
   written to the Worker's log — `npx wrangler tail` — fine for testing, not
   for real users): `MAILER_INTERNAL_KEY` (the same value arcanum-platform-mailer has — see
   its README) and `MAIL_CONFIG` as JSON, either provider the mailer supports:
   - SMTP: `{"provider":"smtp","credentials":{"host":"…","port":465,"username":"…","password":"…","fromAddress":"noreply@kaboutersoft.be","fromName":"Arcanum"}}`
   - Gmail API (a Google service account with domain-wide delegation):
     `{"provider":"gmail_api","credentials":{"clientEmail":"…@….iam.gserviceaccount.com","privateKey":"-----BEGIN PRIVATE KEY-----\n…","impersonatedUser":"noreply@kaboutersoft.be","fromName":"Arcanum"}}`

   **No mail at all**: the var `MAIL_SENDING` = `off` (in `wrangler.jsonc`
   `vars`, or the dashboard) - every mail is only logged, whatever account
   is set, and the test mail answers `mail_off`. For an instance under an
   active security scan (ZAP) or a test instance: no mail credits burnt, no
   spam reputation. Its codes are in `npx wrangler tail`, so you can still
   sign in.

   login.kaboutersoft.be sends through **iCloud+ with the custom domain**
   (since 2026-10-06): SMTP `smtp.mail.me.com`, port 587 (STARTTLS), an
   app-specific password (appleid.apple.com). The username must be the
   primary **@icloud.com** address, not the Apple ID's own address
   (otherwise `550 5.1.1 Mailbox does not exist`); `fromAddress` can be any
   address of the custom domain. Set it without the password ever
   appearing on screen:

   ```sh
   user="…@icloud.com"; printf "App-specific password: "; read -rs pw; echo
   [ -n "$pw" ] && PW="$pw" U="$user" node -e 'process.stdout.write(JSON.stringify({provider:"smtp",credentials:{host:"smtp.mail.me.com",port:587,username:process.env.U,password:process.env.PW,fromAddress:"bert@kaboutersoft.be",fromName:"Arcanum"}}))' | npx wrangler secret put MAIL_CONFIG --name arcanum-auth
   unset pw
   ```

   (`MAIL_SMTP` with only the SMTP credentials still works.)

   **Or set it in the bootstrapper** (`/admin/e-mail`, platform admins):
   stored in this Worker's D1 (`settings`, migration 0006), encrypted with
   `SETTINGS_KEY` — 32 random bytes, base64; without it nothing is stored
   (`openssl rand -base64 32 | npx wrangler secret put SETTINGS_KEY --name
   arcanum-auth`). A stored account comes before `MAIL_CONFIG`; removing it
   there falls back to the secret. API: `/admin/mail` (GET, PUT, DELETE)
   and `/admin/mail/test`, with `ADMIN_API_KEY` (`src/admin.ts`).
   The `MAILER` service binding in `wrangler.jsonc` points at
   `arcanum-platform-mailer` on the same account (the platform's own, never an
   installation's arcanum-mailer); remove it if that Worker isn't there.
3. **Turnstile** (optional, recommended): Cloudflare dashboard → Turnstile →
   Add widget, hostname `login.kaboutersoft.be`, mode "Managed". Then
   `npx wrangler secret put TURNSTILE_SECRET` and
   `npx wrangler secret put TURNSTILE_SITE_KEY`. Both set: on.
4. **Deploy.** Push to `main` with Workers Builds connected, or
   `npx wrangler deploy`.

   **Checks before deploy:** in Workers Builds (Workers → arcanum-auth →
   Settings → Build), set the build command to `npm ci && npm run check` -
   typecheck, tests and `npm audit` of what's deployed. A push that fails
   them isn't deployed. `wrangler.jsonc` claims `login.kaboutersoft.be` as
   a custom domain (the `kaboutersoft.be` zone must be on the same account).
   `workers_dev` is off.

The issuer is `ISSUER` in `wrangler.jsonc`: `https://login.kaboutersoft.be`,
**no trailing slash**. Clients must be configured with exactly that string —
arcanum-bff compares the id_token's `iss` to it character for character.

## Another instance (another Cloudflare account)

Each extra instance is an env block in `wrangler.jsonc` (`env.<name>`): its
own Worker name, address (`ISSUER`), D1 database, rate limits and mail -
bindings and vars are not inherited from the top. Today: **`zap`**, the
target of an active ZAP scan at `https://arcanum-auth-zap.bertkaboutersoft.workers.dev`
(mail off, no Turnstile, no mailer on that account).

Setting one up, logged in to that account (`npx wrangler login`, `whoami`):

1. `npx wrangler d1 create arcanum-auth-<name>` → put its id in the block,
   push.
2. Secrets: `npm run generate-key | npx wrangler secret put SIGNING_KEY --env <name>`,
   `openssl rand -base64 32 | npx wrangler secret put CODE_HASH_KEY --env <name>`,
   `openssl rand -base64 32 | npx wrangler secret put ADMIN_API_KEY --env <name>`
   (keep it somewhere: the way back in), and `ADMIN_EMAILS` (your address).
   For real users also `SETTINGS_KEY`, mail and Turnstile, as above.
3. Workers & Pages → Create → Import a repository → `arcanum-pos/arcanum-auth`,
   deploy command `npx wrangler d1 migrations apply DB --remote --env <name> && npx wrangler deploy --env <name>`.
   Every push to main then deploys there too, migrations first.
4. Manage it with `tools/admin` (`--env <name>`): sign in with a passkey.

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
Create an account: open https://login.kaboutersoft.be/login, enter an
e-mail address, then the 6-digit code (from the mail, or `npx wrangler tail`
if no mailer is configured) and your name. You end on "Aangemeld als …".
Sign out and in again (the code alone now, or the link in the mail); try
"Aanmelden met Google".

**Authorization code flow**, with https://oidcdebugger.com as the client —
register it once in the bootstrapper: `/admin/installaties` → "Andere
toepassing koppelen", redirect URI `https://oidcdebugger.com/debug`. (The
admin API answers only the bootstrapper's service binding — a call from
the internet gets a 404, even with the right key.)
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
   with `tools/admin` running (the admin API doesn't answer from the
   internet); localhost may use http.
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

- **No passwords** — and so no password hashing on the Workers Free plan's
  10 ms of CPU either.
- **Rate limits**: 10 mails per IP and 5 per address per hour; 5 tries per
  mailed code, 10 wrong codes per address per hour; 20 wrong device codes
  per IP per quarter hour; and before any of these, 20 form posts a minute
  per IP in memory.
- **Not (yet) here**: an admin UI, account deletion, dynamic client
  registration, consent screens (every client is first-party).

## Rotating secrets

Every secret lives only as a Worker secret (`npx wrangler secret put …
--name arcanum-auth`); nothing is in the repo or `wrangler.jsonc`. Rotate
one when it may have leaked, and the signing key once a year anyway.

| Secret | Rotating it breaks | Steps |
|---|---|---|
| `SIGNING_KEY` | nothing, done this way | 1. `npm run generate-key --silent > new.json`. 2. The *current* key's public half (its JWK without `d`, `p`, `q`, `dp`, `dq`, `qi`) as a JSON array into `PREVIOUS_PUBLIC_KEYS`. 3. `npx wrangler secret put SIGNING_KEY < new.json`, then `rm new.json`. 4. After an hour (the longest token lifetime), `PREVIOUS_PUBLIC_KEYS` can go. Clients read the keys from the JWKS. |
| `CODE_HASH_KEY` | codes mailed in the last 15 minutes | `openssl rand -base64 32 \| npx wrangler secret put CODE_HASH_KEY` |
| `ADMIN_API_KEY` | the bootstrapper until it has the new one | new value here, then the same in the bootstrapper's secret |
| `SETTINGS_KEY` | the mail account stored from the bootstrapper | store it again at `/admin/e-mail` after the change |
| `GOOGLE_CLIENT_SECRET` | Google sign-in until both match | a new secret in Google Cloud Console, then here; delete the old one there |
| `TURNSTILE_SECRET` | the sign-in form until both match | rotate in the dashboard (Turnstile → widget → Rotate secret), then here |
| `MAILER_INTERNAL_KEY` | sign-in mails until both match | the same new value here and in arcanum-platform-mailer |
| a client's secret | that installation until its installer has it | the client rotates it itself: `POST /clients/self/secret` |


## Contributing and security

Bugs, questions and ideas: [issues](https://github.com/arcanum-pos/arcanum-auth/issues).
How to contribute (and the test policy): [CONTRIBUTING.md](CONTRIBUTING.md).
Security vulnerabilities: privately, see [SECURITY.md](SECURITY.md).

## License

AGPL-3.0-or-later — see [LICENSE](LICENSE).
