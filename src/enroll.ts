// Enrollment (2026-11-02): an application gets its new user a first passkey
// without a code mailed into a mailbox they can't open yet — a mail
// installation's new account. The application vouches for the address; only
// for the domains a platform admin listed for it (clients.enroll_domains),
// whose mail it receives itself: it can already read the codes mailed there,
// so vouching gives it nothing it doesn't have.
//
//   POST /clients/self/users/:email/enrollment  { name?, continue_to, reset? } (client credentials, clients.ts)
//        → 201 { url, expires_in }; asked at the moment the user clicks, the
//          application sends their browser straight there
//   GET  /enroll?ticket=…   opens it: once, within two minutes; from then on
//                           only this browser (a cookie), for ten minutes
//   GET  /enroll            the page: create your passkey — nothing else on offer
//   POST /enroll/options    → options for navigator.credentials.create
//   POST /enroll            the passkey → { redirect: continue_to } + a session made with it
//
// The link signs in to nothing: the only session is the one the new passkey
// makes. Only for an address assigned to the client, and only while its
// account has no way in (no passkey, no Google) — except `reset`, for a
// client a platform admin allowed it (enroll_reset): the account starts
// over (passkeys, Google link, sessions and refresh tokens go) and is told
// by mail. continue_to: this client's own /authorize request.
import type { RegistrationResponseJSON } from '@simplewebauthn/server';
import { accessRow } from './access';
import { securityEvent } from './audit';
import type { Env } from './env';
import { sendMail } from './mail';
import { enrollPage, messagePage, texts } from './pages';
import { body, fail, jsonFromHere, passkeysOf, registrationOptions, storePasskey, verifiedRegistration } from './passkeys';
import { clientById, clientIp, cookieValue, createSession, createUser, recordAttempt, tooManyAttempts, userByEmail, type Client, type User } from './store';
import { inSeconds, json, nowIso, randomToken, redirect, sha256, unixNow } from './util';

const OPEN_SECONDS = 120;
const FINISH_SECONDS = 600;
const ENROLL_COOKIE = '__Host-enroll';
// Per client, per hour: links asked (a stolen secret can't mint them in bulk).
const MAX_PER_CLIENT = 30;
const MAX_PER_ADDRESS = 5;

interface EnrollmentRow {
  token_hash: string;
  client_id: string;
  email: string;
  name: string;
  user_id: string;
  continue_to: string;
  reset: number;
  expires_at: string;
  browser_hash: string | null;
  opened_until: string | null;
  used_at: string | null;
}

export const domainOf = (email: string) => email.slice(email.lastIndexOf('@') + 1);

// A way in already: a passkey or Google. (A mailed code doesn't count: for
// these addresses the application receives it anyway.)
async function hasWayIn(env: Env, user: User): Promise<boolean> {
  return !!user.google_sub || (await passkeysOf(env, user.id)).length > 0;
}

// May this client enroll this address now? null: yes; else why not.
async function refusal(env: Env, client: Client, email: string, reset: boolean): Promise<string | null> {
  if (!client.enroll_domains.includes(domainOf(email))) return 'not_allowed';
  if (reset && !client.enroll_reset) return 'reset_not_allowed';
  if ((await accessRow(env, client.id, email))?.status !== 'assigned') return 'not_assigned';
  const user = await userByEmail(env, email);
  if (user?.guest) return 'not_allowed';
  if (user && !reset && (await hasWayIn(env, user))) return 'enrolled';
  return null;
}

// Its own /authorize request, relative (safeContinue): nowhere else.
function ownAuthorize(client: Client, value: unknown): string | null {
  if (typeof value !== 'string' || !value.startsWith('/authorize?')) return null;
  const params = new URLSearchParams(value.slice('/authorize?'.length));
  return params.get('client_id') === client.id && client.redirect_uris.includes(params.get('redirect_uri') || '') ? value : null;
}

export async function createEnrollment(request: Request, env: Env, client: Client, email: string): Promise<Response> {
  const given = (await request.json().catch(() => null)) as { name?: unknown; continue_to?: unknown; reset?: unknown } | null;
  const continueTo = ownAuthorize(client, given?.continue_to);
  if (!continueTo) return json({ error: "continue_to must be this client's own /authorize request (a path: /authorize?client_id=…&redirect_uri=…)" }, 400);
  if (given?.reset !== undefined && typeof given.reset !== 'boolean') return json({ error: 'reset must be true or false' }, 400);
  const reset = given?.reset === true;
  const why = await refusal(env, client, email, reset);
  if (why) {
    securityEvent('enrollment_refused', { client: client.id, email, reason: why });
    return json({ error: why }, why === 'enrolled' ? 409 : 403);
  }
  const clientKey = `enroll-client:${client.id}`;
  const addressKey = `enroll-email:${email}`;
  if ((await tooManyAttempts(env, clientKey, MAX_PER_CLIENT, 3600)) || (await tooManyAttempts(env, addressKey, MAX_PER_ADDRESS, 3600))) {
    securityEvent('enrollment_limited', { client: client.id, email });
    return json({ error: 'too_many' }, 429);
  }
  await recordAttempt(env, clientKey);
  await recordAttempt(env, addressKey);

  const user = await userByEmail(env, email);
  const name = (typeof given?.name === 'string' ? given.name.trim().slice(0, 100) : '') || user?.name || email;
  const token = randomToken(32);
  const now = nowIso();
  await env.DB.batch([
    // Only the newest one works.
    env.DB.prepare('UPDATE enrollments SET used_at = ? WHERE email = ? AND used_at IS NULL').bind(now, email),
    env.DB.prepare(
      'INSERT INTO enrollments (token_hash, client_id, email, name, user_id, continue_to, reset, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).bind(await sha256(token), client.id, email, name, user?.id ?? crypto.randomUUID(), continueTo, reset ? 1 : 0, now, inSeconds(OPEN_SECONDS)),
  ]);
  securityEvent('enrollment_created', { client: client.id, email, reset, ip: clientIp(request) });
  return json({ url: `${env.ISSUER}/enroll?ticket=${encodeURIComponent(token)}`, expires_in: OPEN_SECONDS }, 201);
}

// This browser's enrollment: opened here, not finished, still in time.
async function opened(env: Env, request: Request): Promise<EnrollmentRow | null> {
  const browser = cookieValue(request, ENROLL_COOKIE);
  if (!browser) return null;
  return env.DB.prepare('SELECT * FROM enrollments WHERE browser_hash = ? AND used_at IS NULL AND opened_until > ?').bind(await sha256(browser), nowIso()).first<EnrollmentRow>();
}

export async function enroll(request: Request, env: Env): Promise<Response> {
  const t = texts(request);
  if (request.method === 'GET') {
    const ticket = new URL(request.url).searchParams.get('ticket');
    if (ticket) {
      // Spent by opening it: from here on it's this browser's cookie, not the link.
      const browser = randomToken(24);
      const claimed = await env.DB.prepare('UPDATE enrollments SET browser_hash = ?, opened_until = ? WHERE token_hash = ? AND browser_hash IS NULL AND used_at IS NULL AND expires_at > ?')
        .bind(await sha256(browser), inSeconds(FINISH_SECONDS), await sha256(ticket), nowIso())
        .run();
      if (!claimed.meta.changes) return messagePage(request, t.errors.enrollInvalid, 400);
      return redirect('/enroll', { 'Set-Cookie': `${ENROLL_COOKIE}=${browser}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${FINISH_SECONDS}` });
    }
    const row = await opened(env, request);
    const client = row ? await clientById(env, row.client_id) : null;
    if (!row || !client) return messagePage(request, t.errors.enrollInvalid, 400);
    return enrollPage(request, { email: row.email, clientName: client.name });
  }

  // POST: the new passkey.
  if (!jsonFromHere(request, env)) return fail(request, 'request', 403);
  const row = await opened(env, request);
  if (!row) return fail(request, 'enrollInvalid', 400);
  const b = await body(request);
  const response = b.response as RegistrationResponseJSON | undefined;
  if (!response?.response?.clientDataJSON) return fail(request, 'request', 400);
  const verified = await verifiedRegistration(env, 'enroll', row.user_id, response);
  if ('error' in verified) return fail(request, verified.error, verified.status);

  // Still allowed (the client, its domains, the assignment, the account may
  // have changed meanwhile) — then spent, once.
  const client = await clientById(env, row.client_id);
  if (!client || (await refusal(env, client, row.email, !!row.reset))) return fail(request, 'enrollInvalid', 400);
  const spent = await env.DB.prepare('UPDATE enrollments SET used_at = ? WHERE token_hash = ? AND used_at IS NULL').bind(nowIso(), row.token_hash).run();
  if (!spent.meta.changes) return fail(request, 'enrollInvalid', 400);

  let user = await userByEmail(env, row.email);
  // Signed up another way in between: the passkey was made for the id we planned.
  if (user && user.id !== row.user_id) return fail(request, 'enrollInvalid', 400);
  if (!user) user = await createUser(env, { email: row.email, name: row.name, id: row.user_id });
  if (row.reset) {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM passkeys WHERE user_id = ?').bind(user.id),
      env.DB.prepare('UPDATE users SET google_sub = NULL, updated_at = ? WHERE id = ?').bind(nowIso(), user.id),
      env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
      env.DB.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').bind(nowIso(), user.id),
    ]);
  }
  const name = await storePasskey(request, env, user.id, verified, b.name);
  const cookie = await createSession(env, user.id, unixNow(), { amr: 'passkey', request });
  securityEvent('enrollment_done', { client: client.id, email: row.email, reset: !!row.reset });
  const mail = row.reset
    ? sendMail(env, user.email, t.mailSignInResetSubject, t.mailSignInReset(client.name, `${env.ISSUER}/account`))
    : sendMail(env, user.email, t.mailPasskeySubject, t.mailPasskey(name, `${env.ISSUER}/account`));
  await mail.catch((err) => console.error('enrollment mail failed', err));
  return json({ redirect: row.continue_to }, 200, { 'Set-Cookie': cookie });
}

export async function enrollOptions(request: Request, env: Env): Promise<Response> {
  if (!jsonFromHere(request, env)) return fail(request, 'request', 403);
  const row = await opened(env, request);
  if (!row) return fail(request, 'enrollInvalid', 400);
  return json(await registrationOptions(env, 'enroll', { id: row.user_id, email: row.email, name: row.name }));
}
