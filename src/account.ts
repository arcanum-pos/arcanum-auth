import { decodeJwt as decodeJwtPayload } from 'jose';
import type { Env } from './env';
import { sendMail } from './mail';
import { codePage, deviceCodePage, deviceConfirmPage, linkPage, loginPage, messagePage, namePage, texts } from './pages';
import { accountWithPasskeys, shouldOfferPasskey } from './passkeys';
import { clientById, clientIp, cookieValue, createSession, createUser, currentSession, recordAttempt, tooManyAttempts, userByEmail, type User } from './store';
import {
  codeHash,
  inSeconds,
  isEmail,
  newEmailCode,
  normalizeEmail,
  normalizeUserCode,
  nowIso,
  randomToken,
  readForm,
  redirect,
  safeContinue,
  sameOrigin,
  sha256,
  timingSafeEqual,
  unixNow,
} from './util';

const EMAIL_CODE_SECONDS = 900;
const MAX_CODE_TRIES = 5;
// Per e-mail address, per hour: wrong codes (all its codes together), and codes asked.
const MAX_CODE_TRIES_PER_ADDRESS = 10;
const MAX_CODES_PER_ADDRESS = 5;
const googleEnabled = (env: Env) => !!(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET);

// Signed in with a mailed code or Google: on to `continueTo` —
// by way of the offer to add a passkey, when that's due (passkeys.ts).
async function signIn(env: Env, user: User, continueTo: string): Promise<Response> {
  const cookie = await createSession(env, user.id, unixNow());
  const next = safeContinue(continueTo);
  const offer = await shouldOfferPasskey(env, user);
  return redirect(offer ? `/passkey/offer?continue=${encodeURIComponent(next)}` : next, { 'Set-Cookie': cookie });
}

// A form post from anywhere but these pages is refused (CSRF).
function refuseForeign(request: Request, env: Env): Response | null {
  return sameOrigin(request, env.ISSUER) ? null : messagePage(request, texts(request).errors.request, 403);
}

// --- Sign in with a mailed code (no passwords). One flow for signing in
// and signing up: the address gets a 6-digit code and a link (15 minutes);
// the code typed here, or the link's button, signs in — an address without
// an account first answers one question (its name). The page never says
// whether an address has an account.

const SIGNIN_COOKIE = '__Host-signin';

interface EmailCodeRow {
  id: string;
  purpose: 'login';
  email: string;
  code_hash: string;
  attempts: number;
  expires_at: string;
  used_at: string | null;
  continue_to: string | null;
  link_hash: string | null;
  browser_hash: string | null;
  finish_hash: string | null;
}

const codeRow = (env: Env, id: string) => env.DB.prepare("SELECT * FROM email_codes WHERE id = ? AND purpose = 'login'").bind(id).first<EmailCodeRow>();

export async function login(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (request.method === 'GET') return loginPage(request, { continueTo: safeContinue(url.searchParams.get('continue')), google: googleEnabled(env) });
  const foreign = refuseForeign(request, env);
  if (foreign) return foreign;

  const form = await readForm(request);
  const continueTo = safeContinue(form.continue);
  const email = normalizeEmail(form.email || '');
  const again = (error: 'emailInvalid' | 'tooMany' | 'mail', status: number) => loginPage(request, { continueTo, email, error, google: googleEnabled(env) }, status);
  if (!isEmail(email)) return again('emailInvalid', 400);
  // Per IP and per address — whether or not it has an account (no enumeration).
  const ipKey = `mail-ip:${clientIp(request)}`;
  const addressKey = `mail-email:${email}`;
  if ((await tooManyAttempts(env, ipKey, 10, 3600)) || (await tooManyAttempts(env, addressKey, MAX_CODES_PER_ADDRESS, 3600))) return again('tooMany', 429);
  await recordAttempt(env, ipKey);
  await recordAttempt(env, addressKey);

  const id = randomToken(16);
  const code = newEmailCode();
  const linkToken = randomToken(24);
  // The browser that asked: the link signs in directly there, and says
  // "another device?" elsewhere.
  const browser = randomToken(24);
  await env.DB.prepare(
    `INSERT INTO email_codes (id, purpose, email, code_hash, link_hash, browser_hash, continue_to, expires_at) VALUES (?, 'login', ?, ?, ?, ?, ?, ?)`
  )
    .bind(id, email, await codeHash(env.CODE_HASH_KEY, code), await sha256(linkToken), await sha256(browser), continueTo, inSeconds(EMAIL_CODE_SECONDS))
    .run();
  const t = texts(request);
  try {
    await sendMail(env, email, t.mailCodeSubject, t.mailCode(code, `${env.ISSUER}/login/link?id=${id}&t=${linkToken}`));
  } catch (err) {
    console.error('sign-in mail failed', err);
    return again('mail', 502);
  }
  return redirect(`/login/code?id=${id}`, { 'Set-Cookie': `${SIGNIN_COOKIE}=${browser}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${EMAIL_CODE_SECONDS}` });
}

// A mailed code: right, not expired, not used, fewer than MAX_CODE_TRIES wrong
// — and, per e-mail address across all its codes, fewer than
// MAX_CODE_TRIES_PER_ADDRESS wrong in an hour. Per code alone, an attacker
// with many IP addresses could ask many codes for one address and guess on each.
async function checkEmailCode(env: Env, id: string, code: string): Promise<EmailCodeRow | 'invalid' | 'unknown'> {
  const row = await codeRow(env, id);
  if (!row || row.used_at || row.expires_at <= nowIso() || row.attempts >= MAX_CODE_TRIES) return 'unknown';
  const addressKey = `code-email:${row.email}`;
  if (await tooManyAttempts(env, addressKey, MAX_CODE_TRIES_PER_ADDRESS, 3600)) return 'unknown';
  if (!timingSafeEqual(await codeHash(env.CODE_HASH_KEY, code.trim()), row.code_hash)) {
    await env.DB.prepare('UPDATE email_codes SET attempts = attempts + 1 WHERE id = ?').bind(id).run();
    await recordAttempt(env, addressKey);
    return 'invalid';
  }
  const claimed = await env.DB.prepare('UPDATE email_codes SET used_at = ? WHERE id = ? AND used_at IS NULL').bind(nowIso(), id).run();
  return claimed.meta.changes ? row : 'unknown';
}

export async function loginCode(request: Request, env: Env): Promise<Response> {
  if (request.method === 'GET') {
    const row = await codeRow(env, new URL(request.url).searchParams.get('id') || '');
    if (!row || row.used_at || row.expires_at <= nowIso()) return redirect('/login');
    return codePage(request, { id: row.id, email: row.email, continueTo: safeContinue(row.continue_to) });
  }
  const foreign = refuseForeign(request, env);
  if (foreign) return foreign;
  const form = await readForm(request);
  const result = await checkEmailCode(env, form.id || '', form.code || '');
  if (typeof result === 'string') {
    const row = await codeRow(env, form.id || '');
    return row ? codePage(request, { id: row.id, email: row.email, continueTo: safeContinue(row.continue_to), error: 'codeInvalid' }, 400) : messagePage(request, texts(request).errors.codeInvalid, 400);
  }
  return proven(request, env, result);
}

// The link in the mail: GET shows a button (mail scanners open links), the
// button's POST signs in.
export async function loginLink(request: Request, env: Env): Promise<Response> {
  const t = texts(request);
  if (request.method === 'GET') {
    const p = new URL(request.url).searchParams;
    const row = await codeRow(env, p.get('id') || '');
    const valid = !!row && !row.used_at && row.expires_at > nowIso() && !!row.link_hash && timingSafeEqual(await sha256(p.get('t') || ''), row.link_hash);
    if (!row || !valid) return messagePage(request, t.errors.linkInvalid, 400);
    const browser = cookieValue(request, SIGNIN_COOKIE);
    const sameBrowser = !!browser && !!row.browser_hash && timingSafeEqual(await sha256(browser), row.browser_hash);
    return linkPage(request, { id: row.id, token: p.get('t')!, email: row.email, sameBrowser });
  }
  const foreign = refuseForeign(request, env);
  if (foreign) return foreign;
  const form = await readForm(request);
  const claimed = await env.DB.prepare("UPDATE email_codes SET used_at = ? WHERE id = ? AND purpose = 'login' AND used_at IS NULL AND expires_at > ? AND link_hash = ?")
    .bind(nowIso(), form.id || '', nowIso(), await sha256(form.t || ''))
    .run();
  const row = claimed.meta.changes ? await codeRow(env, form.id) : null;
  if (!row) return messagePage(request, t.errors.linkInvalid, 400);
  return proven(request, env, row);
}

// The address is proven (code or link): sign in — or, for an address
// without an account, ask its name first.
async function proven(request: Request, env: Env, row: EmailCodeRow): Promise<Response> {
  const continueTo = safeContinue(row.continue_to);
  const user = await userByEmail(env, row.email);
  if (user) {
    if (!user.email_verified) await env.DB.prepare('UPDATE users SET email_verified = 1, updated_at = ? WHERE id = ?').bind(nowIso(), user.id).run();
    return signIn(env, user, continueTo);
  }
  const finish = randomToken(24);
  await env.DB.prepare('UPDATE email_codes SET finish_hash = ? WHERE id = ?').bind(await sha256(finish), row.id).run();
  return namePage(request, { id: row.id, finish, email: row.email });
}

export async function loginName(request: Request, env: Env): Promise<Response> {
  const foreign = refuseForeign(request, env);
  if (foreign) return foreign;
  const form = await readForm(request);
  const row = await codeRow(env, form.id || '');
  const valid = !!row && !!row.used_at && row.expires_at > nowIso() && !!row.finish_hash && timingSafeEqual(await sha256(form.finish || ''), row.finish_hash);
  if (!row || !valid) return messagePage(request, texts(request).errors.codeInvalid, 400);
  const name = (form.name || '').trim().slice(0, 100);
  if (!name) return namePage(request, { id: row.id, finish: form.finish, email: row.email, error: 'nameMissing' }, 400);
  // Once: the finishing token is spent with the account's creation.
  const spent = await env.DB.prepare('UPDATE email_codes SET finish_hash = NULL WHERE id = ? AND finish_hash = ?').bind(row.id, row.finish_hash).run();
  if (!spent.meta.changes) return messagePage(request, texts(request).errors.codeInvalid, 400);
  // Signed up another way (Google) in the meantime: that account.
  const user = (await userByEmail(env, row.email)) ?? (await createUser(env, { email: row.email, name }));
  return signIn(env, user, safeContinue(row.continue_to));
}

// --- Sign in with Google (OpenID Connect, code flow + PKCE).

const GOOGLE_AUTH = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN = 'https://oauth2.googleapis.com/token';
const GOOGLE_STATE_COOKIE = '__Host-google_state';

export async function googleStart(request: Request, env: Env): Promise<Response> {
  if (!googleEnabled(env)) return messagePage(request, texts(request).errors.google, 404);
  const continueTo = safeContinue(new URL(request.url).searchParams.get('continue'));
  const state = randomToken(24);
  const verifier = randomToken(48);
  await env.DB.prepare('INSERT INTO oauth_states (state_hash, code_verifier, continue_to, expires_at) VALUES (?, ?, ?, ?)')
    .bind(await sha256(state), verifier, continueTo, inSeconds(600))
    .run();
  const target = new URL(GOOGLE_AUTH);
  const cookie = `${GOOGLE_STATE_COOKIE}=${state}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;
  target.search = new URLSearchParams({
    client_id: env.GOOGLE_CLIENT_ID!,
    redirect_uri: `${env.ISSUER}/callback/google`,
    response_type: 'code',
    scope: 'openid email profile',
    state,
    code_challenge: await sha256(verifier),
    code_challenge_method: 'S256',
    prompt: 'select_account',
  }).toString();
  return redirect(target.toString(), { 'Set-Cookie': cookie });
}

export async function googleCallback(request: Request, env: Env): Promise<Response> {
  const t = texts(request);
  const p = new URL(request.url).searchParams;
  // Only the browser that started this Google sign-in may finish it (its
  // cookie names that state) — else someone's callback link would sign a
  // victim in as them (login CSRF). The cookie is spent either way.
  const browserState = cookieValue(request, GOOGLE_STATE_COOKIE);
  const fromThisBrowser = !!browserState && timingSafeEqual(browserState, p.get('state') || '');
  const stateHash = await sha256(p.get('state') || '');
  const saved = await env.DB.prepare('SELECT * FROM oauth_states WHERE state_hash = ? AND expires_at > ?')
    .bind(stateHash, nowIso())
    .first<{ code_verifier: string; continue_to: string }>();
  await env.DB.prepare('DELETE FROM oauth_states WHERE state_hash = ?').bind(stateHash).run();
  const spent = { 'Set-Cookie': `${GOOGLE_STATE_COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0` };
  if (!saved || !fromThisBrowser || !p.get('code') || !googleEnabled(env)) return messagePage(request, t.errors.google, 400, spent);

  const res = await fetch(env.GOOGLE_TOKEN_URL || GOOGLE_TOKEN, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code',
      code: p.get('code')!,
      redirect_uri: `${env.ISSUER}/callback/google`,
      client_id: env.GOOGLE_CLIENT_ID!,
      client_secret: env.GOOGLE_CLIENT_SECRET!,
      code_verifier: saved.code_verifier,
    }),
  });
  const body = (await res.json().catch(() => null)) as { id_token?: string } | null;
  // Straight from Google's token endpoint over TLS, so its id_token can be
  // read without a signature check (OIDC Core §3.1.3.7); iss/aud still checked.
  const claims = body?.id_token ? safeDecode(body.id_token) : null;
  const issuerOk = claims && (claims.iss === 'https://accounts.google.com' || claims.iss === 'accounts.google.com');
  if (!res.ok || !claims || !issuerOk || claims.aud !== env.GOOGLE_CLIENT_ID || typeof claims.sub !== 'string') {
    return messagePage(request, t.errors.google, 400);
  }
  if (claims.email_verified !== true || typeof claims.email !== 'string') return messagePage(request, t.errors.googleUnverified, 400);

  const email = normalizeEmail(claims.email);
  let user = await env.DB.prepare('SELECT * FROM users WHERE google_sub = ?').bind(claims.sub).first<User>();
  if (!user) {
    // Same verified address as a password account → the same person, same sub.
    const byEmail = await userByEmail(env, email);
    if (byEmail) {
      await env.DB.prepare('UPDATE users SET google_sub = ?, email_verified = 1, updated_at = ? WHERE id = ?').bind(claims.sub, nowIso(), byEmail.id).run();
      user = byEmail;
      // Told, like a new passkey: from now on this Google account opens it too.
      await sendMail(env, user.email, t.mailGoogleLinkedSubject, t.mailGoogleLinked(`${env.ISSUER}/account`)).catch((err) => console.error('google-linked mail failed', err));
    } else {
      user = await createUser(env, { email, name: typeof claims.name === 'string' ? claims.name : email.split('@')[0], googleSub: claims.sub });
    }
  }
  return signIn(env, user, saved.continue_to);
}

function safeDecode(token: string): Record<string, unknown> | null {
  try {
    return decodeJwtPayload(token);
  } catch {
    return null;
  }
}

// --- The device-code approval pages (verification_uri).

interface PendingDevice {
  user_code: string;
  client_id: string;
  status: string;
  expires_at: string;
}

async function pendingDevice(env: Env, userCode: string): Promise<PendingDevice | null> {
  if (!userCode) return null;
  const row = await env.DB.prepare('SELECT user_code, client_id, status, expires_at FROM device_codes WHERE user_code = ?').bind(userCode).first<PendingDevice>();
  return row && row.status === 'pending' && row.expires_at > nowIso() ? row : null;
}

export async function devicePage(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const session = await currentSession(env, request);
  if (request.method === 'GET') {
    const userCode = normalizeUserCode(url.searchParams.get('user_code') || '');
    if (!session) return redirect(`/login?continue=${encodeURIComponent(url.pathname + url.search)}`);
    const pending = await pendingDevice(env, userCode);
    const client = pending ? await clientById(env, pending.client_id) : null;
    if (pending && client) return deviceConfirmPage(request, { userCode, clientName: client.name, email: session.user.email });
    return deviceCodePage(request, { userCode: url.searchParams.get('user_code') || '', error: userCode ? 'deviceCode' : null });
  }
  const foreign = refuseForeign(request, env);
  if (foreign) return foreign;
  if (!session) return redirect('/login?continue=%2Fdevice');
  const form = await readForm(request);
  const ipKey = `device-ip:${clientIp(request)}`;
  if (await tooManyAttempts(env, ipKey, 20)) return deviceCodePage(request, { userCode: form.user_code, error: 'tooMany' }, 429);
  const userCode = normalizeUserCode(form.user_code || '');
  const pending = await pendingDevice(env, userCode);
  const client = pending ? await clientById(env, pending.client_id) : null;
  if (!pending || !client) {
    await recordAttempt(env, ipKey);
    return deviceCodePage(request, { userCode: form.user_code, error: 'deviceCode' }, 400);
  }
  return deviceConfirmPage(request, { userCode, clientName: client.name, email: session.user.email });
}

export async function deviceConfirm(request: Request, env: Env): Promise<Response> {
  const foreign = refuseForeign(request, env);
  if (foreign) return foreign;
  const t = texts(request);
  const session = await currentSession(env, request);
  if (!session) return redirect('/login?continue=%2Fdevice');
  const form = await readForm(request);
  const userCode = normalizeUserCode(form.user_code || '');
  const allow = form.decision === 'allow';
  const done = await env.DB.prepare(
    "UPDATE device_codes SET status = ?, user_id = ?, auth_time = ? WHERE user_code = ? AND status = 'pending' AND expires_at > ?"
  )
    .bind(allow ? 'approved' : 'denied', session.user.id, session.authTime, userCode, nowIso())
    .run();
  if (!done.meta.changes) return deviceCodePage(request, { error: 'deviceCode' }, 400);
  return messagePage(request, allow ? t.deviceDone : t.deviceDenied);
}

// A one-time sign-in link (POST /admin/login-links): a guest's session, then
// on to where the bootstrapper said (an origin a client registered).
export async function loginOnce(request: Request, env: Env): Promise<Response> {
  const token = new URL(request.url).searchParams.get('token') || '';
  const hash = await sha256(token);
  const claimed = await env.DB.prepare('UPDATE login_links SET used_at = ? WHERE token_hash = ? AND used_at IS NULL AND expires_at > ?')
    .bind(nowIso(), hash, nowIso())
    .run();
  const link = claimed.meta.changes
    ? await env.DB.prepare('SELECT user_id, continue_to FROM login_links WHERE token_hash = ?').bind(hash).first<{ user_id: string; continue_to: string }>()
    : null;
  const user = link ? await env.DB.prepare('SELECT * FROM users WHERE id = ? AND guest = 1 AND expires_at > ?').bind(link.user_id, nowIso()).first<User>() : null;
  if (!link || !user) return messagePage(request, texts(request).errors.linkInvalid, 400);
  const cookie = await createSession(env, user.id, unixNow(), user.expires_at);
  return redirect(link.continue_to, { 'Set-Cookie': cookie });
}

export async function account(request: Request, env: Env): Promise<Response> {
  const session = await currentSession(env, request);
  if (!session) return redirect('/login?continue=%2Faccount');
  return accountWithPasskeys(request, env, session.user, { added: new URL(request.url).searchParams.get('passkey') === 'added' });
}
