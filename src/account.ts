import { decodeJwt as decodeJwtPayload } from 'jose';
import type { Env } from './env';
import { sendMail } from './mail';
import {
  accountPage,
  deviceCodePage,
  deviceConfirmPage,
  loginPage,
  messagePage,
  resetCodePage,
  resetRequestPage,
  signupPage,
  texts,
  verifyPage,
} from './pages';
import { clientById, clientIp, createSession, createUser, currentSession, recordAttempt, tooManyAttempts, userByEmail, type User } from './store';
import {
  hashPassword,
  inSeconds,
  isEmail,
  iterations,
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
  verifyPassword,
} from './util';

const EMAIL_CODE_SECONDS = 900;
const MAX_CODE_TRIES = 5;
const googleEnabled = (env: Env) => !!(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET);

async function signIn(env: Env, user: User, continueTo: string): Promise<Response> {
  const cookie = await createSession(env, user.id, unixNow());
  return redirect(safeContinue(continueTo), { 'Set-Cookie': cookie });
}

// A form post from anywhere but these pages is refused (CSRF).
function refuseForeign(request: Request, env: Env): Response | null {
  return sameOrigin(request, env.ISSUER) ? null : messagePage(request, texts(request).errors.request, 403);
}

// --- Sign in with e-mail + password.

export async function login(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (request.method === 'GET') return loginPage(request, { continueTo: safeContinue(url.searchParams.get('continue')), google: googleEnabled(env) });
  const foreign = refuseForeign(request, env);
  if (foreign) return foreign;

  const form = await readForm(request);
  const continueTo = safeContinue(form.continue);
  const email = normalizeEmail(form.email || '');
  const again = (error: 'invalid' | 'tooMany') => loginPage(request, { continueTo, email, error, google: googleEnabled(env) }, error === 'tooMany' ? 429 : 401);

  const ipKey = `login-ip:${clientIp(request)}`;
  const emailKey = `login-email:${email}`;
  if ((await tooManyAttempts(env, emailKey, 10)) || (await tooManyAttempts(env, ipKey, 30))) return again('tooMany');

  const user = await userByEmail(env, email);
  const ok = !!user?.password_hash && (await verifyPassword(form.password || '', user.password_hash));
  if (!user || !ok) {
    await recordAttempt(env, emailKey);
    await recordAttempt(env, ipKey);
    return again('invalid');
  }
  return signIn(env, user, continueTo);
}

// --- Create an account: the name + password wait in email_codes until the
// address is proven with the mailed code.

export async function signup(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (request.method === 'GET') return signupPage(request, { continueTo: safeContinue(url.searchParams.get('continue')), google: googleEnabled(env) });
  const foreign = refuseForeign(request, env);
  if (foreign) return foreign;

  const form = await readForm(request);
  const continueTo = safeContinue(form.continue);
  const email = normalizeEmail(form.email || '');
  const name = (form.name || '').trim().slice(0, 100);
  const again = (error: 'emailInvalid' | 'passwordShort' | 'exists' | 'tooMany' | 'mail') =>
    signupPage(request, { continueTo, email, name, error, google: googleEnabled(env) }, 400);

  if (!isEmail(email)) return again('emailInvalid');
  if ((form.password || '').length < 10) return again('passwordShort');
  if (await userByEmail(env, email)) return again('exists');
  const ipKey = `mail-ip:${clientIp(request)}`;
  if (await tooManyAttempts(env, ipKey, 10, 3600)) return again('tooMany');

  const t = texts(request);
  const code = newEmailCode();
  const id = randomToken(16);
  await env.DB.prepare(
    `INSERT INTO email_codes (id, purpose, email, code_hash, pending_name, pending_password_hash, expires_at) VALUES (?, 'signup', ?, ?, ?, ?, ?)`
  )
    .bind(id, email, await sha256(code), name || email.split('@')[0], await hashPassword(form.password, iterations(env)), inSeconds(EMAIL_CODE_SECONDS))
    .run();
  await recordAttempt(env, ipKey);
  try {
    await sendMail(env, email, t.mailSignupSubject, t.mailSignup(code));
  } catch (err) {
    console.error('signup mail failed', err);
    return again('mail');
  }
  return redirect(`/verify?id=${id}&continue=${encodeURIComponent(continueTo)}`);
}

interface EmailCodeRow {
  id: string;
  purpose: 'signup' | 'reset';
  email: string;
  code_hash: string;
  pending_name: string | null;
  pending_password_hash: string | null;
  attempts: number;
  expires_at: string;
  used_at: string | null;
}

// A mailed code: right, not expired, not used, fewer than MAX_CODE_TRIES wrong.
async function checkEmailCode(env: Env, id: string, purpose: 'signup' | 'reset', code: string): Promise<EmailCodeRow | 'invalid' | 'unknown'> {
  const row = await env.DB.prepare('SELECT * FROM email_codes WHERE id = ? AND purpose = ?').bind(id, purpose).first<EmailCodeRow>();
  if (!row || row.used_at || row.expires_at <= nowIso() || row.attempts >= MAX_CODE_TRIES) return 'unknown';
  if (!timingSafeEqual(await sha256(code.trim()), row.code_hash)) {
    await env.DB.prepare('UPDATE email_codes SET attempts = attempts + 1 WHERE id = ?').bind(id).run();
    return 'invalid';
  }
  const claimed = await env.DB.prepare('UPDATE email_codes SET used_at = ? WHERE id = ? AND used_at IS NULL').bind(nowIso(), id).run();
  return claimed.meta.changes ? row : 'unknown';
}

export async function verify(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const lookup = (id: string) => env.DB.prepare("SELECT email FROM email_codes WHERE id = ? AND purpose = 'signup'").bind(id).first<{ email: string }>();
  if (request.method === 'GET') {
    const id = url.searchParams.get('id') || '';
    const row = await lookup(id);
    if (!row) return messagePage(request, texts(request).errors.codeInvalid, 400);
    return verifyPage(request, { id, email: row.email, continueTo: safeContinue(url.searchParams.get('continue')) });
  }
  const foreign = refuseForeign(request, env);
  if (foreign) return foreign;
  const form = await readForm(request);
  const continueTo = safeContinue(form.continue);
  const result = await checkEmailCode(env, form.id || '', 'signup', form.code || '');
  if (typeof result === 'string') {
    const row = await lookup(form.id || '');
    return row ? verifyPage(request, { id: form.id, email: row.email, continueTo, error: 'codeInvalid' }, 400) : messagePage(request, texts(request).errors.codeInvalid, 400);
  }
  // Signed up with Google in the meantime? Then just add the password.
  const existing = await userByEmail(env, result.email);
  const user = existing
    ? (await env.DB.prepare('UPDATE users SET password_hash = COALESCE(password_hash, ?), updated_at = ? WHERE id = ?').bind(result.pending_password_hash, nowIso(), existing.id).run(), existing)
    : await createUser(env, { email: result.email, name: result.pending_name || '', passwordHash: result.pending_password_hash });
  return signIn(env, user, continueTo);
}

// --- Password reset. Always the same answer, whether or not the address
// has an account (no account enumeration).

export async function resetRequest(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  if (request.method === 'GET') return resetRequestPage(request, { continueTo: safeContinue(url.searchParams.get('continue')) });
  const foreign = refuseForeign(request, env);
  if (foreign) return foreign;
  const form = await readForm(request);
  const continueTo = safeContinue(form.continue);
  const email = normalizeEmail(form.email || '');
  if (!isEmail(email)) return resetRequestPage(request, { continueTo, error: 'emailInvalid' }, 400);
  const ipKey = `mail-ip:${clientIp(request)}`;
  if (await tooManyAttempts(env, ipKey, 10, 3600)) return resetRequestPage(request, { continueTo, error: 'tooMany' }, 429);
  await recordAttempt(env, ipKey);

  const id = randomToken(16);
  const code = newEmailCode();
  await env.DB.prepare(`INSERT INTO email_codes (id, purpose, email, code_hash, expires_at) VALUES (?, 'reset', ?, ?, ?)`)
    .bind(id, email, await sha256(code), inSeconds(EMAIL_CODE_SECONDS))
    .run();
  if (await userByEmail(env, email)) {
    const t = texts(request);
    try {
      await sendMail(env, email, t.mailResetSubject, t.mailReset(code));
    } catch (err) {
      console.error('reset mail failed', err);
    }
  }
  return resetCodePage(request, { id, email, continueTo });
}

export async function resetConfirm(request: Request, env: Env): Promise<Response> {
  const foreign = refuseForeign(request, env);
  if (foreign) return foreign;
  const form = await readForm(request);
  const continueTo = safeContinue(form.continue);
  const row = await env.DB.prepare("SELECT email FROM email_codes WHERE id = ? AND purpose = 'reset'").bind(form.id || '').first<{ email: string }>();
  if (!row) return messagePage(request, texts(request).errors.codeInvalid, 400);
  if ((form.password || '').length < 10) return resetCodePage(request, { id: form.id, email: row.email, continueTo, error: 'passwordShort' }, 400);
  const result = await checkEmailCode(env, form.id, 'reset', form.code || '');
  const user = typeof result === 'string' ? null : await userByEmail(env, result.email);
  if (!user) return resetCodePage(request, { id: form.id, email: row.email, continueTo, error: 'codeInvalid' }, 400);
  await env.DB.prepare('UPDATE users SET password_hash = ?, updated_at = ? WHERE id = ?').bind(await hashPassword(form.password, iterations(env)), nowIso(), user.id).run();
  // A new password ends every other session and refresh token.
  await env.DB.batch([
    env.DB.prepare('DELETE FROM sessions WHERE user_id = ?').bind(user.id),
    env.DB.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').bind(nowIso(), user.id),
  ]);
  return signIn(env, user, continueTo);
}

// --- Sign in with Google (OpenID Connect, code flow + PKCE).

const GOOGLE_AUTH = 'https://accounts.google.com/o/oauth2/v2/auth';
const GOOGLE_TOKEN = 'https://oauth2.googleapis.com/token';

export async function googleStart(request: Request, env: Env): Promise<Response> {
  if (!googleEnabled(env)) return messagePage(request, texts(request).errors.google, 404);
  const continueTo = safeContinue(new URL(request.url).searchParams.get('continue'));
  const state = randomToken(24);
  const verifier = randomToken(48);
  await env.DB.prepare('INSERT INTO oauth_states (state_hash, code_verifier, continue_to, expires_at) VALUES (?, ?, ?, ?)')
    .bind(await sha256(state), verifier, continueTo, inSeconds(600))
    .run();
  const target = new URL(GOOGLE_AUTH);
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
  return redirect(target.toString());
}

export async function googleCallback(request: Request, env: Env): Promise<Response> {
  const t = texts(request);
  const p = new URL(request.url).searchParams;
  const stateHash = await sha256(p.get('state') || '');
  const saved = await env.DB.prepare('SELECT * FROM oauth_states WHERE state_hash = ? AND expires_at > ?')
    .bind(stateHash, nowIso())
    .first<{ code_verifier: string; continue_to: string }>();
  await env.DB.prepare('DELETE FROM oauth_states WHERE state_hash = ?').bind(stateHash).run();
  if (!saved || !p.get('code') || !googleEnabled(env)) return messagePage(request, t.errors.google, 400);

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
  return session ? accountPage(request, session.user.email) : redirect('/login?continue=%2Faccount');
}
