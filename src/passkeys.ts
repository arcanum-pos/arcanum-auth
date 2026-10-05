// Passkeys (WebAuthn): another way into the same account — the same user,
// the same `sub`, so nothing changes for the installations. The relying
// party is the ISSUER's host (login.kaboutersoft.be): a passkey only works
// there. Verification by @simplewebauthn/server (WebCrypto); attestation
// "none" (no device attestation is needed or kept), user verification
// required (fingerprint, face or the device's PIN).
//
//   POST /passkey/login/options   → options for navigator.credentials.get
//   POST /passkey/login           → { redirect } + the session cookie
//   POST /passkey/register/options (signed in) → options for navigator.credentials.create
//   POST /passkey/register         (signed in) → { redirect }
//   GET/POST /passkey/offer        once after signing in another way: add one, or not now
//   POST /account/passkeys         rename or remove one (a form on /account)
//
// The JSON endpoints take JSON from this very origin only (CSRF). Challenges
// are single use and live five minutes (webauthn_challenges, hashed).
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from '@simplewebauthn/server';
import type { Env } from './env';
import { sendMail } from './mail';
import { accountPage, passkeyOfferPage, texts, type ErrorKey, type PasskeyItem } from './pages';
import { clientIp, createSession, currentSession, recordAttempt, tooManyAttempts, type User } from './store';
import { base64url, fromBase64url, inSeconds, json, nowIso, readForm, redirect, safeContinue, sameOrigin, sha256, unixNow } from './util';

const CHALLENGE_SECONDS = 300;
const OFFER_AGAIN_DAYS = 30;

interface PasskeyRow {
  id: string;
  user_id: string;
  public_key: string;
  counter: number;
  transports: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
}

const rp = (env: Env) => ({ id: new URL(env.ISSUER).hostname, origin: new URL(env.ISSUER).origin });

// JSON, posted by our own pages' script.
function jsonFromHere(request: Request, env: Env): boolean {
  return sameOrigin(request, env.ISSUER) && (request.headers.get('Content-Type') || '').includes('application/json');
}

async function body(request: Request): Promise<Record<string, unknown>> {
  return ((await request.json().catch(() => null)) as Record<string, unknown> | null) ?? {};
}

const fail = (request: Request, key: ErrorKey, status: number) => json({ error: texts(request).errors[key] }, status);

async function saveChallenge(env: Env, challenge: string, purpose: 'register' | 'login', userId: string | null) {
  await env.DB.prepare('INSERT INTO webauthn_challenges (challenge_hash, purpose, user_id, expires_at) VALUES (?, ?, ?, ?)')
    .bind(await sha256(challenge), purpose, userId, inSeconds(CHALLENGE_SECONDS))
    .run();
}

// The challenge the browser signed (from its clientDataJSON), taken: it
// works once. null when it's unknown, used, expired or for something else.
async function takeChallenge(env: Env, clientDataJSON: unknown, purpose: 'register' | 'login'): Promise<{ challenge: string; userId: string | null } | null> {
  let challenge: unknown;
  try {
    challenge = JSON.parse(new TextDecoder().decode(fromBase64url(String(clientDataJSON)))).challenge;
  } catch {
    return null;
  }
  if (typeof challenge !== 'string' || !challenge) return null;
  const row = await env.DB.prepare('DELETE FROM webauthn_challenges WHERE challenge_hash = ? AND purpose = ? AND expires_at > ? RETURNING user_id')
    .bind(await sha256(challenge), purpose, nowIso())
    .first<{ user_id: string | null }>();
  return row ? { challenge, userId: row.user_id } : null;
}

export function passkeysOf(env: Env, userId: string) {
  return env.DB.prepare('SELECT * FROM passkeys WHERE user_id = ? ORDER BY created_at').bind(userId).all<PasskeyRow>().then((r) => r.results);
}

// Offered after signing in another way: an account (not a guest) without a
// passkey, unless "not now" was said less than 30 days ago.
export async function shouldOfferPasskey(env: Env, user: User): Promise<boolean> {
  if (user.guest) return false;
  if (user.passkey_offer_dismissed_at && Date.parse(user.passkey_offer_dismissed_at) > Date.now() - OFFER_AGAIN_DAYS * 86_400_000) return false;
  const any = await env.DB.prepare('SELECT 1 FROM passkeys WHERE user_id = ? LIMIT 1').bind(user.id).first();
  return !any;
}

// --- Signing in.

export async function passkeyLoginOptions(request: Request, env: Env): Promise<Response> {
  if (!jsonFromHere(request, env)) return fail(request, 'request', 403);
  // Discoverable credentials: no e-mail asked, the browser offers the passkeys it has for this site.
  const options = await generateAuthenticationOptions({ rpID: rp(env).id, userVerification: 'required', timeout: CHALLENGE_SECONDS * 1000 });
  await saveChallenge(env, options.challenge, 'login', null);
  return json(options);
}

export async function passkeyLogin(request: Request, env: Env): Promise<Response> {
  if (!jsonFromHere(request, env)) return fail(request, 'request', 403);
  const ipKey = `passkey-ip:${clientIp(request)}`;
  if (await tooManyAttempts(env, ipKey, 30)) return fail(request, 'tooMany', 429);
  const b = await body(request);
  const response = b.response as AuthenticationResponseJSON | undefined;
  if (!response?.id || !response.response?.clientDataJSON) return fail(request, 'request', 400);

  const taken = await takeChallenge(env, response.response.clientDataJSON, 'login');
  if (!taken) return fail(request, 'passkeyExpired', 400);
  const key = await env.DB.prepare(
    `SELECT passkeys.* FROM passkeys JOIN users ON users.id = passkeys.user_id WHERE passkeys.id = ? AND users.guest = 0`
  )
    .bind(response.id)
    .first<PasskeyRow>();
  if (!key) {
    await recordAttempt(env, ipKey);
    return fail(request, 'passkeyUnknown', 401);
  }
  // The user handle, when the authenticator returns it, must be this passkey's user.
  const handle = response.response.userHandle;
  if (handle && new TextDecoder().decode(fromBase64url(handle)) !== key.user_id) {
    await recordAttempt(env, ipKey);
    return fail(request, 'passkeyFailed', 401);
  }
  let verified = false;
  let newCounter = key.counter;
  try {
    const result = await verifyAuthenticationResponse({
      response,
      expectedChallenge: taken.challenge,
      expectedOrigin: rp(env).origin,
      expectedRPID: rp(env).id,
      requireUserVerification: true,
      credential: { id: key.id, publicKey: new Uint8Array(fromBase64url(key.public_key)), counter: key.counter, transports: JSON.parse(key.transports) },
    });
    verified = result.verified;
    newCounter = result.authenticationInfo.newCounter;
  } catch (err) {
    console.warn('passkey sign-in refused', (err as Error).message);
  }
  if (!verified) {
    await recordAttempt(env, ipKey);
    return fail(request, 'passkeyFailed', 401);
  }
  await env.DB.prepare('UPDATE passkeys SET counter = ?, last_used_at = ? WHERE id = ?').bind(newCounter, nowIso(), key.id).run();
  const cookie = await createSession(env, key.user_id, unixNow());
  return json({ redirect: safeContinue(typeof b.continue === 'string' ? b.continue : null) }, 200, { 'Set-Cookie': cookie });
}

// --- Adding one (signed in).

async function signedInAccount(request: Request, env: Env): Promise<User | null> {
  const session = await currentSession(env, request);
  return session && !session.user.guest ? session.user : null;
}

export async function passkeyRegisterOptions(request: Request, env: Env): Promise<Response> {
  if (!jsonFromHere(request, env)) return fail(request, 'request', 403);
  const user = await signedInAccount(request, env);
  if (!user) return fail(request, 'signInFirst', 401);
  const existing = await passkeysOf(env, user.id);
  const options = await generateRegistrationOptions({
    rpName: 'Arcanum',
    rpID: rp(env).id,
    userName: user.email,
    userDisplayName: user.name || user.email,
    userID: new Uint8Array(new TextEncoder().encode(user.id)),
    attestationType: 'none',
    excludeCredentials: existing.map((k) => ({ id: k.id, transports: JSON.parse(k.transports) })),
    authenticatorSelection: { residentKey: 'required', userVerification: 'required' },
    timeout: CHALLENGE_SECONDS * 1000,
  });
  await saveChallenge(env, options.challenge, 'register', user.id);
  return json(options);
}

export async function passkeyRegister(request: Request, env: Env): Promise<Response> {
  if (!jsonFromHere(request, env)) return fail(request, 'request', 403);
  const user = await signedInAccount(request, env);
  if (!user) return fail(request, 'signInFirst', 401);
  const b = await body(request);
  const response = b.response as RegistrationResponseJSON | undefined;
  if (!response?.response?.clientDataJSON) return fail(request, 'request', 400);
  const taken = await takeChallenge(env, response.response.clientDataJSON, 'register');
  if (!taken || taken.userId !== user.id) return fail(request, 'passkeyExpired', 400);

  let info;
  try {
    const result = await verifyRegistrationResponse({
      response,
      expectedChallenge: taken.challenge,
      expectedOrigin: rp(env).origin,
      expectedRPID: rp(env).id,
      requireUserVerification: true,
    });
    info = result.verified ? result.registrationInfo : null;
  } catch (err) {
    console.warn('passkey registration refused', (err as Error).message);
  }
  if (!info) return fail(request, 'passkeyAddFailed', 400);
  if (await env.DB.prepare('SELECT 1 FROM passkeys WHERE id = ?').bind(info.credential.id).first()) return fail(request, 'passkeyExists', 409);

  const name = (typeof b.name === 'string' ? b.name.trim().slice(0, 60) : '') || 'Passkey';
  await env.DB.prepare(
    'INSERT INTO passkeys (id, user_id, public_key, counter, transports, device_type, backed_up, name, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
  )
    .bind(
      info.credential.id,
      user.id,
      base64url(info.credential.publicKey),
      info.credential.counter,
      JSON.stringify(info.credential.transports ?? response.response.transports ?? []),
      info.credentialDeviceType,
      info.credentialBackedUp ? 1 : 0,
      name,
      nowIso()
    )
    .run();
  // Told by mail: someone who got into the account can't quietly add a way back in.
  const t = texts(request);
  await sendMail(env, user.email, t.mailPasskeySubject, t.mailPasskey(name, `${env.ISSUER}/account`)).catch((err) => console.error('passkey mail failed', err));
  return json({ redirect: safeContinue(typeof b.continue === 'string' ? b.continue : null) });
}

// --- The offer after signing in another way.

export async function passkeyOffer(request: Request, env: Env): Promise<Response> {
  const url = new URL(request.url);
  const session = await currentSession(env, request);
  if (request.method === 'GET') {
    const continueTo = safeContinue(url.searchParams.get('continue'));
    if (!session) return redirect(`/login?continue=${encodeURIComponent(continueTo)}`);
    if (!(await shouldOfferPasskey(env, session.user))) return redirect(continueTo);
    return passkeyOfferPage(request, continueTo);
  }
  // "Not now".
  if (!sameOrigin(request, env.ISSUER)) return redirect('/account');
  const continueTo = safeContinue((await readForm(request)).continue);
  if (session) await env.DB.prepare('UPDATE users SET passkey_offer_dismissed_at = ? WHERE id = ?').bind(nowIso(), session.user.id).run();
  return redirect(continueTo);
}

// --- /account: the list, rename, remove.

export async function accountWithPasskeys(request: Request, env: Env, user: User, opts: { added?: boolean; error?: ErrorKey | null } = {}, status = 200) {
  const passkeys: PasskeyItem[] = (await passkeysOf(env, user.id)).map((k) => ({ id: k.id, name: k.name, created_at: k.created_at, last_used_at: k.last_used_at }));
  return accountPage(request, { email: user.email, passkeys, ...opts }, status);
}

export async function managePasskey(request: Request, env: Env): Promise<Response> {
  const session = await currentSession(env, request);
  if (!session) return redirect('/login?continue=%2Faccount');
  if (!sameOrigin(request, env.ISSUER)) return accountWithPasskeys(request, env, session.user, { error: 'request' }, 403);
  const form = await readForm(request);
  if (form.action === 'delete') {
    await env.DB.prepare('DELETE FROM passkeys WHERE id = ? AND user_id = ?').bind(form.id || '', session.user.id).run();
  } else if (form.action === 'rename') {
    const name = (form.name || '').trim().slice(0, 60);
    if (name) await env.DB.prepare('UPDATE passkeys SET name = ? WHERE id = ? AND user_id = ?').bind(name, form.id || '', session.user.id).run();
  }
  return redirect('/account');
}
