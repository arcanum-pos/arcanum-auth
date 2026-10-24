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
//   GET  /login/passkey            a client that requires a passkey (2026-10-24):
//                                  sign in with yours, or add your first one
//
// Once someone has a passkey, adding or removing one takes a session made
// with a passkey: else whoever reads their mail could sign in with a code,
// swap the passkeys and pass any client that requires one. All of them lost:
// a platform admin resets them (DELETE /admin/users/:email/passkeys).
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
import { managedClients } from './access';
import { securityEvent } from './audit';
import { accountPage, passkeyOfferPage, passkeyRequiredPage, texts, type ErrorKey, type PasskeyItem, type SessionItem } from './pages';
import { clientIp, createSession, currentSession, recordAttempt, SESSION_IDLE_SECONDS, tooManyAttempts, type Client, type Session, type User } from './store';
import { base64url, fromBase64url, inSeconds, json, nowIso, readForm, redirect, safeContinue, sameOrigin, sha256, unixNow } from './util';

const CHALLENGE_SECONDS = 300;

// Well-known authenticators by the model id (AAGUID) a passkey reports — a
// name for the list on /account. Anything else is named by how it connects.
const KNOWN_AUTHENTICATORS: Record<string, string> = {
  'fbfc3007-154e-4ecc-8c0b-6e020557d7bd': 'iCloud Keychain',
  'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4': 'Google Password Manager',
  'adce0002-35bc-c60a-648b-0b25f1f05503': 'Chrome (Mac)',
  '08987058-cadc-4b81-b6e1-30de50dcbe96': 'Windows Hello',
  '9ddd1817-af5a-4672-a2b9-3e3dd95000a9': 'Windows Hello',
  '6028b017-b1d4-4c02-b4b3-afcdafc96bb2': 'Windows Hello',
  'bada5566-a7aa-401f-bd96-45619a55120d': '1Password',
  'd548826e-79b4-db40-a3d8-11116f7e8349': 'Bitwarden',
};

const isSecurityKey = (transports: string[]) => transports.some((t) => t === 'usb' || t === 'nfc' || t === 'ble') && !transports.includes('internal');

// The name a new passkey gets (renamable on /account): a known model, else
// "Beveiligingssleutel" for a USB/NFC/Bluetooth key, "Telefoon" for one
// on a phone (the QR code), else the device the browser runs on.
function defaultName(request: Request, aaguid: string, transports: string[], browserName: unknown): string {
  const t = texts(request);
  if (KNOWN_AUTHENTICATORS[aaguid]) return KNOWN_AUTHENTICATORS[aaguid];
  if (isSecurityKey(transports)) return t.securityKey;
  if (transports.length === 1 && transports[0] === 'hybrid') return t.phone;
  return (typeof browserName === 'string' ? browserName.trim().slice(0, 60) : '') || 'Passkey';
}
const OFFER_AGAIN_DAYS = 30;

interface PasskeyRow {
  id: string;
  user_id: string;
  public_key: string;
  counter: number;
  transports: string;
  device_type: string;
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
  const cookie = await createSession(env, key.user_id, unixNow(), { amr: 'passkey', request });
  return json({ redirect: safeContinue(typeof b.continue === 'string' ? b.continue : null) }, 200, { 'Set-Cookie': cookie });
}

// --- A client that requires a passkey.

export const needsPasskey = (client: Client, session: Session) => !!client.require_passkey && session.amr !== 'passkey';

// To where it says: sign in with a passkey (or add the first one), then back.
export const passkeyStep = (continueTo: string) => redirect(`/login/passkey?continue=${encodeURIComponent(continueTo)}`);

export async function passkeyRequired(request: Request, env: Env): Promise<Response> {
  const continueTo = safeContinue(new URL(request.url).searchParams.get('continue'));
  const session = await currentSession(env, request);
  if (!session) return redirect(`/login?continue=${encodeURIComponent(continueTo)}`);
  if (session.amr === 'passkey' || session.user.guest) return redirect(continueTo);
  const has = (await passkeysOf(env, session.user.id)).length > 0;
  return passkeyRequiredPage(request, { continueTo, enroll: !has });
}

// --- Adding one (signed in).

async function signedInAccount(request: Request, env: Env): Promise<Session | null> {
  const session = await currentSession(env, request);
  return session && !session.user.guest ? session : null;
}

export async function passkeyRegisterOptions(request: Request, env: Env): Promise<Response> {
  if (!jsonFromHere(request, env)) return fail(request, 'request', 403);
  const session = await signedInAccount(request, env);
  if (!session) return fail(request, 'signInFirst', 401);
  const user = session.user;
  const existing = await passkeysOf(env, user.id);
  if (existing.length && session.amr !== 'passkey') return fail(request, 'passkeyStepUp', 403);
  const options = await generateRegistrationOptions({
    // What the browser shows when saving it: this sign-in service's own host.
    rpName: rp(env).id,
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
  const session = await signedInAccount(request, env);
  if (!session) return fail(request, 'signInFirst', 401);
  const user = session.user;
  const first = (await passkeysOf(env, user.id)).length === 0;
  if (!first && session.amr !== 'passkey') return fail(request, 'passkeyStepUp', 403);
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

  const transports = info.credential.transports ?? response.response.transports ?? [];
  const name = defaultName(request, info.aaguid, transports, b.name);
  await env.DB.prepare(
    'INSERT INTO passkeys (id, user_id, public_key, counter, transports, device_type, backed_up, name, aaguid, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  )
    .bind(
      info.credential.id,
      user.id,
      base64url(info.credential.publicKey),
      info.credential.counter,
      JSON.stringify(transports),
      info.credentialDeviceType,
      info.credentialBackedUp ? 1 : 0,
      name,
      info.aaguid,
      nowIso()
    )
    .run();
  // The first one, just made and used: this session now counts as made with a
  // passkey (a client that requires one lets it through).
  if (first) await env.DB.prepare("UPDATE sessions SET amr = 'passkey' WHERE id_hash = ?").bind(session.idHash).run();
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

export async function accountWithPasskeys(request: Request, env: Env, user: User, opts: { added?: boolean; googleUnlinked?: boolean; endedEverywhere?: boolean; error?: ErrorKey | null } = {}, status = 200) {
  const passkeys: PasskeyItem[] = (await passkeysOf(env, user.id)).map((k) => {
    const transports = JSON.parse(k.transports) as string[];
    return {
      id: k.id,
      name: k.name,
      created_at: k.created_at,
      last_used_at: k.last_used_at,
      kind: isSecurityKey(transports) ? 'securityKey' : k.device_type === 'multiDevice' ? 'synced' : 'device',
      transports: transports.filter((t) => t === 'usb' || t === 'nfc' || t === 'ble'),
    };
  });
  return accountPage(request, { email: user.email, passkeys, google: !!user.google_sub, managed: await managedClients(env, user), sessions: await sessionsOf(env, request, user), ...opts }, status);
}

export async function managePasskey(request: Request, env: Env): Promise<Response> {
  const session = await currentSession(env, request);
  if (!session) return redirect('/login?continue=%2Faccount');
  if (!sameOrigin(request, env.ISSUER)) return accountWithPasskeys(request, env, session.user, { error: 'request' }, 403);
  const form = await readForm(request);
  if (form.action === 'delete') {
    // Removing one takes a passkey sign-in (see the top of this file).
    if (session.amr !== 'passkey') return accountWithPasskeys(request, env, session.user, { error: 'passkeyStepUp' }, 403);
    await env.DB.prepare('DELETE FROM passkeys WHERE id = ? AND user_id = ?').bind(form.id || '', session.user.id).run();
  } else if (form.action === 'rename') {
    const name = (form.name || '').trim().slice(0, 60);
    if (name) await env.DB.prepare('UPDATE passkeys SET name = ? WHERE id = ? AND user_id = ?').bind(name, form.id || '', session.user.id).run();
  }
  return redirect('/account');
}

// --- Where someone is signed in (/account, 2026-10-24): this site's live
// sessions, one ended, or all others and every application's refresh tokens.

async function sessionsOf(env: Env, request: Request, user: User): Promise<SessionItem[]> {
  const current = await currentSession(env, request);
  const idleSince = new Date(Date.now() - SESSION_IDLE_SECONDS * 1000).toISOString();
  const { results } = await env.DB.prepare(
    `SELECT id_hash, created_at, last_seen_at, user_agent, amr FROM sessions
     WHERE user_id = ? AND expires_at > ? AND COALESCE(last_seen_at, created_at) > ? ORDER BY COALESCE(last_seen_at, created_at) DESC LIMIT 20`
  )
    .bind(user.id, nowIso(), idleSince)
    .all<{ id_hash: string; created_at: string; last_seen_at: string | null; user_agent: string | null; amr: string | null }>();
  return (results || []).map((r) => ({ id: r.id_hash, created_at: r.created_at, last_seen_at: r.last_seen_at, user_agent: r.user_agent, amr: r.amr, current: r.id_hash === current?.idHash }));
}

export async function manageSessions(request: Request, env: Env): Promise<Response> {
  const session = await currentSession(env, request);
  if (!session) return redirect('/login?continue=%2Faccount');
  if (!sameOrigin(request, env.ISSUER)) return accountWithPasskeys(request, env, session.user, { error: 'request' }, 403);
  const form = await readForm(request);
  if (form.action === 'end' && form.id && form.id !== session.idHash) {
    await env.DB.prepare('DELETE FROM sessions WHERE id_hash = ? AND user_id = ?').bind(form.id, session.user.id).run();
    return redirect('/account');
  }
  if (form.action === 'everywhere') {
    await env.DB.batch([
      env.DB.prepare('DELETE FROM sessions WHERE user_id = ? AND id_hash != ?').bind(session.user.id, session.idHash),
      env.DB.prepare('UPDATE refresh_tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL').bind(nowIso(), session.user.id),
    ]);
    securityEvent('signed_out_everywhere', { user: session.user.id });
    return redirect('/account?ended=everywhere');
  }
  return redirect('/account');
}

// Unlink Google (a form on /account): signing in goes on by mailed code or passkey.
export async function manageGoogle(request: Request, env: Env): Promise<Response> {
  const session = await currentSession(env, request);
  if (!session) return redirect('/login?continue=%2Faccount');
  if (!sameOrigin(request, env.ISSUER)) return accountWithPasskeys(request, env, session.user, { error: 'request' }, 403);
  const form = await readForm(request);
  if (form.action !== 'unlink') return redirect('/account');
  await env.DB.prepare('UPDATE users SET google_sub = NULL, updated_at = ? WHERE id = ?').bind(nowIso(), session.user.id).run();
  return redirect('/account?google=unlinked');
}
