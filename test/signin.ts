// Signing in the only way left besides passkeys and Google: a mailed code
// (a new address also gives its name). Shared by the test files.
import { env } from 'cloudflare:test';
import { expect } from 'vitest';

const ISSUER = 'https://login.kaboutersoft.be';
type Post = (path: string, fields: Record<string, string>, headers?: Record<string, string>) => Promise<Response>;

export const cookieOf = (res: Response) => (res.headers.get('Set-Cookie') || '').split(';')[0];

export async function lastMailFor(email: string): Promise<{ subject: string; text: string }> {
  const mails = (await (await env.MAILER!.fetch('https://mailer/__calls')).json()) as { body: { message: { to: string; subject: string; text: string } } }[];
  return mails.reverse().find((m) => m.body.message.to === email)!.body.message;
}

export async function lastCodeFor(email: string): Promise<string> {
  return (await lastMailFor(email)).text.match(/\b(\d{6})\b/)![1];
}

export async function lastLinkFor(email: string): Promise<string> {
  return (await lastMailFor(email)).text.match(/https:\/\/\S+\/login\/link\?\S+/)![0];
}

// Asks a code: its id (from where /login sends the browser) and the browser's sign-in cookie.
export async function askCode(post: Post, email: string, continueTo = '/account'): Promise<{ id: string; browser: string }> {
  const asked = await post('/login', { email, continue: continueTo });
  expect(asked.status).toBe(302);
  return { id: new URL(asked.headers.get('Location')!, ISSUER).searchParams.get('id')!, browser: cookieOf(asked) };
}

// Signs in with the mailed code → the session cookie and where it went next.
export async function signInWithCode(post: Post, email: string, opts: { name?: string; continueTo?: string } = {}) {
  const { id } = await askCode(post, email, opts.continueTo);
  let done = await post('/login/code', { id, code: await lastCodeFor(email) });
  if (done.status === 200) {
    // A new address: what's your name?
    const finish = (await done.text()).match(/name="finish" value="([^"]+)"/)![1];
    done = await post('/login/name', { id, finish, name: opts.name ?? 'Jan Peeters' });
  }
  expect(done.status).toBe(302);
  return { cookie: cookieOf(done), next: done.headers.get('Location')! };
}
