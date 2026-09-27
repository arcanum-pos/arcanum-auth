import type { Env } from './env';

// Sends through arcanum-mailer (its /send, bearer MAILER_INTERNAL_KEY, SMTP
// credentials from MAIL_SMTP). Without a mailer configured the message is
// only logged — enough to test, never for real users.
export async function sendMail(env: Env, to: string, subject: string, text: string): Promise<void> {
  if (!env.MAILER || !env.MAILER_INTERNAL_KEY || !env.MAIL_SMTP) {
    console.log(`[arcanum-auth] no mailer configured — mail to ${to}: ${subject}\n${text}`);
    return;
  }
  const res = await env.MAILER.fetch('https://arcanum-mailer/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${env.MAILER_INTERNAL_KEY}` },
    body: JSON.stringify({ to, subject, text, credentials: JSON.parse(env.MAIL_SMTP) }),
  });
  if (!res.ok) throw new Error(`arcanum-mailer returned ${res.status}: ${await res.text()}`);
}
