import type { Env } from './env';

// Sends through arcanum-platform-mailer (its /send, bearer MAILER_INTERNAL_KEY,
// the mailer's one contract — MAIL.md): { message, provider: { type, …settings } }.
// The account is MAIL_CONFIG, either form:
//   {"provider":"brevo","apiKey":"…","fromAddress":"…"}         (flat, any service)
//   {"provider":"smtp"|"gmail_api","credentials":{…}}           (as before)
// or plain SMTP credentials in MAIL_SMTP. Without one the message is only
// logged — enough to test, never for real users.
export function mailProvider(env: Env): ({ type: string } & Record<string, unknown>) | null {
  if (env.MAIL_CONFIG) {
    const config = JSON.parse(env.MAIL_CONFIG) as { provider?: unknown; credentials?: unknown } & Record<string, unknown>;
    if (typeof config.provider !== 'string' || !config.provider) throw new Error('MAIL_CONFIG must name its "provider" (smtp, gmail_api, brevo, resend, …)');
    const { provider, credentials, ...settings } = config;
    return { ...(credentials && typeof credentials === 'object' ? (credentials as Record<string, unknown>) : settings), type: provider };
  }
  return env.MAIL_SMTP ? { ...(JSON.parse(env.MAIL_SMTP) as Record<string, unknown>), type: 'smtp' } : null;
}

export async function sendMail(env: Env, to: string, subject: string, text: string): Promise<void> {
  const provider = mailProvider(env);
  if (!env.MAILER || !env.MAILER_INTERNAL_KEY || !provider) {
    console.log(`[arcanum-auth] no mailer configured — mail to ${to}: ${subject}\n${text}`);
    return;
  }
  const res = await env.MAILER.fetch('https://arcanum-mailer/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${env.MAILER_INTERNAL_KEY}` },
    body: JSON.stringify({ message: { to, subject, text }, provider }),
  });
  if (!res.ok) throw new Error(`arcanum-mailer returned ${res.status}: ${await res.text()}`);
}
