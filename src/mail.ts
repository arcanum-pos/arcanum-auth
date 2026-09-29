import type { Env } from './env';

// Sends through arcanum-mailer (its /send, bearer MAILER_INTERNAL_KEY) with
// the provider from MAIL_CONFIG — {"provider":"smtp"|"gmail_api","credentials":{…}}
// (arcanum-mailer's own shapes) — or plain SMTP credentials in MAIL_SMTP.
// Without a mailer configured the message is only logged — enough to test,
// never for real users.
function mailProvider(env: Env): { provider: 'smtp' | 'gmail_api'; credentials: unknown } | null {
  if (env.MAIL_CONFIG) {
    const config = JSON.parse(env.MAIL_CONFIG) as { provider?: string; credentials?: unknown };
    if ((config.provider === 'smtp' || config.provider === 'gmail_api') && config.credentials) return { provider: config.provider, credentials: config.credentials };
    throw new Error('MAIL_CONFIG must be {"provider":"smtp"|"gmail_api","credentials":{…}}');
  }
  return env.MAIL_SMTP ? { provider: 'smtp', credentials: JSON.parse(env.MAIL_SMTP) } : null;
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
    body: JSON.stringify({ to, subject, text, ...provider }),
  });
  if (!res.ok) throw new Error(`arcanum-mailer returned ${res.status}: ${await res.text()}`);
}
