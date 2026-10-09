import type { Env } from './env';
import { readSetting, type MailSetting } from './settings';

// Sends through arcanum-platform-mailer (its /send, bearer MAILER_INTERNAL_KEY,
// the mailer's one contract — MAIL.md): { message, provider: { type, …settings } }.
// The account: the one set in the bootstrapper (/admin/e-mail, stored
// encrypted — settings.ts), else MAIL_CONFIG, either form:
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

// The account in use, and where it comes from.
export async function currentMail(env: Env): Promise<{ source: 'settings' | 'secret'; provider: { type: string } & Record<string, unknown> } | null> {
  const stored = await readSetting<MailSetting>(env, 'mail');
  if (stored) {
    const { provider, ...settings } = stored.value;
    return { source: 'settings', provider: { ...settings, type: provider } };
  }
  const fromSecret = mailProvider(env);
  return fromSecret ? { source: 'secret', provider: fromSecret } : null;
}

// The same mail as HTML: paragraphs on blank lines, line breaks kept, links
// clickable. Sent next to the text so services that only keep one version
// (Brevo turns a text-only mail into HTML-only) send both — spam filters
// mark down an HTML-only mail (MIME_HTML_ONLY, mail-tester.com).
export function htmlOf(text: string): string {
  const escape = (v: string) => v.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  const linked = (v: string) => escape(v).replace(/https:\/\/[^\s<]+[^\s<.,:;!?)]/g, (url) => `<a href="${url}">${url}</a>`);
  return text
    .split(/\n{2,}/)
    .map((p) => `<p>${linked(p).replace(/\n/g, '<br>')}</p>`)
    .join('\n');
}

async function callMailer(env: Env, provider: { type: string } & Record<string, unknown>, to: string, subject: string, text: string): Promise<Response> {
  return env.MAILER!.fetch('https://arcanum-mailer/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${env.MAILER_INTERNAL_KEY}` },
    body: JSON.stringify({ message: { to, subject, text, html: htmlOf(text) }, provider }),
  });
}

// A test mail (the bootstrapper's "Testmail sturen"): the mailer's answer as it is.
export async function sendTestMail(env: Env, to: string, subject: string, text: string): Promise<{ status: number; body: Record<string, unknown> }> {
  const mail = await currentMail(env);
  if (!env.MAILER || !env.MAILER_INTERNAL_KEY) return { status: 409, body: { ok: false, code: 'invalid_config', error: 'No platform mailer bound (MAILER, MAILER_INTERNAL_KEY)' } };
  if (!mail) return { status: 409, body: { ok: false, code: 'invalid_config', error: 'No mail account set' } };
  const res = await callMailer(env, mail.provider, to, subject, text);
  const body = (await res.json().catch(() => null)) as Record<string, unknown> | null;
  return { status: res.status, body: { ...(body ?? { ok: false, code: 'unreachable', error: `arcanum-mailer returned ${res.status}` }), source: mail.source } };
}

export async function sendMail(env: Env, to: string, subject: string, text: string): Promise<void> {
  const provider = (await currentMail(env))?.provider;
  if (!env.MAILER || !env.MAILER_INTERNAL_KEY || !provider) {
    console.log(`[arcanum-auth] no mailer configured — mail to ${to}: ${subject}\n${text}`);
    return;
  }
  const res = await callMailer(env, provider, to, subject, text);
  if (!res.ok) throw new Error(`arcanum-mailer returned ${res.status}: ${await res.text()}`);
}
