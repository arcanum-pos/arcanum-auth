import type { Env } from './env';
import { securityEvent } from './audit';
import { currentMail, mailOff } from './mail';
import { turnstileSiteKey } from './turnstile';

// What protects this instance but isn't on (2026-10-24): checked by the
// hourly cron and logged as one security event, `protection_off` - so an
// instance deployed without Turnstile or without mail is noticed, at most
// once an hour, never per request. Off on purpose (a scan target) shows too;
// that's the point of seeing it.
//   turnstile  - TURNSTILE_SITE_KEY and TURNSTILE_SECRET not both set
//   mail_off   - MAIL_SENDING is "off"
//   mail_unset - no mailer bound or no mail account: codes only logged
export async function protectionsOff(env: Env): Promise<string[]> {
  const off: string[] = [];
  if (!turnstileSiteKey(env)) off.push('turnstile');
  if (mailOff(env)) off.push('mail_off');
  else {
    const mail = await currentMail(env).catch(() => null);
    if (!env.MAILER || !env.MAILER_INTERNAL_KEY || !mail) off.push('mail_unset');
  }
  return off;
}

export async function reportProtections(env: Env): Promise<void> {
  const off = await protectionsOff(env);
  if (off.length) securityEvent('protection_off', { off });
}
