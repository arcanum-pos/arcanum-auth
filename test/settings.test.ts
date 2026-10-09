import { env, SELF } from 'cloudflare:test';
import { describe, expect, it } from 'vitest';
import { sendMail } from '../src/mail';

// The platform's mail account set from the bootstrapper (/admin/e-mail):
// stored encrypted in D1 (src/settings.ts), used before MAIL_CONFIG /
// MAIL_SMTP, never shown back. One file, in order: the stored row is shared.

const ISSUER = 'https://login.kaboutersoft.be';
const ADMIN = { Authorization: 'Bearer test-admin-key', 'Content-Type': 'application/json' };
const call = (path: string, init: RequestInit = {}) => SELF.fetch(`${ISSUER}${path}`, { redirect: 'manual', ...init });
const admin = (method: string, path: string, body?: unknown) => call(path, { method, headers: ADMIN, ...(body === undefined ? {} : { body: JSON.stringify(body) }) });
const mailTo = async (to: string) => {
  const calls = (await (await env.MAILER!.fetch('https://mailer/__calls')).json()) as { body: { message: { to: string; subject: string }; provider: Record<string, unknown> } }[];
  return calls.filter((c) => c.body.message?.to === to).map((c) => c.body);
};

describe('the platform mail account (/admin/mail)', () => {
  it('only with the admin key', async () => {
    expect((await call('/admin/mail')).status).toBe(401);
    expect((await call('/admin/mail', { method: 'PUT', body: '{}' })).status).toBe(401);
  });

  it('nothing stored: the secret (MAIL_SMTP here) is in use, shown without its password', async () => {
    const res = await admin('GET', '/admin/mail');
    expect(await res.json()).toEqual({
      canStore: true,
      active: 'secret',
      stored: null,
      secret: { provider: 'smtp', values: { host: 'smtp.test', port: 465, username: 'u', fromAddress: 'noreply@test' }, secretsSet: ['password'] },
    });
  });

  it('stored: used for every mail from then on, encrypted in D1, its key never shown', async () => {
    const saved = await admin('PUT', '/admin/mail', { provider: 'brevo', settings: { apiKey: 'xkeysib-geheim', fromAddress: ' noreply@kaboutersoft.be ', fromName: '' } });
    expect(await saved.json()).toEqual({ ok: true, provider: 'brevo', values: { fromAddress: 'noreply@kaboutersoft.be' }, secretsSet: ['apiKey'] });
    const shown = (await (await admin('GET', '/admin/mail')).json()) as Record<string, any>;
    expect(shown.active).toBe('settings');
    expect(shown.stored).toMatchObject({ provider: 'brevo', values: { fromAddress: 'noreply@kaboutersoft.be' }, secretsSet: ['apiKey'] });
    expect(JSON.stringify(shown)).not.toContain('xkeysib-geheim');
    const row = await env.DB.prepare("SELECT value FROM settings WHERE name = 'mail'").first<{ value: string }>();
    expect(row!.value).not.toContain('xkeysib');

    await sendMail(env, 'stored@example.test', 'Code', 'Je code');
    expect((await mailTo('stored@example.test'))[0].provider).toEqual({ type: 'brevo', apiKey: 'xkeysib-geheim', fromAddress: 'noreply@kaboutersoft.be' });
  });

  it('a key left out but kept: the stored one stays (same service only)', async () => {
    await admin('PUT', '/admin/mail', { provider: 'brevo', settings: { fromAddress: 'info@kaboutersoft.be' }, keep: ['apiKey'] });
    await sendMail(env, 'kept@example.test', 'Code', 'Je code');
    expect((await mailTo('kept@example.test'))[0].provider).toEqual({ type: 'brevo', apiKey: 'xkeysib-geheim', fromAddress: 'info@kaboutersoft.be' });
    const other = await admin('PUT', '/admin/mail', { provider: 'resend', settings: { fromAddress: 'info@kaboutersoft.be' }, keep: ['apiKey'] });
    expect(((await other.json()) as { secretsSet: string[] }).secretsSet).toEqual([]);
  });

  it('only the services the platform mailer has; a test mail gives the mailer’s answer', async () => {
    expect((await admin('PUT', '/admin/mail', { provider: 'mailchimp', settings: { fromAddress: 'a@b.test' } })).status).toBe(400);
    // Cloudflare Email Service: no key, just the sender (the mailer's send_email binding).
    const cf = await admin('PUT', '/admin/mail', { provider: 'cloudflare', settings: { fromAddress: 'noreply@kaboutersoft.be', fromName: 'Arcanum' } });
    expect(await cf.json()).toEqual({ ok: true, provider: 'cloudflare', values: { fromAddress: 'noreply@kaboutersoft.be', fromName: 'Arcanum' }, secretsSet: [] });
    await sendMail(env, 'cf@example.test', 'Code', 'Je code');
    expect((await mailTo('cf@example.test'))[0].provider).toEqual({ type: 'cloudflare', fromAddress: 'noreply@kaboutersoft.be', fromName: 'Arcanum' });
    await admin('PUT', '/admin/mail', { provider: 'resend', settings: { apiKey: 're_1', fromAddress: 'noreply@kaboutersoft.be' } });
    const test = await admin('POST', '/admin/mail/test', { to: 'bert@example.test' });
    expect(test.status).toBe(200);
    expect(await test.json()).toEqual({ ok: true, source: 'settings' });
    expect((await mailTo('bert@example.test'))[0]).toMatchObject({ message: { subject: 'Je code voor Arcanum' }, provider: { type: 'resend', apiKey: 're_1' } });
    expect((await admin('POST', '/admin/mail/test', { to: 'geen-adres' })).status).toBe(400);
  });

  it('at most 10 test mails an hour', async () => {
    const statuses: number[] = [];
    for (let i = 0; i < 10; i++) statuses.push((await admin('POST', '/admin/mail/test', { to: `n${i}@example.test` })).status);
    // One went out in the test before.
    expect(statuses.filter((s) => s === 200)).toHaveLength(9);
    expect(statuses.at(-1)).toBe(429);
  });

  it('removed: back to the secret', async () => {
    expect((await admin('DELETE', '/admin/mail')).status).toBe(200);
    expect(((await (await admin('GET', '/admin/mail')).json()) as { active: string }).active).toBe('secret');
    await sendMail(env, 'back@example.test', 'Code', 'Je code');
    expect((await mailTo('back@example.test'))[0].provider).toMatchObject({ type: 'smtp' });
  });

  it('without SETTINGS_KEY nothing is stored or read', async () => {
    const { admin: handler } = await import('../src/admin');
    const noKey = { ...env, SETTINGS_KEY: undefined };
    const put = await handler(new Request(`${ISSUER}/admin/mail`, { method: 'PUT', headers: ADMIN, body: JSON.stringify({ provider: 'brevo', settings: {} }) }), noKey, '/admin/mail');
    expect(put.status).toBe(409);
    const get = await handler(new Request(`${ISSUER}/admin/mail`, { headers: ADMIN }), noKey, '/admin/mail');
    expect(await get.json()).toMatchObject({ canStore: false, active: 'secret' });
  });
});
