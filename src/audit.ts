// Security events (2026-10-24): one JSON line each in Workers Logs
// (observability), `event: "security"`, to search and alert on - a reused
// refresh token or code, refused bot checks, rate limits hit, admin changes.
// Never a token, code or secret in them; an e-mail address only where it
// names whose account it is.
export function securityEvent(name: string, fields: Record<string, unknown> = {}): void {
  console.log(JSON.stringify({ event: 'security', name, at: new Date().toISOString(), ...fields }));
}

// The audit log the admin dashboard shows (audit_log, migration 0014): admin
// changes and machine-secret events, next to the security event above. Best
// effort - a missing table or a failed write never fails the request.
// `detail`: what and on what, never a secret's, token's or code's value.
export async function auditLog(env: { DB: D1Database }, name: string, by: string | null, detail: Record<string, unknown> = {}): Promise<void> {
  try {
    await env.DB.prepare('INSERT INTO audit_log (at, name, by, detail) VALUES (?, ?, ?, ?)').bind(new Date().toISOString(), name, by, JSON.stringify(detail)).run();
  } catch (err) {
    console.error('audit log write failed', (err as Error).message);
  }
}
