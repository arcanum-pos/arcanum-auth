// Security events (2026-10-24): one JSON line each in Workers Logs
// (observability), `event: "security"`, to search and alert on - a reused
// refresh token or code, refused bot checks, rate limits hit, admin changes.
// Never a token, code or secret in them; an e-mail address only where it
// names whose account it is.
export function securityEvent(name: string, fields: Record<string, unknown> = {}): void {
  console.log(JSON.stringify({ event: 'security', name, at: new Date().toISOString(), ...fields }));
}
