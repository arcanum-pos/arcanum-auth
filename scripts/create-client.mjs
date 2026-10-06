// Creates a client (one per Arcanum installation) through /admin/clients —
// what the installer will do for a new instance:
//   ADMIN_API_KEY=… node scripts/create-client.mjs "Scouts Elewijt" https://arcanum.example.be
// Prints client_id + client_secret (the secret is shown only once).
const [name, appUrl, issuer = process.env.ISSUER || 'https://login.kaboutersoft.be'] = process.argv.slice(2);
if (!name || !appUrl || !process.env.ADMIN_API_KEY) {
  console.error('usage: ADMIN_API_KEY=… node scripts/create-client.mjs "<name>" <arcanum URL, e.g. https://demo.arcanum.kaboutersoft.be> [issuer]');
  process.exit(1);
}
const base = appUrl.replace(/\/+$/, '');
const res = await fetch(`${issuer}/admin/clients`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${process.env.ADMIN_API_KEY}`, 'Content-Type': 'application/json' },
  // arcanum-bff's callback, and where its logout returns to (FRONTEND_URL).
  body: JSON.stringify({ name, redirect_uris: [`${base}/callback`], post_logout_redirect_uris: [base] }),
});
console.log(res.status, JSON.stringify(await res.json(), null, 2));
