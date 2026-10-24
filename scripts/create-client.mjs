// Creates a client (one per Arcanum installation) through /admin/clients.
// The admin API doesn't answer from the internet: run tools/admin first
// (`npx wrangler dev -c tools/admin/wrangler.jsonc`, logged in to the
// instance's account), then:
//   ADMIN_API_KEY=… node scripts/create-client.mjs "Scouts Elewijt" https://arcanum.example.be
// Prints client_id + client_secret (the secret is shown only once).
// ADMIN_URL: where tools/admin listens (default http://localhost:8799).
const [name, appUrl] = process.argv.slice(2);
const adminUrl = (process.env.ADMIN_URL || 'http://localhost:8799').replace(/\/+$/, '');
if (!name || !appUrl || !process.env.ADMIN_API_KEY) {
  console.error('usage: ADMIN_API_KEY=… node scripts/create-client.mjs "<name>" <arcanum URL, e.g. https://demo.arcanum.kaboutersoft.be>  (with tools/admin running)');
  process.exit(1);
}
const base = appUrl.replace(/\/+$/, '');
const res = await fetch(`${adminUrl}/admin/clients`, {
  method: 'POST',
  headers: { Authorization: `Bearer ${process.env.ADMIN_API_KEY}`, 'Content-Type': 'application/json' },
  // arcanum-bff's callback, and where its logout returns to (FRONTEND_URL).
  body: JSON.stringify({ name, redirect_uris: [`${base}/callback`], post_logout_redirect_uris: [base] }),
});
console.log(res.status, JSON.stringify(await res.json(), null, 2));
