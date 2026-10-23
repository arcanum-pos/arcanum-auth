import { env, SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { cookieOf, signInWithCode } from "./signin";

// Restricted clients (access.ts): only assigned people sign in — assigned
// by the client's admins (after a request) or by the application itself.

const ISSUER = "https://login.kaboutersoft.be";
const APP = "https://restricted.test";
const REDIRECT = `${APP}/callback`;
const FORM = {
  "Content-Type": "application/x-www-form-urlencoded",
  Origin: ISSUER,
};
const ADMIN = {
  Authorization: "Bearer test-admin-key",
  "Content-Type": "application/json",
};

let seq = 0;
const uniqueEmail = (tag: string) =>
  `${tag}-${Date.now()}-${++seq}@example.test`;
const someIp = () =>
  `10.${seq % 250}.${Math.floor(Math.random() * 250)}.${Math.floor(Math.random() * 250)}`;
const call = (path: string, init: RequestInit = {}) =>
  SELF.fetch(`${ISSUER}${path}`, { redirect: "manual", ...init });
const post = (
  path: string,
  fields: Record<string, string>,
  headers: Record<string, string> = {},
) =>
  call(path, {
    method: "POST",
    headers: { ...FORM, "CF-Connecting-IP": someIp(), ...headers },
    body: new URLSearchParams(fields),
  });
const basic = (c: { client_id: string; client_secret: string }) => ({
  Authorization: `Basic ${btoa(`${c.client_id}:${c.client_secret}`)}`,
});
const signUp = async (email: string, name = "Jan Peeters") =>
  (await signInWithCode(post, email, { name })).cookie;

async function mailsTo(
  email: string,
): Promise<{ subject: string; text: string }[]> {
  const calls = (await (
    await env.MAILER!.fetch("https://mailer/__calls")
  ).json()) as {
    body: { message: { to: string; subject: string; text: string } };
  }[];
  return calls
    .filter((m) => m.body.message.to === email)
    .map((m) => m.body.message);
}

async function newClient(extra: Record<string, unknown> = {}) {
  const res = await call("/admin/clients", {
    method: "POST",
    headers: ADMIN,
    body: JSON.stringify({
      name: "Scouts Elewijt",
      redirect_uris: [REDIRECT],
      instance_url: APP,
      ...extra,
    }),
  });
  expect(res.status).toBe(201);
  return (await res.json()) as {
    client_id: string;
    client_secret: string;
    restricted: boolean;
  };
}

async function pkce() {
  const verifier = "v".repeat(20) + crypto.randomUUID().replace(/-/g, "");
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier),
  );
  return {
    verifier,
    challenge: btoa(String.fromCharCode(...new Uint8Array(digest)))
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/, ""),
  };
}

const authorizeUrl = (clientId: string, challenge: string) =>
  `/authorize?${new URLSearchParams({ response_type: "code", client_id: clientId, redirect_uri: REDIRECT, scope: "openid email offline_access", state: "s", code_challenge: challenge, code_challenge_method: "S256" })}`;

// The code flow to the end: the token response (or the page /authorize showed instead).
async function signInTo(
  client: { client_id: string; client_secret: string },
  cookie: string,
) {
  const { verifier, challenge } = await pkce();
  const res = await call(authorizeUrl(client.client_id, challenge), {
    headers: { Cookie: cookie },
  });
  if (res.status !== 302) return { page: res };
  const code = new URL(res.headers.get("Location")!).searchParams.get("code")!;
  const tokens = await post("/token", {
    grant_type: "authorization_code",
    code,
    redirect_uri: REDIRECT,
    client_id: client.client_id,
    client_secret: client.client_secret,
    code_verifier: verifier,
  });
  return { tokens: (await tokens.json()) as Record<string, string> };
}

describe("restricted clients", () => {
  it("are the default; the owner is the first admin; discovery names the users endpoint", async () => {
    const owner = uniqueEmail("owner");
    const client = await newClient({ owner_email: owner.toUpperCase() });
    expect(client.restricted).toBe(true);
    const row = await env.DB.prepare(
      "SELECT status, role FROM client_access WHERE client_id = ? AND email = ?",
    )
      .bind(client.client_id, owner)
      .first();
    expect(row).toEqual({ status: "assigned", role: "admin" });
    const discovery = (await (
      await call("/.well-known/openid-configuration")
    ).json()) as Record<string, string>;
    expect(discovery.client_users_endpoint).toBe(
      `${ISSUER}/clients/self/users`,
    );
    // Opened (and closed again) by the platform's admins.
    const open = await call(`/admin/clients/${client.client_id}`, {
      method: "PATCH",
      headers: ADMIN,
      body: JSON.stringify({ restricted: false }),
    });
    expect(await open.json()).toMatchObject({
      ok: true,
      restricted: false,
      redirect_uris: [REDIRECT],
    });
    const list = (await (
      await call("/admin/clients", { headers: ADMIN })
    ).json()) as { client_id: string; restricted: boolean }[];
    expect(list.find((c) => c.client_id === client.client_id)!.restricted).toBe(
      false,
    );
  });

  it("PATCH /admin/clients/:id replaces the URI lists (exact https URLs), never on a disabled client", async () => {
    const client = await newClient();
    const patch = (body: unknown) =>
      call(`/admin/clients/${client.client_id}`, {
        method: "PATCH",
        headers: ADMIN,
        body: JSON.stringify(body),
      });
    const res = await patch({
      redirect_uris: [REDIRECT, `${APP}/oauth2/callback`],
    });
    expect(await res.json()).toMatchObject({
      ok: true,
      restricted: true,
      redirect_uris: [REDIRECT, `${APP}/oauth2/callback`],
      post_logout_redirect_uris: [],
    });
    expect((await patch({ redirect_uris: [] })).status).toBe(400);
    expect(
      (await patch({ redirect_uris: ["http://evil.test/cb"] })).status,
    ).toBe(400);
    expect(
      (await patch({ post_logout_redirect_uris: ["https://x.test/#frag"] }))
        .status,
    ).toBe(400);
    expect((await patch({})).status).toBe(400);
    await call(`/admin/clients/${client.client_id}`, {
      method: "DELETE",
      headers: ADMIN,
    });
    expect((await patch({ redirect_uris: [REDIRECT] })).status).toBe(404);
  });

  it("flow 1: no access → a request → the admins get a mail → approved → signed in", async () => {
    const owner = uniqueEmail("owner");
    const client = await newClient({ owner_email: owner });
    const email = uniqueEmail("asker");
    const cookie = await signUp(email, "Mie Peeters");

    const { page } = await signInTo(client, cookie);
    expect(page!.status).toBe(403);
    const html = await page!.text();
    expect(html).toContain("Je hebt nog geen toegang tot Scouts Elewijt");
    expect(html).toContain(`action="/access/${client.client_id}/request"`);

    // A request from another site is refused; from here it goes out once.
    expect(
      (
        await post(
          `/access/${client.client_id}/request`,
          {},
          { Cookie: cookie, Origin: "https://evil.test" },
        )
      ).status,
    ).toBe(403);
    const asked = await post(
      `/access/${client.client_id}/request`,
      {},
      { Cookie: cookie },
    );
    expect(await asked.text()).toContain(
      "Je aanvraag voor Scouts Elewijt is verstuurd",
    );
    await post(`/access/${client.client_id}/request`, {}, { Cookie: cookie });
    const toOwner = (await mailsTo(owner)).filter(
      (m) => m.subject === "Aanvraag voor toegang tot Scouts Elewijt",
    );
    expect(toOwner).toHaveLength(1);
    expect(toOwner[0].text).toContain(`Mie Peeters (${email})`);
    expect(toOwner[0].text).toContain(`${ISSUER}/access/${client.client_id}`);
    // Still not in, and /authorize now says the request is on its way.
    expect(await (await signInTo(client, cookie)).page!.text()).toContain(
      "is verstuurd",
    );

    // Someone who isn't its admin can't see or decide.
    const notAdmin = await call(`/access/${client.client_id}`, {
      headers: { Cookie: cookie },
    });
    expect(notAdmin.status).toBe(403);
    const notAdminHtml = await notAdmin.text();
    expect(notAdminHtml).toContain(`Je bent aangemeld als ${email}`);
    expect(notAdminHtml).toContain(
      `href="/login?continue=${encodeURIComponent(`/access/${client.client_id}`)}"`,
    );
    const ownerCookie = await signUp(owner);
    const admin = await call(`/access/${client.client_id}`, {
      headers: { Cookie: ownerCookie },
    });
    expect(admin.status).toBe(200);
    const adminHtml = await admin.text();
    expect(adminHtml).toContain("Mie Peeters");
    expect(adminHtml).toContain("Toestaan");
    expect(
      await (
        await call("/account", { headers: { Cookie: ownerCookie } })
      ).text(),
    ).toContain(`href="/access/${client.client_id}"`);

    const approved = await post(
      `/access/${client.client_id}`,
      { action: "approve", email },
      { Cookie: ownerCookie },
    );
    expect(approved.headers.get("Location")).toBe(
      `/access/${client.client_id}?done=approved`,
    );
    const granted = (await mailsTo(email)).find(
      (m) => m.subject === "Je hebt toegang tot Scouts Elewijt",
    )!;
    expect(granted.text).toContain(`Meld je aan op ${APP}`);
    const { tokens } = await signInTo(client, cookie);
    expect(tokens!.access_token).toBeTruthy();
  });

  it("refusing a request removes it; the last admin stays; an admin adds someone by address", async () => {
    const owner = uniqueEmail("owner");
    const client = await newClient({ owner_email: owner });
    const ownerCookie = await signUp(owner);
    const email = uniqueEmail("refused");
    const cookie = await signUp(email);
    await post(`/access/${client.client_id}/request`, {}, { Cookie: cookie });
    await post(
      `/access/${client.client_id}`,
      { action: "refuse", email },
      { Cookie: ownerCookie },
    );
    expect(
      await env.DB.prepare(
        "SELECT 1 FROM client_access WHERE client_id = ? AND email = ?",
      )
        .bind(client.client_id, email)
        .first(),
    ).toBeNull();

    expect(
      (
        await post(
          `/access/${client.client_id}`,
          { action: "remove", email: owner },
          { Cookie: ownerCookie },
        )
      ).status,
    ).toBe(409);
    expect(
      (
        await post(
          `/access/${client.client_id}`,
          { action: "member", email: owner },
          { Cookie: ownerCookie },
        )
      ).status,
    ).toBe(409);
    expect(
      (
        await post(
          `/access/${client.client_id}`,
          { action: "add", email: "not-an-address" },
          { Cookie: ownerCookie },
        )
      ).status,
    ).toBe(400);

    const later = uniqueEmail("added");
    await post(
      `/access/${client.client_id}`,
      { action: "add", email: later.toUpperCase() },
      { Cookie: ownerCookie },
    );
    // A second admin: now the owner may step down.
    await post(
      `/access/${client.client_id}`,
      { action: "admin", email: later },
      { Cookie: ownerCookie },
    );
    expect(
      (
        await post(
          `/access/${client.client_id}`,
          { action: "member", email: owner },
          { Cookie: ownerCookie },
        )
      ).status,
    ).toBe(303);
    expect(
      (await signInTo(client, await signUp(later))).tokens!.access_token,
    ).toBeTruthy();
  });

  it("a guest gets no access and no request button; an open client lets anyone in", async () => {
    const client = await newClient();
    const guest = (await (
      await call("/admin/guests", {
        method: "POST",
        headers: ADMIN,
        body: "{}",
      })
    ).json()) as { sub: string };
    const link = (await (
      await call("/admin/login-links", {
        method: "POST",
        headers: ADMIN,
        body: JSON.stringify({ sub: guest.sub, continue_to: `${APP}/` }),
      })
    ).json()) as { url: string };
    const cookie = cookieOf(
      await call(new URL(link.url).pathname + new URL(link.url).search),
    );
    const { page } = await signInTo(client, cookie);
    expect(page!.status).toBe(403);
    expect(await page!.text()).not.toContain("/request");

    const open = await newClient({ restricted: false });
    expect(
      (await signInTo(open, await signUp(uniqueEmail("anyone")))).tokens!
        .access_token,
    ).toBeTruthy();
  });
});

describe("the application assigns (/clients/self/users)", () => {
  it("assigns an address before it has an account; unassigning revokes its refresh tokens", async () => {
    const client = await newClient({ owner_email: uniqueEmail("owner") });
    const email = uniqueEmail("invited");
    expect(
      (
        await call(`/clients/self/users/${encodeURIComponent(email)}`, {
          method: "PUT",
          headers: { Authorization: "Basic d3Jvbmc6d3Jvbmc=" },
        })
      ).status,
    ).toBe(401);
    const put = await call(
      `/clients/self/users/${encodeURIComponent(email.toUpperCase())}`,
      { method: "PUT", headers: basic(client) },
    );
    expect(await put.json()).toEqual({
      email,
      status: "assigned",
      role: "member",
    });

    const { tokens } = await signInTo(client, await signUp(email));
    expect(tokens!.refresh_token).toBeTruthy();

    const removed = await call(
      `/clients/self/users/${encodeURIComponent(email)}`,
      { method: "DELETE", headers: basic(client) },
    );
    expect(await removed.json()).toEqual({ email, removed: true });
    const refreshed = await post("/token", {
      grant_type: "refresh_token",
      refresh_token: tokens!.refresh_token,
      client_id: client.client_id,
      client_secret: client.client_secret,
    });
    expect(((await refreshed.json()) as Record<string, string>).error).toBe(
      "invalid_grant",
    );
    expect(
      await call(`/clients/self/users/${encodeURIComponent(email)}`, {
        method: "DELETE",
        headers: basic(client),
      }).then((r) => r.json()),
    ).toEqual({ email, removed: false });
  });

  it("a pending request becomes an assignment; an admin is never unassigned; bulk and list", async () => {
    const owner = uniqueEmail("owner");
    const client = await newClient({ owner_email: owner });
    const email = uniqueEmail("asked");
    await post(
      `/access/${client.client_id}/request`,
      {},
      { Cookie: await signUp(email) },
    );
    await call(`/clients/self/users/${encodeURIComponent(email)}`, {
      method: "PUT",
      headers: basic(client),
    });
    expect(
      await call(`/clients/self/users/${encodeURIComponent(owner)}`, {
        method: "DELETE",
        headers: basic(client),
      }).then((r) => r.json()),
    ).toEqual({ email: owner, removed: false, reason: "admin" });

    const many = [uniqueEmail("a"), uniqueEmail("b")];
    const bulk = await call("/clients/self/users", {
      method: "POST",
      headers: { ...basic(client), "Content-Type": "application/json" },
      body: JSON.stringify({ emails: [...many, many[0]] }),
    });
    expect(await bulk.json()).toEqual({ assigned: 2 });
    expect(
      (
        await call("/clients/self/users", {
          method: "POST",
          headers: { ...basic(client), "Content-Type": "application/json" },
          body: JSON.stringify({ emails: ["nope"] }),
        })
      ).status,
    ).toBe(400);
    const list = (await (
      await call("/clients/self/users", { headers: basic(client) })
    ).json()) as {
      restricted: boolean;
      users: { email: string; status: string; role: string }[];
    };
    expect(list.restricted).toBe(true);
    expect(list.users.map((u) => u.email).sort()).toEqual(
      [email, owner, ...many].sort(),
    );
    expect(list.users.every((u) => u.status === "assigned")).toBe(true);
  });
});

describe("client admins named by the application", () => {
  const put = (
    client: { client_id: string; client_secret: string },
    email: string,
    role?: string,
  ) =>
    call(`/clients/self/users/${encodeURIComponent(email)}`, {
      method: "PUT",
      headers: { ...basic(client), "Content-Type": "application/json" },
      body: JSON.stringify(role ? { role } : {}),
    });
  const rowOf = (clientId: string, email: string) =>
    env.DB.prepare(
      "SELECT status, role, app_admin FROM client_access WHERE client_id = ? AND email = ?",
    )
      .bind(clientId, email)
      .first<{ status: string; role: string; app_admin: number }>();

  it("an admin it names manages the client; it takes that back and can remove them — never the owner or a manual admin", async () => {
    const owner = uniqueEmail("owner");
    const client = await newClient({ owner_email: owner });
    const orgAdmin = uniqueEmail("orgadmin");
    expect(await (await put(client, orgAdmin, "admin")).json()).toEqual({
      email: orgAdmin,
      status: "assigned",
      role: "admin",
    });
    expect(
      (
        await call(`/access/${client.client_id}`, {
          headers: { Cookie: await signUp(orgAdmin) },
        })
      ).status,
    ).toBe(200);

    await put(client, orgAdmin, "member");
    expect(await rowOf(client.client_id, orgAdmin)).toEqual({
      status: "assigned",
      role: "member",
      app_admin: 0,
    });
    await put(client, orgAdmin, "admin");
    expect(
      await call(`/clients/self/users/${encodeURIComponent(orgAdmin)}`, {
        method: "DELETE",
        headers: basic(client),
      }).then((r) => r.json()),
    ).toEqual({ email: orgAdmin, removed: true });

    // The owner, and someone made admin by hand, stay admins whatever the application says.
    await put(client, owner, "member");
    expect((await rowOf(client.client_id, owner))!.role).toBe("admin");
    const manual = uniqueEmail("manual");
    await put(client, manual, "admin");
    await post(
      `/access/${client.client_id}`,
      { action: "member", email: manual },
      { Cookie: await signUp(owner) },
    );
    await post(
      `/access/${client.client_id}`,
      { action: "admin", email: manual },
      { Cookie: await signUp(owner) },
    );
    expect(await rowOf(client.client_id, manual)).toEqual({
      status: "assigned",
      role: "admin",
      app_admin: 0,
    });
    await put(client, manual, "member");
    expect((await rowOf(client.client_id, manual))!.role).toBe("admin");
    expect(
      await call(`/clients/self/users/${encodeURIComponent(manual)}`, {
        method: "DELETE",
        headers: basic(client),
      }).then((r) => r.json()),
    ).toEqual({ email: manual, removed: false, reason: "admin" });
  });

  it("bulk with roles; a request becomes an app-made admin; an open client gets no admins this way; a wrong role is refused", async () => {
    const client = await newClient({ owner_email: uniqueEmail("owner") });
    const asker = uniqueEmail("asker");
    await post(
      `/access/${client.client_id}/request`,
      {},
      { Cookie: await signUp(asker) },
    );
    const cashier = uniqueEmail("cashier");
    const bulk = await call("/clients/self/users", {
      method: "POST",
      headers: { ...basic(client), "Content-Type": "application/json" },
      body: JSON.stringify({
        users: [
          { email: asker.toUpperCase(), role: "admin" },
          { email: cashier },
        ],
      }),
    });
    expect(await bulk.json()).toEqual({ assigned: 2 });
    expect(await rowOf(client.client_id, asker)).toEqual({
      status: "assigned",
      role: "admin",
      app_admin: 1,
    });
    expect(await rowOf(client.client_id, cashier)).toEqual({
      status: "assigned",
      role: "member",
      app_admin: 0,
    });
    expect((await put(client, cashier, "owner")).status).toBe(400);

    const open = await newClient({ restricted: false });
    const visitor = uniqueEmail("visitor");
    await put(open, visitor, "admin");
    expect(await rowOf(open.client_id, visitor)).toEqual({
      status: "assigned",
      role: "member",
      app_admin: 0,
    });
  });
});

describe("a kassa (device grant) on a restricted client", () => {
  it("an unassigned phone sees the access page and cannot approve; assigned, it can", async () => {
    const client = await newClient();
    const email = uniqueEmail("phone");
    const cookie = await signUp(email);
    const d = (await (
      await post("/device/code", {
        client_id: client.client_id,
        scope: "openid offline_access",
      })
    ).json()) as { device_code: string; user_code: string };
    const page = await call(`/device?user_code=${d.user_code}`, {
      headers: { Cookie: cookie },
    });
    expect(page.status).toBe(403);
    expect(await page.text()).toContain("Toegang vragen");
    expect(
      (
        await post(
          "/device/confirm",
          { user_code: d.user_code, decision: "allow" },
          { Cookie: cookie },
        )
      ).status,
    ).toBe(403);

    await call(`/clients/self/users/${encodeURIComponent(email)}`, {
      method: "PUT",
      headers: basic(client),
    });
    expect(
      (
        await post(
          "/device/confirm",
          { user_code: d.user_code, decision: "allow" },
          { Cookie: cookie },
        )
      ).status,
    ).toBe(200);
    const tokens = await post("/token", {
      grant_type: "urn:ietf:params:oauth:grant-type:device_code",
      device_code: d.device_code,
      client_id: client.client_id,
      client_secret: client.client_secret,
    });
    expect(tokens.status).toBe(200);
  });
});

describe("a client's addresses on its access page", () => {
  it("an application's admin edits them (each list replaced); the other admins get a mail; a wrong one is refused", async () => {
    const owner = uniqueEmail("owner");
    const client = await newClient({
      owner_email: owner,
      instance_url: null,
      redirect_uris: ["https://editor.example.test/auth/callback"],
    });
    const other = uniqueEmail("other");
    await call(`/clients/self/users/${encodeURIComponent(other)}`, {
      method: "PUT",
      headers: { ...basic(client), "Content-Type": "application/json" },
      body: JSON.stringify({ role: "admin" }),
    });
    const cookie = await signUp(owner);

    const page = await (
      await call(`/access/${client.client_id}`, { headers: { Cookie: cookie } })
    ).text();
    expect(page).toContain('data-testid="client-hosts">editor.example.test<');
    expect(page).toContain('name="redirect_uris"');
    expect(
      await (await call("/account", { headers: { Cookie: cookie } })).text(),
    ).toContain("editor.example.test");
    // On /account only its own domains: no *.workers.dev addresses — and an
    // installation named after its workers.dev address shows its own domain instead.
    const installation = await newClient({
      name: "Arcanum — someone.workers.dev",
      owner_email: owner,
      redirect_uris: [
        "https://arcanum-bff.someone.workers.dev/callback",
        "https://kassa.club.test/callback",
      ],
    });
    const account = await (
      await call("/account", { headers: { Cookie: cookie } })
    ).text();
    expect(account).toContain(`href="/access/${installation.client_id}"`);
    expect(account).toContain("kassa.club.test");
    expect(account).not.toContain("someone.workers.dev");
    expect(account).toContain("Arcanum — kassa.club.test");

    const saved = await post(
      `/access/${client.client_id}`,
      {
        action: "uris",
        redirect_uris:
          "https://editor.example.test/auth/callback\nhttps://editor.example.test/oauth2/callback",
        post_logout_redirect_uris: "",
      },
      { Cookie: cookie },
    );
    expect(saved.headers.get("Location")).toBe(
      `/access/${client.client_id}?done=uris`,
    );
    const row = await env.DB.prepare(
      "SELECT redirect_uris, post_logout_redirect_uris FROM clients WHERE id = ?",
    )
      .bind(client.client_id)
      .first<{ redirect_uris: string; post_logout_redirect_uris: string }>();
    expect(JSON.parse(row!.redirect_uris)).toEqual([
      "https://editor.example.test/auth/callback",
      "https://editor.example.test/oauth2/callback",
    ]);
    expect(JSON.parse(row!.post_logout_redirect_uris)).toEqual([]);
    const mail = (await mailsTo(other)).find(
      (m) => m.subject === "Adressen van Scouts Elewijt gewijzigd",
    )!;
    expect(mail.text).toContain(`${owner} wijzigde`);
    expect(mail.text).toContain("https://editor.example.test/oauth2/callback");
    expect(
      await mailsTo(owner).then((list) =>
        list.some((m) => m.subject.startsWith("Adressen van")),
      ),
    ).toBe(false);

    const refused = await post(
      `/access/${client.client_id}`,
      { action: "uris", redirect_uris: "http://evil.test/cb" },
      { Cookie: cookie },
    );
    expect(refused.status).toBe(400);
    expect(await refused.text()).toContain("Geef 1 tot 10 https-adressen");
    expect(
      (
        await post(
          `/access/${client.client_id}`,
          { action: "uris", redirect_uris: "" },
          { Cookie: cookie },
        )
      ).status,
    ).toBe(400);
  });

  it("an installation's are shown, not edited — its installer keeps them; posting changes nothing", async () => {
    const owner = uniqueEmail("owner");
    const client = await newClient({ owner_email: owner });
    const cookie = await signUp(owner);
    const page = await (
      await call(`/access/${client.client_id}`, { headers: { Cookie: cookie } })
    ).text();
    expect(page).toContain("Deze adressen beheert de installatie zelf");
    expect(page).not.toContain('name="redirect_uris"');
    await post(
      `/access/${client.client_id}`,
      { action: "uris", redirect_uris: "https://other.test/cb" },
      { Cookie: cookie },
    );
    const row = await env.DB.prepare(
      "SELECT redirect_uris FROM clients WHERE id = ?",
    )
      .bind(client.client_id)
      .first<{ redirect_uris: string }>();
    expect(JSON.parse(row!.redirect_uris)).toEqual([REDIRECT]);
  });
});

describe("shownName", () => {
  it("an installation named after its workers.dev address shows its own domain; anything else stays", async () => {
    const { shownName } = await import("../src/store");
    expect(
      shownName(
        "Arcanum — throbbing-mouse-73a8.workers.dev",
        "https://arcanum-bff.throbbing-mouse-73a8.workers.dev",
        [
          "https://arcanum-bff.throbbing-mouse-73a8.workers.dev/callback",
          "https://arcanum-installer.throbbing-mouse-73a8.workers.dev/auth/callback",
          "https://arcanum.esvvzw.be/callback",
        ],
      ),
    ).toBe("Arcanum — arcanum.esvvzw.be");
    expect(
      shownName(
        "Arcanum — x.workers.dev",
        "https://arcanum-bff.x.workers.dev",
        ["https://arcanum-bff.x.workers.dev/callback"],
      ),
    ).toBe("Arcanum — x.workers.dev");
    expect(
      shownName("tresjr on Docker — a@b.test", "docker", [
        "http://localhost:8080/auth/callback",
      ]),
    ).toBe("tresjr on Docker — a@b.test");
    expect(
      shownName("Webstudio", null, ["https://editor.kaboutersoft.be/cb"]),
    ).toBe("Webstudio");
    expect(
      shownName("Arcanum — x.workers.dev", null, ["https://own.test/cb"]),
    ).toBe("Arcanum — x.workers.dev");
  });
});
