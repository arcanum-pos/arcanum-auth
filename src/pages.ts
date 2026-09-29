// The issuer's own pages — sign in, create an account, verify an e-mail,
// reset a password, connect a device. Plain server-rendered HTML (no
// scripts), in the browser's language (nl/fr/en), light or dark.

type Lang = 'nl' | 'fr' | 'en';

const T = {
  nl: {
    signIn: 'Aanmelden',
    email: 'E-mailadres',
    password: 'Wachtwoord',
    name: 'Naam',
    submitSignIn: 'Aanmelden',
    withGoogle: 'Aanmelden met Google',
    or: 'of',
    noAccount: 'Nog geen account?',
    createAccount: 'Account aanmaken',
    forgot: 'Wachtwoord vergeten?',
    haveAccount: 'Al een account?',
    passwordHint: 'Minstens 10 tekens.',
    create: 'Account aanmaken',
    verifyTitle: 'Bevestig je e-mailadres',
    verifyText: (email: string) => `We stuurden een code van 6 cijfers naar ${email}. Vul ze hier in.`,
    code: 'Code',
    confirm: 'Bevestigen',
    resetTitle: 'Wachtwoord vergeten',
    resetText: 'Vul je e-mailadres in; als er een account bij hoort, sturen we een code om een nieuw wachtwoord te kiezen.',
    sendCode: 'Code sturen',
    newPassword: 'Nieuw wachtwoord',
    resetDoneTitle: 'Nieuw wachtwoord kiezen',
    resetDoneText: (email: string) => `Als ${email} bij een account hoort, staat er nu een code in je mailbox.`,
    save: 'Opslaan',
    deviceTitle: 'Toestel koppelen',
    deviceText: 'Vul de code in die op het toestel staat.',
    next: 'Verder',
    deviceConfirm: (client: string) => `Aanmelden op een toestel van ${client}?`,
    deviceConfirmText: 'Doe dit alleen voor een toestel dat voor je staat en waarop je deze code net zag.',
    allow: 'Toestaan',
    deny: 'Weigeren',
    deviceDone: 'Het toestel is aangemeld. Je kan dit venster sluiten.',
    deviceDenied: 'Geweigerd. Het toestel wordt niet aangemeld.',
    signedInAs: (email: string) => `Aangemeld als ${email}.`,
    signOut: 'Afmelden',
    signedOut: 'Je bent afgemeld.',
    errors: {
      invalid: 'E-mailadres of wachtwoord klopt niet.',
      tooMany: 'Te veel pogingen. Probeer het over een kwartier opnieuw.',
      emailInvalid: 'Vul een geldig e-mailadres in.',
      passwordShort: 'Het wachtwoord moet minstens 10 tekens hebben.',
      exists: 'Er bestaat al een account met dit e-mailadres. Meld je aan, of kies "Wachtwoord vergeten".',
      codeInvalid: 'Deze code klopt niet of is verlopen.',
      deviceCode: 'Deze code klopt niet of is verlopen. Kijk nog eens op het toestel.',
      google: 'Aanmelden met Google is niet gelukt.',
      googleUnverified: 'Dit Google-account heeft geen bevestigd e-mailadres.',
      request: 'Deze aanvraag is ongeldig.',
      mail: 'De e-mail kon niet verstuurd worden. Probeer het later opnieuw.',
      linkInvalid: 'Deze aanmeldlink is al gebruikt of verlopen. Vraag een nieuwe aan.',
    },
    mailSignupSubject: 'Je code voor Arcanum',
    mailSignup: (code: string) => `Je code om je account te bevestigen: ${code}\n\nDe code is 15 minuten geldig. Heb je dit niet gevraagd? Dan kan je deze e-mail negeren.`,
    mailResetSubject: 'Nieuw wachtwoord voor Arcanum',
    mailReset: (code: string) => `Je code om een nieuw wachtwoord te kiezen: ${code}\n\nDe code is 15 minuten geldig. Heb je dit niet gevraagd? Dan kan je deze e-mail negeren.`,
  },
  fr: {
    signIn: 'Connexion',
    email: 'Adresse e-mail',
    password: 'Mot de passe',
    name: 'Nom',
    submitSignIn: 'Se connecter',
    withGoogle: 'Se connecter avec Google',
    or: 'ou',
    noAccount: 'Pas encore de compte ?',
    createAccount: 'Créer un compte',
    forgot: 'Mot de passe oublié ?',
    haveAccount: 'Déjà un compte ?',
    passwordHint: 'Au moins 10 caractères.',
    create: 'Créer le compte',
    verifyTitle: 'Confirmez votre adresse e-mail',
    verifyText: (email: string) => `Nous avons envoyé un code de 6 chiffres à ${email}. Saisissez-le ici.`,
    code: 'Code',
    confirm: 'Confirmer',
    resetTitle: 'Mot de passe oublié',
    resetText: 'Saisissez votre adresse e-mail ; si un compte y est lié, nous envoyons un code pour choisir un nouveau mot de passe.',
    sendCode: 'Envoyer le code',
    newPassword: 'Nouveau mot de passe',
    resetDoneTitle: 'Choisir un nouveau mot de passe',
    resetDoneText: (email: string) => `Si ${email} est lié à un compte, un code se trouve maintenant dans votre boîte mail.`,
    save: 'Enregistrer',
    deviceTitle: 'Connecter un appareil',
    deviceText: 'Saisissez le code affiché sur l’appareil.',
    next: 'Continuer',
    deviceConfirm: (client: string) => `Se connecter sur un appareil de ${client} ?`,
    deviceConfirmText: 'Ne faites ceci que pour un appareil devant vous, sur lequel vous venez de voir ce code.',
    allow: 'Autoriser',
    deny: 'Refuser',
    deviceDone: 'L’appareil est connecté. Vous pouvez fermer cette fenêtre.',
    deviceDenied: 'Refusé. L’appareil ne sera pas connecté.',
    signedInAs: (email: string) => `Connecté en tant que ${email}.`,
    signOut: 'Se déconnecter',
    signedOut: 'Vous êtes déconnecté.',
    errors: {
      invalid: 'Adresse e-mail ou mot de passe incorrect.',
      tooMany: 'Trop de tentatives. Réessayez dans un quart d’heure.',
      emailInvalid: 'Saisissez une adresse e-mail valable.',
      passwordShort: 'Le mot de passe doit contenir au moins 10 caractères.',
      exists: 'Un compte existe déjà avec cette adresse. Connectez-vous, ou choisissez « Mot de passe oublié ».',
      codeInvalid: 'Ce code est incorrect ou expiré.',
      deviceCode: 'Ce code est incorrect ou expiré. Vérifiez l’appareil.',
      google: 'La connexion avec Google a échoué.',
      googleUnverified: 'Ce compte Google n’a pas d’adresse e-mail confirmée.',
      request: 'Cette demande n’est pas valable.',
      mail: 'L’e-mail n’a pas pu être envoyé. Réessayez plus tard.',
      linkInvalid: 'Ce lien de connexion a déjà été utilisé ou a expiré. Demandez-en un nouveau.',
    },
    mailSignupSubject: 'Votre code pour Arcanum',
    mailSignup: (code: string) => `Votre code pour confirmer votre compte : ${code}\n\nLe code est valable 15 minutes. Vous n’avez rien demandé ? Ignorez cet e-mail.`,
    mailResetSubject: 'Nouveau mot de passe pour Arcanum',
    mailReset: (code: string) => `Votre code pour choisir un nouveau mot de passe : ${code}\n\nLe code est valable 15 minutes. Vous n’avez rien demandé ? Ignorez cet e-mail.`,
  },
  en: {
    signIn: 'Sign in',
    email: 'Email address',
    password: 'Password',
    name: 'Name',
    submitSignIn: 'Sign in',
    withGoogle: 'Sign in with Google',
    or: 'or',
    noAccount: 'No account yet?',
    createAccount: 'Create an account',
    forgot: 'Forgot your password?',
    haveAccount: 'Already have an account?',
    passwordHint: 'At least 10 characters.',
    create: 'Create account',
    verifyTitle: 'Confirm your email address',
    verifyText: (email: string) => `We sent a 6-digit code to ${email}. Enter it here.`,
    code: 'Code',
    confirm: 'Confirm',
    resetTitle: 'Forgot your password',
    resetText: 'Enter your email address; if an account belongs to it, we send a code to choose a new password.',
    sendCode: 'Send code',
    newPassword: 'New password',
    resetDoneTitle: 'Choose a new password',
    resetDoneText: (email: string) => `If ${email} belongs to an account, there is now a code in your mailbox.`,
    save: 'Save',
    deviceTitle: 'Connect a device',
    deviceText: 'Enter the code shown on the device.',
    next: 'Continue',
    deviceConfirm: (client: string) => `Sign in on a device of ${client}?`,
    deviceConfirmText: 'Only do this for a device in front of you, on which you just saw this code.',
    allow: 'Allow',
    deny: 'Deny',
    deviceDone: 'The device is signed in. You can close this window.',
    deviceDenied: 'Denied. The device will not be signed in.',
    signedInAs: (email: string) => `Signed in as ${email}.`,
    signOut: 'Sign out',
    signedOut: 'You are signed out.',
    errors: {
      invalid: 'Email address or password is incorrect.',
      tooMany: 'Too many attempts. Try again in a quarter of an hour.',
      emailInvalid: 'Enter a valid email address.',
      passwordShort: 'The password must be at least 10 characters.',
      exists: 'An account with this email address already exists. Sign in, or choose "Forgot your password".',
      codeInvalid: 'This code is incorrect or has expired.',
      deviceCode: 'This code is incorrect or has expired. Check the device again.',
      google: 'Signing in with Google failed.',
      googleUnverified: 'This Google account has no confirmed email address.',
      request: 'This request is not valid.',
      mail: 'The email could not be sent. Try again later.',
      linkInvalid: 'This sign-in link has already been used or has expired. Ask for a new one.',
    },
    mailSignupSubject: 'Your code for Arcanum',
    mailSignup: (code: string) => `Your code to confirm your account: ${code}\n\nThe code is valid for 15 minutes. Didn't ask for this? Then ignore this email.`,
    mailResetSubject: 'New password for Arcanum',
    mailReset: (code: string) => `Your code to choose a new password: ${code}\n\nThe code is valid for 15 minutes. Didn't ask for this? Then ignore this email.`,
  },
} satisfies Record<Lang, unknown>;

export type Texts = (typeof T)['nl'];
export type ErrorKey = keyof Texts['errors'];

export function language(request: Request): Lang {
  for (const part of (request.headers.get('Accept-Language') || '').split(',')) {
    const base = part.trim().split(';')[0].split('-')[0].toLowerCase();
    if (base === 'nl' || base === 'fr' || base === 'en') return base;
  }
  return 'nl';
}

export function texts(request: Request): Texts {
  return T[language(request)] as Texts;
}

export function esc(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

const STYLE = `
:root{--bg:#fafafa;--card:#fff;--fg:#0a0a0a;--muted:#737373;--border:#e5e5e5;--primary:#0a0a0a;--on-primary:#fff;--danger:#b91c1c}
@media (prefers-color-scheme:dark){:root{--bg:#0a0a0a;--card:#171717;--fg:#fafafa;--muted:#a3a3a3;--border:#262626;--primary:#fafafa;--on-primary:#0a0a0a;--danger:#f87171}}
*{box-sizing:border-box}body{margin:0;min-height:100svh;display:flex;align-items:center;justify-content:center;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,-apple-system,"Segoe UI",sans-serif;padding:24px}
main{width:100%;max-width:380px;background:var(--card);border:1px solid var(--border);border-radius:16px;padding:28px}
.brand{font-weight:700;letter-spacing:-.02em;margin-bottom:18px}h1{font-size:22px;letter-spacing:-.02em;margin:0 0 6px}p{margin:0 0 14px;color:var(--muted)}
label{display:block;font-size:13px;font-weight:600;margin:14px 0 6px}input{width:100%;height:42px;border:1px solid var(--border);border-radius:10px;background:transparent;color:var(--fg);padding:0 12px;font:inherit}
input.code{letter-spacing:.3em;text-align:center;font-size:20px;font-family:ui-monospace,monospace;text-transform:uppercase}
button,.button{display:flex;align-items:center;justify-content:center;width:100%;height:44px;margin-top:18px;border-radius:10px;border:1px solid var(--primary);background:var(--primary);color:var(--on-primary);font:600 15px system-ui,sans-serif;text-decoration:none;cursor:pointer}
.secondary{background:transparent;color:var(--fg);border-color:var(--border)}.row{display:flex;gap:10px}.row>*{flex:1}
.error{color:var(--danger);font-size:14px;margin:12px 0 0}.hint{font-size:12.5px;margin:6px 0 0}.links{margin-top:18px;font-size:13.5px;display:flex;flex-direction:column;gap:6px}
a{color:var(--fg)}.or{text-align:center;color:var(--muted);font-size:13px;margin:16px 0 0}`;

export function page(request: Request, title: string, body: string, status = 200, headers: Record<string, string> = {}): Response {
  const html = `<!doctype html><html lang="${language(request)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>${esc(title)} · Arcanum</title><style>${STYLE}</style></head>
<body><main><div class="brand">arcanum</div>${body}</main></body></html>`;
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https:; frame-ancestors 'none'; base-uri 'none'",
      'X-Frame-Options': 'DENY',
      // Not no-referrer: that makes browsers send `Origin: null` on our own
      // form posts. same-origin still leaks nothing to other sites (Google).
      'Referrer-Policy': 'same-origin',
      ...headers,
    },
  });
}

const hidden = (name: string, value: string) => `<input type="hidden" name="${name}" value="${esc(value)}">`;
const error = (t: Texts, key?: ErrorKey | null) => (key ? `<p class="error" role="alert">${esc(t.errors[key])}</p>` : '');

export function loginPage(request: Request, opts: { continueTo: string; email?: string; error?: ErrorKey | null; google: boolean }, status = 200) {
  const t = texts(request);
  const q = `?continue=${encodeURIComponent(opts.continueTo)}`;
  return page(
    request,
    t.signIn,
    `<h1>${t.signIn}</h1>
<form method="post" action="/login">${hidden('continue', opts.continueTo)}
<label for="email">${t.email}</label><input id="email" name="email" type="email" autocomplete="username" required value="${esc(opts.email ?? '')}">
<label for="password">${t.password}</label><input id="password" name="password" type="password" autocomplete="current-password" required>
${error(t, opts.error)}<button type="submit">${t.submitSignIn}</button></form>
${opts.google ? `<p class="or">${t.or}</p><a class="button secondary" href="/google${q}">${t.withGoogle}</a>` : ''}
<div class="links"><span>${t.noAccount} <a href="/signup${q}">${t.createAccount}</a></span><a href="/reset${q}">${t.forgot}</a></div>`,
    status
  );
}

export function signupPage(request: Request, opts: { continueTo: string; email?: string; name?: string; error?: ErrorKey | null; google: boolean }, status = 200) {
  const t = texts(request);
  const q = `?continue=${encodeURIComponent(opts.continueTo)}`;
  return page(
    request,
    t.createAccount,
    `<h1>${t.createAccount}</h1>
<form method="post" action="/signup">${hidden('continue', opts.continueTo)}
<label for="name">${t.name}</label><input id="name" name="name" autocomplete="name" required maxlength="100" value="${esc(opts.name ?? '')}">
<label for="email">${t.email}</label><input id="email" name="email" type="email" autocomplete="email" required value="${esc(opts.email ?? '')}">
<label for="password">${t.password}</label><input id="password" name="password" type="password" autocomplete="new-password" required minlength="10">
<p class="hint">${t.passwordHint}</p>${error(t, opts.error)}<button type="submit">${t.create}</button></form>
${opts.google ? `<p class="or">${t.or}</p><a class="button secondary" href="/google${q}">${t.withGoogle}</a>` : ''}
<div class="links"><span>${t.haveAccount} <a href="/login${q}">${t.signIn}</a></span></div>`,
    status
  );
}

export function verifyPage(request: Request, opts: { id: string; email: string; continueTo: string; error?: ErrorKey | null }, status = 200) {
  const t = texts(request);
  return page(
    request,
    t.verifyTitle,
    `<h1>${t.verifyTitle}</h1><p>${esc(t.verifyText(opts.email))}</p>
<form method="post" action="/verify">${hidden('id', opts.id)}${hidden('continue', opts.continueTo)}
<label for="code">${t.code}</label><input id="code" class="code" name="code" inputmode="numeric" autocomplete="one-time-code" required maxlength="6">
${error(t, opts.error)}<button type="submit">${t.confirm}</button></form>`,
    status
  );
}

export function resetRequestPage(request: Request, opts: { continueTo: string; error?: ErrorKey | null }, status = 200) {
  const t = texts(request);
  return page(
    request,
    t.resetTitle,
    `<h1>${t.resetTitle}</h1><p>${t.resetText}</p>
<form method="post" action="/reset">${hidden('continue', opts.continueTo)}
<label for="email">${t.email}</label><input id="email" name="email" type="email" autocomplete="email" required>
${error(t, opts.error)}<button type="submit">${t.sendCode}</button></form>`,
    status
  );
}

export function resetCodePage(request: Request, opts: { id: string; email: string; continueTo: string; error?: ErrorKey | null }, status = 200) {
  const t = texts(request);
  return page(
    request,
    t.resetDoneTitle,
    `<h1>${t.resetDoneTitle}</h1><p>${esc(t.resetDoneText(opts.email))}</p>
<form method="post" action="/reset/confirm">${hidden('id', opts.id)}${hidden('continue', opts.continueTo)}
<label for="code">${t.code}</label><input id="code" class="code" name="code" inputmode="numeric" autocomplete="one-time-code" required maxlength="6">
<label for="password">${t.newPassword}</label><input id="password" name="password" type="password" autocomplete="new-password" required minlength="10">
<p class="hint">${t.passwordHint}</p>${error(t, opts.error)}<button type="submit">${t.save}</button></form>`,
    status
  );
}

export function deviceCodePage(request: Request, opts: { userCode?: string; error?: ErrorKey | null }, status = 200) {
  const t = texts(request);
  return page(
    request,
    t.deviceTitle,
    `<h1>${t.deviceTitle}</h1><p>${t.deviceText}</p>
<form method="post" action="/device">
<label for="user_code">${t.code}</label><input id="user_code" class="code" name="user_code" required autocomplete="off" value="${esc(opts.userCode ?? '')}">
${error(t, opts.error)}<button type="submit">${t.next}</button></form>`,
    status
  );
}

export function deviceConfirmPage(request: Request, opts: { userCode: string; clientName: string; email: string }) {
  const t = texts(request);
  return page(
    request,
    t.deviceTitle,
    `<h1>${esc(t.deviceConfirm(opts.clientName))}</h1><p>${t.deviceConfirmText}</p><p>${esc(t.signedInAs(opts.email))}</p>
<p style="font-family:ui-monospace,monospace;font-size:22px;letter-spacing:.2em;color:var(--fg);text-align:center">${esc(opts.userCode)}</p>
<form method="post" action="/device/confirm" class="row">${hidden('user_code', opts.userCode)}
<button type="submit" name="decision" value="deny" class="secondary">${t.deny}</button><button type="submit" name="decision" value="allow">${t.allow}</button></form>`
  );
}

export function messagePage(request: Request, message: string, status = 200) {
  return page(request, 'Arcanum', `<p style="color:var(--fg)">${esc(message)}</p>`, status);
}

export function accountPage(request: Request, email: string) {
  const t = texts(request);
  return page(request, 'Arcanum', `<p style="color:var(--fg)">${esc(t.signedInAs(email))}</p><a class="button secondary" href="/logout">${t.signOut}</a>`);
}
