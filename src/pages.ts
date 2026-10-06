// The issuer's own pages — sign in, create an account, verify an e-mail,
// reset a password, connect a device, manage passkeys. Server-rendered HTML
// in the browser's language (nl/fr/en), light or dark. The only script is
// /passkey.js (passkeys need the browser's WebAuthn API), on the pages that
// offer them.

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
    withPasskey: 'Aanmelden met een passkey',
    accountTitle: 'Je account',
    passkeysTitle: 'Passkeys',
    passkeysIntro: 'Met een passkey meld je je aan met je vingerafdruk, je gezicht of de pincode van je toestel — zonder wachtwoord.',
    noPasskeys: 'Nog geen passkeys.',
    addPasskey: 'Passkey toevoegen',
    passkeyAdded: 'Passkey toegevoegd.',
    passkeyMeta: (created: string, used: string | null) => `Toegevoegd op ${created}` + (used ? ` · laatst gebruikt op ${used}` : ''),
    rename: 'Naam wijzigen',
    remove: 'Verwijderen',
    passkeyName: 'Naam',
    passkeyUnsupported: 'Deze browser ondersteunt geen passkeys.',
    offerTitle: 'Sneller aanmelden met een passkey?',
    offerText: 'Meld je voortaan aan met je vingerafdruk, je gezicht of de pincode van dit toestel — zonder wachtwoord. Je huidige manier van aanmelden blijft ook werken.',
    notNow: 'Niet nu',
    mailPasskeySubject: 'Nieuwe passkey voor je Arcanum-account',
    mailPasskey: (name: string, accountUrl: string) => `Er werd een passkey ("${name}") aan je account toegevoegd.\n\nWas jij dat niet? Verwijder hem op ${accountUrl} en wijzig je wachtwoord.`,
    securityKey: 'Beveiligingssleutel',
    phone: 'Telefoon',
    kindSecurityKey: (how: string) => `Beveiligingssleutel${how ? ` · ${how}` : ''}`,
    kindSynced: 'Gesynchroniseerd tussen je toestellen',
    kindDevice: 'Alleen op het toestel waarop hij gemaakt werd',
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
      passkeyFailed: 'Aanmelden met een passkey is niet gelukt. Probeer opnieuw.',
      passkeyUnknown: 'Deze passkey hoort bij geen account (meer). Meld je op een andere manier aan.',
      passkeyExpired: 'Dat duurde te lang. Probeer opnieuw.',
      passkeyExists: 'Dit toestel heeft al een passkey voor je account.',
      passkeyAddFailed: 'De passkey kon niet toegevoegd worden. Probeer opnieuw.',
      signInFirst: 'Meld je eerst aan.',
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
    withPasskey: 'Se connecter avec une clé d’accès',
    accountTitle: 'Votre compte',
    passkeysTitle: 'Clés d’accès',
    passkeysIntro: 'Avec une clé d’accès, vous vous connectez avec votre empreinte, votre visage ou le code de votre appareil — sans mot de passe.',
    noPasskeys: 'Aucune clé d’accès pour l’instant.',
    addPasskey: 'Ajouter une clé d’accès',
    passkeyAdded: 'Clé d’accès ajoutée.',
    passkeyMeta: (created: string, used: string | null) => `Ajoutée le ${created}` + (used ? ` · utilisée pour la dernière fois le ${used}` : ''),
    rename: 'Renommer',
    remove: 'Supprimer',
    passkeyName: 'Nom',
    passkeyUnsupported: 'Ce navigateur ne prend pas en charge les clés d’accès.',
    offerTitle: 'Vous connecter plus vite avec une clé d’accès ?',
    offerText: 'Connectez-vous désormais avec votre empreinte, votre visage ou le code de cet appareil — sans mot de passe. Votre façon actuelle de vous connecter continue aussi de fonctionner.',
    notNow: 'Pas maintenant',
    mailPasskeySubject: 'Nouvelle clé d’accès pour votre compte Arcanum',
    mailPasskey: (name: string, accountUrl: string) => `Une clé d’accès (« ${name} ») a été ajoutée à votre compte.\n\nCe n’était pas vous ? Supprimez-la sur ${accountUrl} et changez votre mot de passe.`,
    securityKey: 'Clé de sécurité',
    phone: 'Téléphone',
    kindSecurityKey: (how: string) => `Clé de sécurité${how ? ` · ${how}` : ''}`,
    kindSynced: 'Synchronisée entre vos appareils',
    kindDevice: 'Uniquement sur l’appareil où elle a été créée',
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
      passkeyFailed: 'La connexion avec une clé d’accès a échoué. Réessayez.',
      passkeyUnknown: 'Cette clé d’accès n’appartient (plus) à aucun compte. Connectez-vous autrement.',
      passkeyExpired: 'C’était trop long. Réessayez.',
      passkeyExists: 'Cet appareil a déjà une clé d’accès pour votre compte.',
      passkeyAddFailed: 'La clé d’accès n’a pas pu être ajoutée. Réessayez.',
      signInFirst: 'Connectez-vous d’abord.',
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
    withPasskey: 'Sign in with a passkey',
    accountTitle: 'Your account',
    passkeysTitle: 'Passkeys',
    passkeysIntro: 'With a passkey you sign in with your fingerprint, your face or your device’s PIN — no password.',
    noPasskeys: 'No passkeys yet.',
    addPasskey: 'Add a passkey',
    passkeyAdded: 'Passkey added.',
    passkeyMeta: (created: string, used: string | null) => `Added on ${created}` + (used ? ` · last used on ${used}` : ''),
    rename: 'Rename',
    remove: 'Remove',
    passkeyName: 'Name',
    passkeyUnsupported: 'This browser doesn’t support passkeys.',
    offerTitle: 'Sign in faster with a passkey?',
    offerText: 'From now on, sign in with your fingerprint, your face or this device’s PIN — no password. The way you sign in today keeps working too.',
    notNow: 'Not now',
    mailPasskeySubject: 'New passkey for your Arcanum account',
    mailPasskey: (name: string, accountUrl: string) => `A passkey ("${name}") was added to your account.\n\nWasn't you? Remove it at ${accountUrl} and change your password.`,
    securityKey: 'Security key',
    phone: 'Phone',
    kindSecurityKey: (how: string) => `Security key${how ? ` · ${how}` : ''}`,
    kindSynced: 'Synced across your devices',
    kindDevice: 'Only on the device it was made on',
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
      passkeyFailed: 'Signing in with a passkey failed. Try again.',
      passkeyUnknown: 'This passkey doesn’t belong to an account (any more). Sign in another way.',
      passkeyExpired: 'That took too long. Try again.',
      passkeyExists: 'This device already has a passkey for your account.',
      passkeyAddFailed: 'The passkey could not be added. Try again.',
      signInFirst: 'Sign in first.',
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
a{color:var(--fg)}.or{text-align:center;color:var(--muted);font-size:13px;margin:16px 0 0}
.ok{color:var(--fg);font-size:14px}h2{font-size:16px;margin:22px 0 6px}ul.keys{list-style:none;padding:0;margin:8px 0 0;display:grid;gap:10px}
ul.keys li{border:1px solid var(--border);border-radius:10px;padding:10px 12px}.key-name{font-weight:600}.key-meta{font-size:12.5px;color:var(--muted)}
ul.keys form{display:flex;gap:8px;margin-top:8px}ul.keys input{height:36px}ul.keys button{width:auto;height:36px;margin:0;padding:0 12px;font-size:13.5px}
[hidden]{display:none!important}`;

export function page(request: Request, title: string, body: string, status = 200, headers: Record<string, string> = {}, opts: { passkeys?: boolean } = {}): Response {
  const script = opts.passkeys ? '<script src="/passkey.js" defer></script>' : '';
  const html = `<!doctype html><html lang="${language(request)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>${esc(title)} · Arcanum</title><style>${STYLE}</style>${script}</head>
<body><main><div class="brand">arcanum</div>${body}</main></body></html>`;
  return new Response(html, {
    status,
    headers: {
      'Content-Type': 'text/html; charset=utf-8',
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'none'; script-src 'self'; connect-src 'self'; style-src 'unsafe-inline'; form-action 'self' https:; frame-ancestors 'none'; base-uri 'none'",
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
<label for="email">${t.email}</label><input id="email" name="email" type="email" autocomplete="username webauthn" required value="${esc(opts.email ?? '')}">
<label for="password">${t.password}</label><input id="password" name="password" type="password" autocomplete="current-password" required>
${error(t, opts.error)}<button type="submit">${t.submitSignIn}</button></form>
<div data-passkey-box hidden><p class="or">${t.or}</p><button type="button" class="secondary" data-passkey-login data-continue="${esc(opts.continueTo)}">${t.withPasskey}</button></div>
<p class="error" role="alert" data-passkey-error hidden></p>
${opts.google ? `<p class="or">${t.or}</p><a class="button secondary" href="/google${q}">${t.withGoogle}</a>` : ''}
<div class="links"><span>${t.noAccount} <a href="/signup${q}">${t.createAccount}</a></span><a href="/reset${q}">${t.forgot}</a></div>`,
    status,
    {},
    { passkeys: true }
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

export function messagePage(request: Request, message: string, status = 200, headers: Record<string, string> = {}) {
  return page(request, 'Arcanum', `<p style="color:var(--fg)">${esc(message)}</p>`, status, headers);
}

export interface PasskeyItem {
  id: string;
  name: string;
  created_at: string;
  last_used_at: string | null;
  // How it connects: a USB/NFC/Bluetooth key, synced (iCloud, Google …), or this device only.
  kind: 'securityKey' | 'synced' | 'device';
  transports: string[];
}

const LOCALES: Record<Lang, string> = { nl: 'nl-BE', fr: 'fr-BE', en: 'en-GB' };
// Date and time as people here read it (Belgian time, whatever the server's).
const when = (request: Request, iso: string) =>
  new Date(iso).toLocaleString(LOCALES[language(request)], { dateStyle: 'long', timeStyle: 'short', timeZone: 'Europe/Brussels' });
const kindOf = (t: Texts, k: PasskeyItem) =>
  k.kind === 'securityKey' ? t.kindSecurityKey(k.transports.map((x) => x.toUpperCase().replace('BLE', 'Bluetooth')).join(', ')) : k.kind === 'synced' ? t.kindSynced : t.kindDevice;

// The add-a-passkey button: shown by /passkey.js only where the browser can.
const addPasskeyButton = (t: Texts, continueTo: string, skipTo?: string) =>
  `<button type="button" data-passkey-register data-continue="${esc(continueTo)}" data-exists="${esc(t.errors.passkeyExists)}"${skipTo ? ` data-skip="${esc(skipTo)}"` : ''} hidden>${t.addPasskey}</button>
<p class="error" role="alert" data-passkey-error hidden></p>`;

export function accountPage(request: Request, opts: { email: string; passkeys: PasskeyItem[]; added?: boolean; error?: ErrorKey | null }, status = 200) {
  const t = texts(request);
  const items = opts.passkeys
    .map(
      (k) => `<li><div class="key-name">${esc(k.name)}</div><div class="key-meta">${esc(kindOf(t, k))}</div><div class="key-meta">${esc(t.passkeyMeta(when(request, k.created_at), k.last_used_at ? when(request, k.last_used_at) : null))}</div>
<form method="post" action="/account/passkeys">${hidden('id', k.id)}<input name="name" aria-label="${t.passkeyName}" maxlength="60" required value="${esc(k.name)}"><button type="submit" name="action" value="rename" class="secondary">${t.rename}</button><button type="submit" name="action" value="delete" class="secondary">${t.remove}</button></form></li>`
    )
    .join('');
  return page(
    request,
    t.accountTitle,
    `<h1>${t.accountTitle}</h1><p>${esc(t.signedInAs(opts.email))}</p>
<h2>${t.passkeysTitle}</h2><p>${t.passkeysIntro}</p>
${opts.added ? `<p class="ok" role="status">${t.passkeyAdded}</p>` : ''}${error(t, opts.error)}
${items ? `<ul class="keys">${items}</ul>` : `<p>${t.noPasskeys}</p>`}
${addPasskeyButton(t, '/account?passkey=added')}<p data-passkey-unsupported hidden>${t.passkeyUnsupported}</p>
<a class="button secondary" href="/logout">${t.signOut}</a>`,
    status,
    {},
    { passkeys: true }
  );
}

// After signing in another way: once, the offer to add a passkey (or not now).
export function passkeyOfferPage(request: Request, continueTo: string) {
  const t = texts(request);
  return page(
    request,
    t.offerTitle,
    `<h1>${t.offerTitle}</h1><p>${t.offerText}</p>
${addPasskeyButton(t, continueTo, continueTo)}
<form method="post" action="/passkey/offer">${hidden('continue', continueTo)}<button type="submit" class="secondary">${t.notNow}</button></form>`,
    200,
    {},
    { passkeys: true }
  );
}
