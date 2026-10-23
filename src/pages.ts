// The issuer's own pages — sign in (a mailed code, a passkey, Google; no
// passwords), connect a device, manage passkeys. Server-rendered HTML
// in the browser's language (nl/fr/en), light or dark. The only script is
// /passkey.js (passkeys need the browser's WebAuthn API), on the pages that
// offer them.

type Lang = 'nl' | 'fr' | 'en';

const T = {
  nl: {
    signIn: 'Aanmelden',
    email: 'E-mailadres',
    name: 'Naam',
    withGoogle: 'Aanmelden met Google',
    or: 'of',
    code: 'Code',
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
    googleTitle: 'Google',
    googleLinkedText: 'Je kunt je ook aanmelden met je Google-account.',
    unlinkGoogle: 'Google ontkoppelen',
    googleUnlinked: 'Google is ontkoppeld. Je meldt je nog aan met een code per e-mail of een passkey.',
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
    mailPasskeySubject: 'Nieuwe passkey voor je account',
    mailPasskey: (name: string, accountUrl: string) => `Er werd een passkey ("${name}") aan je account toegevoegd.\n\nWas jij dat niet? Verwijder hem meteen op ${accountUrl}.`,
    mailGoogleLinkedSubject: 'Google gekoppeld aan je account',
    mailGoogleLinked: (accountUrl: string) => `Je kunt je voortaan ook aanmelden met je Google-account met dit e-mailadres.\n\nWas jij dat niet? Meld het meteen aan de beheerder van de toepassing waarvoor je je aanmeldt, en kijk je account na op ${accountUrl}.`,
    accessTitle: "Geen toegang",
    accessRequestButton: "Toegang vragen",
    manageIntro: "Alleen wie hier met toegang staat, kan zich aanmelden.",
    manageOpen: "Deze toepassing is open: iedereen kan zich aanmelden. De lijst hieronder geldt pas als ze afgeschermd wordt.",
    requestsTitle: "Aanvragen",
    noRequests: "Geen openstaande aanvragen.",
    assignedTitle: "Met toegang",
    approve: "Toestaan",
    refuse: "Weigeren",
    removeAccess: "Verwijderen",
    makeAdmin: "Beheerder maken",
    makeMember: "Geen beheerder meer",
    adminBadge: "beheerder",
    you: "jij",
    addTitle: "Iemand toevoegen",
    add: "Toevoegen",
    manageApps: "Toepassingen die je beheert",
    accessText: (client: string) => `Je hebt nog geen toegang tot ${client}. Vraag de beheerder om je toe te voegen.`,
    accessRequested: (client: string) => `Je aanvraag voor ${client} is verstuurd. Je krijgt een e-mail zodra een beheerder je toegang geeft.`,
    accessGuest: (client: string) => `Met een gastaccount heb je geen toegang tot ${client}.`,
    accessAlready: (client: string) => `Je hebt al toegang tot ${client}. Ga terug naar de toepassing en meld je opnieuw aan.`,
    mailAccessRequestSubject: (client: string) => `Aanvraag voor toegang tot ${client}`,
    mailAccessRequest: (name: string, email: string, client: string, url: string) => `${name} (${email}) vraagt toegang tot ${client}.\n\nToestaan of weigeren: ${url}`,
    mailAccessGrantedSubject: (client: string) => `Je hebt toegang tot ${client}`,
    mailAccessGranted: (client: string, url: string | null) => `Een beheerder gaf je toegang tot ${client}.` + (url ? `\n\nMeld je aan op ${url}` : ''),
    manageTitle: (client: string) => `Toegang tot ${client}`,
    addressesTitle: "Adressen",
    redirectLabel: "Redirect-URI’s — één per regel, https",
    logoutLabel: "Adres na afmelden (optioneel)",
    saveUris: "Adressen opslaan",
    urisHint: "Waar deze toepassing na het aanmelden naartoe mag — precies zoals ze het gebruikt. De andere beheerders krijgen een e-mail bij elke wijziging.",
    urisByInstaller: "Deze adressen beheert de installatie zelf (haar installer voegt bv. een eigen domein toe).",
    mailUrisSubject: (client: string) => `Adressen van ${client} gewijzigd`,
    mailUris: (client: string, by: string, uris: string[], url: string) => `${by} wijzigde de adressen waar ${client} na het aanmelden naartoe mag:\n\n${uris.join('\n')}\n\nWas dat niet de bedoeling? Kijk het na op ${url}`,
    notAdminAs: (email: string, client: string) => `Je bent aangemeld als ${email}, en dat account beheert ${client} niet. Kreeg je een e-mail met een aanvraag? Meld je dan aan met het adres waarop je die kreeg.`,
    switchAccount: "Aanmelden met een ander account",
    accessDone: { approved: "Toegestaan. De persoon krijgt een e-mail.", refused: "Aanvraag geweigerd.", removed: "Verwijderd.", role: "Aangepast.", added: "Toegevoegd.", none: "Niets veranderd.", uris: "Adressen opgeslagen." },
    securityKey: 'Beveiligingssleutel',
    phone: 'Telefoon',
    kindSecurityKey: (how: string) => `Beveiligingssleutel${how ? ` · ${how}` : ''}`,
    kindSynced: 'Gesynchroniseerd tussen je toestellen',
    kindDevice: 'Alleen op het toestel waarop hij gemaakt werd',
    continueEmail: 'Ga verder met e-mail',
    signInHint: 'We mailen je een code. Nog geen account? Met die code maak je er meteen een.',
    codeTitle: 'Kijk in je mailbox',
    codeText: (email: string) => `We stuurden een code van 6 cijfers naar ${email}. Vul ze hier in, of klik op de link in de mail.`,
    otherAddress: 'Ander e-mailadres',
    nameTitle: 'Welkom',
    nameText: (email: string) => `Er is nog geen account voor ${email}. Hoe heet je?`,
    linkText: (email: string) => `Aanmelden als ${email}?`,
    linkOtherDevice: 'Je opent deze link op een ander toestel of in een andere browser dan waar je de code vroeg. Typ daar de code uit de mail, of meld je hier aan.',
    signInHere: 'Hier aanmelden',
    mailCodeSubject: 'Je aanmeldcode',
    mailCode: (code: string, link: string) => `Je code om je aan te melden: ${code}\n\nOf meld je aan met deze link: ${link}\n\nDe code en de link zijn 15 minuten geldig. Heb je dit niet gevraagd? Dan kan je deze e-mail negeren.`,
    errors: {
      urisInvalid: "Geef 1 tot 10 https-adressen, één per regel, zonder #.",
      notAdmin: "Je beheert deze toepassing niet.",
      lastAdmin: "Er moet minstens één beheerder overblijven.",
      tooMany: 'Te veel pogingen. Probeer het over een kwartier opnieuw.',
      emailInvalid: 'Vul een geldig e-mailadres in.',
      nameMissing: 'Vul je naam in.',
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
    mailTestSubject: 'Testmail',
    mailTestNote: (host: string) => `Dit is een testmail van ${host}: zo ziet een mail met een aanmeldcode eruit. De code hieronder opent niets; je hoeft er niets mee te doen.`,
  },
  fr: {
    signIn: 'Connexion',
    email: 'Adresse e-mail',
    name: 'Nom',
    withGoogle: 'Se connecter avec Google',
    or: 'ou',
    code: 'Code',
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
    googleTitle: 'Google',
    googleLinkedText: 'Vous pouvez aussi vous connecter avec votre compte Google.',
    unlinkGoogle: 'Délier Google',
    googleUnlinked: 'Google est délié. Vous vous connectez toujours avec un code par e-mail ou une clé d’accès.',
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
    mailPasskeySubject: 'Nouvelle clé d’accès pour votre compte',
    mailPasskey: (name: string, accountUrl: string) => `Une clé d’accès (« ${name} ») a été ajoutée à votre compte.\n\nCe n’était pas vous ? Supprimez-la tout de suite sur ${accountUrl}.`,
    mailGoogleLinkedSubject: 'Google lié à votre compte',
    mailGoogleLinked: (accountUrl: string) => `Vous pouvez désormais aussi vous connecter avec votre compte Google à cette adresse e-mail.\n\nCe n’était pas vous ? Signalez-le tout de suite à l’administrateur de l’application à laquelle vous vous connectez, et vérifiez votre compte sur ${accountUrl}.`,
    accessTitle: "Pas d’accès",
    accessRequestButton: "Demander l’accès",
    manageIntro: "Seules les personnes ayant accès ici peuvent se connecter.",
    manageOpen: "Cette application est ouverte : tout le monde peut se connecter. La liste ci-dessous ne s’applique qu’une fois l’accès restreint.",
    requestsTitle: "Demandes",
    noRequests: "Aucune demande en attente.",
    assignedTitle: "Avec accès",
    approve: "Accepter",
    refuse: "Refuser",
    removeAccess: "Retirer",
    makeAdmin: "Rendre administrateur",
    makeMember: "Retirer administrateur",
    adminBadge: "administrateur",
    you: "vous",
    addTitle: "Ajouter quelqu’un",
    add: "Ajouter",
    manageApps: "Applications que vous gérez",
    accessText: (client: string) => `Vous n’avez pas encore accès à ${client}. Demandez à l’administrateur de vous ajouter.`,
    accessRequested: (client: string) => `Votre demande pour ${client} a été envoyée. Vous recevrez un e-mail dès qu’un administrateur vous donne accès.`,
    accessGuest: (client: string) => `Un compte invité n’a pas accès à ${client}.`,
    accessAlready: (client: string) => `Vous avez déjà accès à ${client}. Retournez à l’application et reconnectez-vous.`,
    mailAccessRequestSubject: (client: string) => `Demande d’accès à ${client}`,
    mailAccessRequest: (name: string, email: string, client: string, url: string) => `${name} (${email}) demande l’accès à ${client}.\n\nAccepter ou refuser : ${url}`,
    mailAccessGrantedSubject: (client: string) => `Vous avez accès à ${client}`,
    mailAccessGranted: (client: string, url: string | null) => `Un administrateur vous a donné accès à ${client}.` + (url ? `\n\nConnectez-vous sur ${url}` : ''),
    manageTitle: (client: string) => `Accès à ${client}`,
    addressesTitle: "Adresses",
    redirectLabel: "URI de redirection — une par ligne, https",
    logoutLabel: "Adresse après déconnexion (facultatif)",
    saveUris: "Enregistrer les adresses",
    urisHint: "Où cette application peut aller après la connexion — exactement comme elle l’utilise. Les autres administrateurs reçoivent un e-mail à chaque modification.",
    urisByInstaller: "Ces adresses sont gérées par l’installation elle-même (son installateur ajoute p. ex. un domaine propre).",
    mailUrisSubject: (client: string) => `Adresses de ${client} modifiées`,
    mailUris: (client: string, by: string, uris: string[], url: string) => `${by} a modifié les adresses où ${client} peut aller après la connexion :\n\n${uris.join('\n')}\n\nCe n’était pas voulu ? Vérifiez sur ${url}`,
    notAdminAs: (email: string, client: string) => `Vous êtes connecté en tant que ${email}, et ce compte ne gère pas ${client}. Vous avez reçu un e-mail avec une demande ? Connectez-vous avec l’adresse sur laquelle vous l’avez reçu.`,
    switchAccount: "Se connecter avec un autre compte",
    accessDone: { approved: "Accepté. La personne reçoit un e-mail.", refused: "Demande refusée.", removed: "Retiré.", role: "Modifié.", added: "Ajouté.", none: "Rien n’a changé.", uris: "Adresses enregistrées." },
    securityKey: 'Clé de sécurité',
    phone: 'Téléphone',
    kindSecurityKey: (how: string) => `Clé de sécurité${how ? ` · ${how}` : ''}`,
    kindSynced: 'Synchronisée entre vos appareils',
    kindDevice: 'Uniquement sur l’appareil où elle a été créée',
    continueEmail: 'Continuer avec l’e-mail',
    signInHint: 'Nous vous envoyons un code par e-mail. Pas encore de compte ? Ce code en crée un tout de suite.',
    codeTitle: 'Consultez votre boîte mail',
    codeText: (email: string) => `Nous avons envoyé un code à 6 chiffres à ${email}. Saisissez-le ici, ou cliquez sur le lien dans l’e-mail.`,
    otherAddress: 'Autre adresse e-mail',
    nameTitle: 'Bienvenue',
    nameText: (email: string) => `Il n’y a pas encore de compte pour ${email}. Comment vous appelez-vous ?`,
    linkText: (email: string) => `Se connecter en tant que ${email} ?`,
    linkOtherDevice: 'Vous ouvrez ce lien sur un autre appareil ou dans un autre navigateur que celui où vous avez demandé le code. Saisissez-y le code de l’e-mail, ou connectez-vous ici.',
    signInHere: 'Se connecter ici',
    mailCodeSubject: 'Votre code de connexion',
    mailCode: (code: string, link: string) => `Votre code pour vous connecter : ${code}\n\nOu connectez-vous avec ce lien : ${link}\n\nLe code et le lien sont valables 15 minutes. Vous n’avez rien demandé ? Ignorez cet e-mail.`,
    errors: {
      urisInvalid: "Indiquez 1 à 10 adresses https, une par ligne, sans #.",
      notAdmin: "Vous ne gérez pas cette application.",
      lastAdmin: "Il doit rester au moins un administrateur.",
      tooMany: 'Trop de tentatives. Réessayez dans un quart d’heure.',
      emailInvalid: 'Saisissez une adresse e-mail valable.',
      nameMissing: 'Saisissez votre nom.',
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
    mailTestSubject: 'E-mail de test',
    mailTestNote: (host: string) => `Ceci est un e-mail de test de ${host} : voici à quoi ressemble un e-mail avec un code de connexion. Le code ci-dessous n’ouvre rien ; vous n’avez rien à faire.`,
  },
  en: {
    signIn: 'Sign in',
    email: 'Email address',
    name: 'Name',
    withGoogle: 'Sign in with Google',
    or: 'or',
    code: 'Code',
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
    googleTitle: 'Google',
    googleLinkedText: 'You can also sign in with your Google account.',
    unlinkGoogle: 'Unlink Google',
    googleUnlinked: 'Google is unlinked. You still sign in with a code by email or a passkey.',
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
    mailPasskeySubject: 'New passkey for your account',
    mailPasskey: (name: string, accountUrl: string) => `A passkey ("${name}") was added to your account.\n\nWasn't you? Remove it straight away at ${accountUrl}.`,
    mailGoogleLinkedSubject: 'Google linked to your account',
    mailGoogleLinked: (accountUrl: string) => `From now on you can also sign in with your Google account for this email address.\n\nWasn't you? Tell the administrator of the application you sign in to straight away, and check your account at ${accountUrl}.`,
    accessTitle: "No access",
    accessRequestButton: "Request access",
    manageIntro: "Only the people with access listed here can sign in.",
    manageOpen: "This application is open: anyone can sign in. The list below only applies once it is restricted.",
    requestsTitle: "Requests",
    noRequests: "No open requests.",
    assignedTitle: "With access",
    approve: "Approve",
    refuse: "Refuse",
    removeAccess: "Remove",
    makeAdmin: "Make admin",
    makeMember: "No longer admin",
    adminBadge: "admin",
    you: "you",
    addTitle: "Add someone",
    add: "Add",
    manageApps: "Applications you manage",
    accessText: (client: string) => `You don't have access to ${client} yet. Ask its administrator to add you.`,
    accessRequested: (client: string) => `Your request for ${client} was sent. You'll get an email as soon as an administrator gives you access.`,
    accessGuest: (client: string) => `A guest account has no access to ${client}.`,
    accessAlready: (client: string) => `You already have access to ${client}. Go back to the application and sign in again.`,
    mailAccessRequestSubject: (client: string) => `Access request for ${client}`,
    mailAccessRequest: (name: string, email: string, client: string, url: string) => `${name} (${email}) asks for access to ${client}.\n\nApprove or refuse: ${url}`,
    mailAccessGrantedSubject: (client: string) => `You have access to ${client}`,
    mailAccessGranted: (client: string, url: string | null) => `An administrator gave you access to ${client}.` + (url ? `\n\nSign in at ${url}` : ''),
    manageTitle: (client: string) => `Access to ${client}`,
    addressesTitle: "Addresses",
    redirectLabel: "Redirect URIs — one per line, https",
    logoutLabel: "Address after signing out (optional)",
    saveUris: "Save addresses",
    urisHint: "Where this application may go after signing in — exactly as it uses them. The other admins get an email on every change.",
    urisByInstaller: "The installation manages these addresses itself (its installer adds e.g. a custom domain).",
    mailUrisSubject: (client: string) => `Addresses of ${client} changed`,
    mailUris: (client: string, by: string, uris: string[], url: string) => `${by} changed where ${client} may go after signing in:\n\n${uris.join('\n')}\n\nNot intended? Check it at ${url}`,
    notAdminAs: (email: string, client: string) => `You're signed in as ${email}, and that account doesn't manage ${client}. Got an email with a request? Sign in with the address it was sent to.`,
    switchAccount: "Sign in with another account",
    accessDone: { approved: "Approved. They get an email.", refused: "Request refused.", removed: "Removed.", role: "Changed.", added: "Added.", none: "Nothing changed.", uris: "Addresses saved." },
    securityKey: 'Security key',
    phone: 'Phone',
    kindSecurityKey: (how: string) => `Security key${how ? ` · ${how}` : ''}`,
    kindSynced: 'Synced across your devices',
    kindDevice: 'Only on the device it was made on',
    continueEmail: 'Continue with email',
    signInHint: 'We email you a code. No account yet? That code creates one straight away.',
    codeTitle: 'Check your mailbox',
    codeText: (email: string) => `We sent a 6-digit code to ${email}. Enter it here, or click the link in the email.`,
    otherAddress: 'Another email address',
    nameTitle: 'Welcome',
    nameText: (email: string) => `There’s no account for ${email} yet. What’s your name?`,
    linkText: (email: string) => `Sign in as ${email}?`,
    linkOtherDevice: 'You’re opening this link on another device or in another browser than where you asked for the code. Enter the code from the email there, or sign in here.',
    signInHere: 'Sign in here',
    mailCodeSubject: 'Your sign-in code',
    mailCode: (code: string, link: string) => `Your code to sign in: ${code}\n\nOr sign in with this link: ${link}\n\nThe code and the link are valid for 15 minutes. Didn’t ask for this? Then ignore this email.`,
    errors: {
      urisInvalid: "Give 1 to 10 https addresses, one per line, without #.",
      notAdmin: "You don't manage this application.",
      lastAdmin: "At least one admin has to remain.",
      tooMany: 'Too many attempts. Try again in a quarter of an hour.',
      emailInvalid: 'Enter a valid email address.',
      nameMissing: 'Enter your name.',
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
    mailTestSubject: 'Test mail',
    mailTestNote: (host: string) => `This is a test mail from ${host}: this is what an e-mail with a sign-in code looks like. The code below opens nothing; there is nothing you need to do.`,
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
main.wide{max-width:720px}main.wide ul.keys li{display:flex;flex-wrap:wrap;align-items:center;gap:4px 12px}main.wide ul.keys li>div:first-child{flex:1 1 220px;min-width:0}main.wide ul.keys li form{margin-top:0}main.wide form button[type=submit]:only-of-type{width:auto;padding:0 20px}textarea.uris{white-space:pre;overflow-x:auto}
.brand{font-weight:700;letter-spacing:-.02em;margin-bottom:18px}h1{font-size:22px;letter-spacing:-.02em;margin:0 0 6px}p{margin:0 0 14px;color:var(--muted)}
label{display:block;font-size:13px;font-weight:600;margin:14px 0 6px}input{width:100%;height:42px;border:1px solid var(--border);border-radius:10px;background:transparent;color:var(--fg);padding:0 12px;font:inherit}
input.code{letter-spacing:.3em;text-align:center;font-size:20px;font-family:ui-monospace,monospace;text-transform:uppercase}
button,.button{display:flex;align-items:center;justify-content:center;width:100%;height:44px;margin-top:18px;border-radius:10px;border:1px solid var(--primary);background:var(--primary);color:var(--on-primary);font:600 15px system-ui,sans-serif;text-decoration:none;cursor:pointer}
.secondary{background:transparent;color:var(--fg);border-color:var(--border)}.row{display:flex;gap:10px}.row>*{flex:1}
.error{color:var(--danger);font-size:14px;margin:12px 0 0}.hint{font-size:12.5px;margin:6px 0 0}.links{margin-top:18px;font-size:13.5px;display:flex;flex-direction:column;gap:6px}
a{color:var(--fg)}.or{text-align:center;color:var(--muted);font-size:13px;margin:16px 0 0}
.ok{color:var(--fg);font-size:14px}h2{font-size:16px;margin:22px 0 6px}ul.keys{list-style:none;padding:0;margin:8px 0 0;display:grid;gap:10px}
ul.keys li{border:1px solid var(--border);border-radius:10px;padding:10px 12px}.key-name{font-weight:600}.key-meta{font-size:12.5px;color:var(--muted)}
ul.keys form{display:flex;flex-wrap:wrap;gap:8px;margin-top:8px}ul.keys input{height:36px;flex:1 1 100%}
textarea{width:100%;border:1px solid var(--border);border-radius:10px;background:transparent;color:var(--fg);padding:8px 12px;font:13px/1.5 ui-monospace,monospace;resize:vertical}code{font:12.5px ui-monospace,monospace;word-break:break-all}ul.keys button{width:auto;height:36px;margin:0;padding:0 12px;font-size:13.5px}
[hidden]{display:none!important}`;

// `wide`: a page to manage something (a client's access), not a sign-in form.
export function page(request: Request, title: string, body: string, status = 200, headers: Record<string, string> = {}, opts: { passkeys?: boolean; wide?: boolean } = {}): Response {
  const script = opts.passkeys ? '<script src="/passkey.js" defer></script>' : '';
  const html = `<!doctype html><html lang="${language(request)}"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex"><title>${esc(title)} · ${esc(new URL(request.url).host)}</title><style>${STYLE}</style>${script}</head>
<body><main${opts.wide ? ' class="wide"' : ''}><div class="brand">${esc(new URL(request.url).host)}</div>${body}</main></body></html>`;
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
      // Nothing here needs the camera, microphone or location; passkeys
      // (publickey-credentials-*) stay allowed.
      'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
      ...headers,
    },
  });
}

const hidden = (name: string, value: string) => `<input type="hidden" name="${name}" value="${esc(value)}">`;
const error = (t: Texts, key?: ErrorKey | null) => (key ? `<p class="error" role="alert">${esc(t.errors[key])}</p>` : '');

// Sign in without a password: an e-mail address (a mailed code follows), a
// passkey (the browser also offers it in the e-mail field) or Google. An
// address without an account gets one after its code (namePage).
export function loginPage(request: Request, opts: { continueTo: string; email?: string; error?: ErrorKey | null; google: boolean }, status = 200) {
  const t = texts(request);
  const q = `?continue=${encodeURIComponent(opts.continueTo)}`;
  return page(
    request,
    t.signIn,
    `<h1>${t.signIn}</h1><p>${t.signInHint}</p>
<form method="post" action="/login">${hidden('continue', opts.continueTo)}
<label for="email">${t.email}</label><input id="email" name="email" type="email" autocomplete="username webauthn" required value="${esc(opts.email ?? '')}">
${error(t, opts.error)}<button type="submit">${t.continueEmail}</button></form>
<div data-passkey-box hidden><p class="or">${t.or}</p><button type="button" class="secondary" data-passkey-login data-continue="${esc(opts.continueTo)}">${t.withPasskey}</button></div>
<p class="error" role="alert" data-passkey-error hidden></p>
${opts.google ? `<p class="or">${t.or}</p><a class="button secondary" href="/google${q}">${t.withGoogle}</a>` : ''}`,
    status,
    {},
    { passkeys: true }
  );
}

export function codePage(request: Request, opts: { id: string; email: string; continueTo: string; error?: ErrorKey | null }, status = 200) {
  const t = texts(request);
  return page(
    request,
    t.codeTitle,
    `<h1>${t.codeTitle}</h1><p>${esc(t.codeText(opts.email))}</p>
<form method="post" action="/login/code">${hidden('id', opts.id)}
<label for="code">${t.code}</label><input id="code" class="code" name="code" inputmode="numeric" autocomplete="one-time-code" required maxlength="6" autofocus>
${error(t, opts.error)}<button type="submit">${t.signIn}</button></form>
<div class="links"><a href="/login?continue=${encodeURIComponent(opts.continueTo)}">${t.otherAddress}</a></div>`,
    status
  );
}

// A new address, proven by its code: one question, then the account exists.
export function namePage(request: Request, opts: { id: string; finish: string; email: string; error?: ErrorKey | null }, status = 200) {
  const t = texts(request);
  return page(
    request,
    t.nameTitle,
    `<h1>${t.nameTitle}</h1><p>${esc(t.nameText(opts.email))}</p>
<form method="post" action="/login/name">${hidden('id', opts.id)}${hidden('finish', opts.finish)}
<label for="name">${t.name}</label><input id="name" name="name" autocomplete="name" required maxlength="100" autofocus>
${error(t, opts.error)}<button type="submit">${t.signIn}</button></form>`,
    status
  );
}

// The link in the mail: a button, never signing in on the GET itself (mail
// scanners open links). In another browser than the one that asked: say so.
export function linkPage(request: Request, opts: { id: string; token: string; email: string; sameBrowser: boolean }) {
  const t = texts(request);
  return page(
    request,
    t.signIn,
    `<h1>${esc(t.linkText(opts.email))}</h1>${opts.sameBrowser ? '' : `<p>${t.linkOtherDevice}</p>`}
<form method="post" action="/login/link">${hidden('id', opts.id)}${hidden('t', opts.token)}
<button type="submit"${opts.sameBrowser ? '' : ' class="secondary"'}>${opts.sameBrowser ? t.signIn : t.signInHere}</button></form>`
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
  return page(request, new URL(request.url).host, `<p style="color:var(--fg)">${esc(message)}</p>`, status, headers);
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

export function accountPage(request: Request, opts: { email: string; passkeys: PasskeyItem[]; google: boolean; managed: { id: string; name: string; hosts: string[] }[]; added?: boolean; googleUnlinked?: boolean; error?: ErrorKey | null }, status = 200) {
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
${opts.googleUnlinked ? `<p class="ok" role="status">${t.googleUnlinked}</p>` : ''}${
      opts.google ? `<h2>${t.googleTitle}</h2><p>${t.googleLinkedText}</p><form method="post" action="/account/google"><button type="submit" name="action" value="unlink" class="secondary">${t.unlinkGoogle}</button></form>` : ''
    }
${
      opts.managed.length
        ? `<h2>${t.manageApps}</h2><ul class="keys">${opts.managed
            .map((c) => `<li><a href="/access/${encodeURIComponent(c.id)}">${esc(c.name)}</a>${c.hosts.length ? `<div class="key-meta">${esc(c.hosts.join(' · '))}</div>` : ''}</li>`)
            .join('')}</ul>`
        : ''
    }
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

// A restricted client someone has no access to (from /authorize or /device):
// ask its admins to be added, or see that the request is on its way.
export function accessPage(request: Request, opts: { clientId: string; clientName: string; email: string; requested: boolean; error?: ErrorKey | null }, status = 200) {
  const t = texts(request);
  const body = opts.requested
    ? `<p class="ok" role="status">${esc(t.accessRequested(opts.clientName))}</p>`
    : `<p>${esc(t.accessText(opts.clientName))}</p>${error(t, opts.error)}
<form method="post" action="/access/${encodeURIComponent(opts.clientId)}/request"><button type="submit">${t.accessRequestButton}</button></form>`;
  return page(
    request,
    t.accessTitle,
    `<h1>${t.accessTitle}</h1><p>${esc(t.signedInAs(opts.email))}</p>${body}
<a class="button secondary" href="/logout">${t.signOut}</a>`,
    status
  );
}

export interface AccessItem {
  email: string;
  status: 'assigned' | 'requested';
  role: 'member' | 'admin';
  created_at: string;
  name: string | null;
}

// A client's admins: open requests, who has access, add someone.
export function accessAdminPage(
  request: Request,
  opts: {
    clientId: string;
    clientName: string;
    // Its addresses' host names (which installation it is), and the addresses themselves.
    hosts: string[];
    redirectUris: string[];
    logoutUris: string[];
    // An installation's: its installer keeps the addresses up to date — shown, not edited here.
    byInstaller: boolean;
    restricted: boolean;
    me: string;
    items: AccessItem[];
    notice?: string;
    error?: ErrorKey | null;
    tried?: { redirect: string; logout: string };
  },
  status = 200
) {
  const t = texts(request);
  const action = `/access/${encodeURIComponent(opts.clientId)}`;
  // Who, in one block on the left (name, then address and what else); the buttons on the right.
  const who = (i: AccessItem, extra: string[] = []) =>
    `<div><div class="key-name">${esc(i.name || i.email)}${i.email === opts.me ? ` (${t.you})` : ''}</div>${
      i.name || extra.length ? `<div class="key-meta">${esc([...(i.name ? [i.email] : []), ...extra].join(' · '))}</div>` : ''
    }</div>`;
  const buttons = (i: AccessItem, list: [string, string][]) =>
    `<form method="post" action="${action}">${hidden('email', i.email)}${list.map(([value, label]) => `<button type="submit" name="action" value="${value}" class="secondary">${label}</button>`).join('')}</form>`;
  const requests = opts.items.filter((i) => i.status === 'requested');
  const assigned = opts.items.filter((i) => i.status === 'assigned');
  const requestItems = requests.map((i) => `<li>${who(i, [when(request, i.created_at)])}${buttons(i, [['approve', t.approve], ['refuse', t.refuse]])}</li>`).join('');
  const assignedItems = assigned
    .map(
      (i) =>
        `<li>${who(i, i.role === 'admin' ? [t.adminBadge] : [])}${buttons(i, [
          i.role === 'admin' ? ['member', t.makeMember] : ['admin', t.makeAdmin],
          ['remove', t.removeAccess],
        ])}</li>`
    )
    .join('');
  return page(
    request,
    t.manageTitle(opts.clientName),
    `<h1>${esc(t.manageTitle(opts.clientName))}</h1>${opts.hosts.length ? `<p class="hint" data-testid="client-hosts">${esc(opts.hosts.join(' · '))}</p>` : ''}<p>${opts.restricted ? t.manageIntro : t.manageOpen}</p>
${opts.notice ? `<p class="ok" role="status">${esc(opts.notice)}</p>` : ''}${error(t, opts.error)}
<h2>${t.requestsTitle}</h2>${requestItems ? `<ul class="keys">${requestItems}</ul>` : `<p>${t.noRequests}</p>`}
<h2>${t.assignedTitle}</h2><ul class="keys">${assignedItems}</ul>
<h2>${t.addTitle}</h2><form method="post" action="${action}">${hidden('action', 'add')}<label for="email">${t.email}</label><input id="email" name="email" type="email" required autocomplete="off"><button type="submit">${t.add}</button></form>
<h2>${t.addressesTitle}</h2>${
      opts.byInstaller
        ? `<p>${t.urisByInstaller}</p><ul class="keys" data-testid="client-uris">${opts.redirectUris.map((u) => `<li><code>${esc(u)}</code></li>`).join('')}</ul>`
        : `<form method="post" action="${action}" data-testid="client-uris">${hidden('action', 'uris')}<p>${t.urisHint}</p>
<label for="redirect_uris">${t.redirectLabel}</label><textarea id="redirect_uris" name="redirect_uris" class="uris" wrap="off" rows="${Math.max(2, opts.redirectUris.length + 1)}" required>${esc(opts.tried?.redirect ?? opts.redirectUris.join('\n'))}</textarea>
<label for="post_logout_redirect_uris">${t.logoutLabel}</label><textarea id="post_logout_redirect_uris" name="post_logout_redirect_uris" class="uris" wrap="off" rows="${Math.max(2, opts.logoutUris.length + 1)}">${esc(opts.tried?.logout ?? opts.logoutUris.join('\n'))}</textarea>
<button type="submit">${t.saveUris}</button></form>`
    }
<div class="links"><a href="/account">${t.accountTitle}</a></div>`,
    status,
    {},
    { wide: true }
  );
}

// Signed in, but not as one of the client's admins (often: another account
// than the one the request mail went to) — say who, and offer to switch.
export function notAdminPage(request: Request, opts: { clientId: string; clientName: string; email: string }) {
  const t = texts(request);
  const back = `/access/${encodeURIComponent(opts.clientId)}`;
  return page(
    request,
    t.manageTitle(opts.clientName),
    `<h1>${esc(t.manageTitle(opts.clientName))}</h1><p>${esc(t.notAdminAs(opts.email, opts.clientName))}</p>
<a class="button" href="/login?continue=${encodeURIComponent(back)}">${t.switchAccount}</a>`,
    403
  );
}
