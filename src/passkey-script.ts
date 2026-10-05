// /passkey.js — the one script on the issuer's pages (passkeys.ts): the
// browser's WebAuthn API needs one. It only adds to pages that work
// without it: the passkey buttons stay hidden where the browser can't.
//   [data-passkey-login]     sign in with a passkey (and the e-mail field's autofill)
//   [data-passkey-register]  add a passkey; [data-skip] = where to go when this browser can't
//   [data-passkey-error]     where a failure is shown (the server words it)
// Kept as plain ES2017, no build step; no backticks or ${ in it (it lives in
// a String.raw template).
export const PASSKEY_SCRIPT = String.raw`(function () {
  'use strict';
  var supported = !!(window.PublicKeyCredential && navigator.credentials && navigator.credentials.create);
  var $ = function (s) { return document.querySelector(s); };
  var errorBox = $('[data-passkey-error]');

  function enc(buffer) {
    var bytes = new Uint8Array(buffer), s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function dec(text) {
    var b64 = text.replace(/-/g, '+').replace(/_/g, '/');
    while (b64.length % 4) b64 += '=';
    var s = atob(b64), bytes = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
    return bytes.buffer;
  }
  function withIds(list) { return (list || []).map(function (c) { return Object.assign({}, c, { id: dec(c.id) }); }); }

  function showError(text) { if (errorBox) { errorBox.textContent = text; errorBox.hidden = false; } }
  function clearError() { if (errorBox) { errorBox.textContent = ''; errorBox.hidden = true; } }
  // Cancelled in the browser's own dialog, or replaced by another attempt: nothing to report.
  function quiet(e) { return e && (e.name === 'NotAllowedError' || e.name === 'AbortError'); }

  function post(path, body) {
    return fetch(path, { method: 'POST', credentials: 'same-origin', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      .then(function (res) {
        return res.json().catch(function () { return {}; }).then(function (data) {
          if (!res.ok) { var e = new Error(data.error || 'HTTP ' + res.status); e.server = true; throw e; }
          return data;
        });
      });
  }

  // A rough name for the passkey list ("iPhone", "Mac" …) — renamable there.
  function deviceName() {
    var ua = navigator.userAgent;
    if (/iPhone/.test(ua)) return 'iPhone';
    if (/iPad/.test(ua)) return 'iPad';
    if (/Android/.test(ua)) return 'Android';
    if (/Macintosh|Mac OS X/.test(ua)) return 'Mac';
    if (/Windows/.test(ua)) return 'Windows';
    if (/CrOS/.test(ua)) return 'Chromebook';
    if (/Linux/.test(ua)) return 'Linux';
    return 'Passkey';
  }

  // --- Signing in.
  var login = $('[data-passkey-login]');
  if (login && supported) {
    $('[data-passkey-box]').hidden = false;
    var pending = null;
    var signIn = function (conditional) {
      if (pending) pending.abort();
      pending = new AbortController();
      var signal = pending.signal;
      return post('/passkey/login/options', {}).then(function (o) {
        var publicKey = Object.assign({}, o, { challenge: dec(o.challenge), allowCredentials: withIds(o.allowCredentials) });
        var request = { publicKey: publicKey, signal: signal };
        if (conditional) request.mediation = 'conditional';
        return navigator.credentials.get(request);
      }).then(function (c) {
        if (!c) return;
        clearError();
        return post('/passkey/login', {
          continue: login.dataset.continue,
          response: {
            id: c.id, rawId: enc(c.rawId), type: c.type,
            authenticatorAttachment: c.authenticatorAttachment || undefined,
            clientExtensionResults: c.getClientExtensionResults(),
            response: {
              clientDataJSON: enc(c.response.clientDataJSON),
              authenticatorData: enc(c.response.authenticatorData),
              signature: enc(c.response.signature),
              userHandle: c.response.userHandle ? enc(c.response.userHandle) : undefined,
            },
          },
        }).then(function (r) { location.href = r.redirect; });
      });
    };
    login.addEventListener('click', function () {
      signIn(false).catch(function (e) { if (!quiet(e)) showError(e.server ? e.message : login.textContent + ': ' + e.message); });
    });
    // The e-mail field offers the passkeys this browser has (autocomplete="username webauthn").
    if (PublicKeyCredential.isConditionalMediationAvailable) {
      PublicKeyCredential.isConditionalMediationAvailable().then(function (ok) {
        if (ok) signIn(true).catch(function (e) { if (!quiet(e) && e.server) showError(e.message); });
      });
    }
  }

  // --- Adding one.
  var add = $('[data-passkey-register]');
  if (add) {
    if (!supported) {
      if (add.dataset.skip) location.replace(add.dataset.skip);
      var note = $('[data-passkey-unsupported]');
      if (note) note.hidden = false;
    } else {
      add.hidden = false;
      add.addEventListener('click', function () {
        add.disabled = true;
        clearError();
        post('/passkey/register/options', {}).then(function (o) {
          var publicKey = Object.assign({}, o, {
            challenge: dec(o.challenge),
            user: Object.assign({}, o.user, { id: dec(o.user.id) }),
            excludeCredentials: withIds(o.excludeCredentials),
          });
          return navigator.credentials.create({ publicKey: publicKey });
        }).then(function (c) {
          return post('/passkey/register', {
            name: deviceName(),
            continue: add.dataset.continue,
            response: {
              id: c.id, rawId: enc(c.rawId), type: c.type,
              authenticatorAttachment: c.authenticatorAttachment || undefined,
              clientExtensionResults: c.getClientExtensionResults(),
              response: {
                clientDataJSON: enc(c.response.clientDataJSON),
                attestationObject: enc(c.response.attestationObject),
                transports: c.response.getTransports ? c.response.getTransports() : [],
              },
            },
          });
        }).then(function (r) { location.href = r.redirect; }).catch(function (e) {
          add.disabled = false;
          // InvalidStateError: this device already holds a passkey for the account (excludeCredentials).
          if (!quiet(e)) showError(e.server ? e.message : e.name === 'InvalidStateError' ? add.dataset.exists : add.textContent + ': ' + e.message);
        });
      });
    }
  }
})();
`;
