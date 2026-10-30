// Property-based tests (fast-check) for the helpers that take outside input:
// what a visitor types or posts, and the tokens we hand out and read back.
import fc from 'fast-check';
import { describe, expect, it } from 'vitest';
import {
  base64url,
  fromBase64url,
  isEmail,
  newEmailCode,
  newUserCode,
  normalizeEmail,
  normalizeUserCode,
  randomChars,
  safeContinue,
  timingSafeEqual,
} from '../src/util';

const USER_CODE = /^[A-Z]{4}-[A-Z]{4}$/;
const USER_CODE_ALPHABET = 'BCDFGHJKLMNPQRSTVWXZ';

describe('device user codes', () => {
  it('normalizeUserCode gives either nothing or XXXX-XXXX, and is idempotent', () => {
    fc.assert(
      fc.property(fc.string(), (input) => {
        const code = normalizeUserCode(input);
        expect(code === '' || USER_CODE.test(code)).toBe(true);
        expect(normalizeUserCode(code)).toBe(code);
      }),
    );
  });

  it('a code survives however it is typed back: lower case, spaces, other separators', () => {
    fc.assert(
      fc.property(fc.constantFrom(' ', '-', '.', '  ', ''), fc.boolean(), (sep, lower) => {
        const code = newUserCode();
        let typed = `${code.slice(0, 4)}${sep}${code.slice(5)}`;
        if (lower) typed = typed.toLowerCase();
        expect(normalizeUserCode(` ${typed} `)).toBe(code);
      }),
    );
  });

  it('newUserCode only uses the vowel-free alphabet', () => {
    fc.assert(
      fc.property(fc.constant(null), () => {
        const code = newUserCode();
        expect(code).toMatch(USER_CODE);
        expect([...code.replace('-', '')].every((c) => USER_CODE_ALPHABET.includes(c))).toBe(true);
      }),
    );
  });
});

describe('random characters', () => {
  it('randomChars has the asked length and only characters from the alphabet', () => {
    fc.assert(
      fc.property(fc.nat({ max: 64 }), fc.string({ minLength: 1, maxLength: 200 }), (length, alphabet) => {
        const out = randomChars(length, alphabet);
        expect(out.length).toBe(length);
        expect([...out].every((c) => alphabet.includes(c))).toBe(true);
      }),
    );
  });

  it('newEmailCode is six digits', () => {
    fc.assert(
      fc.property(fc.constant(null), () => {
        expect(newEmailCode()).toMatch(/^\d{6}$/);
      }),
    );
  });
});

describe('base64url', () => {
  it('round-trips any bytes and never yields +, / or padding', () => {
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 300 }), (bytes) => {
        const text = base64url(bytes);
        expect(text).toMatch(/^[A-Za-z0-9_-]*$/);
        expect(fromBase64url(text)).toEqual(bytes);
      }),
    );
  });
});

describe('timingSafeEqual', () => {
  it('agrees with ===', () => {
    fc.assert(
      fc.property(fc.string(), fc.string(), (a, b) => {
        expect(timingSafeEqual(a, b)).toBe(a === b);
        expect(timingSafeEqual(a, a)).toBe(true);
      }),
    );
  });
});

describe('e-mail addresses', () => {
  it('normalizeEmail is idempotent and leaves no surrounding space or capitals', () => {
    fc.assert(
      fc.property(fc.string(), (input) => {
        const email = normalizeEmail(input);
        expect(normalizeEmail(email)).toBe(email);
        expect(email).toBe(email.trim());
        expect(email).toBe(email.toLowerCase());
      }),
    );
  });

  it('isEmail accepts generated addresses and rejects anything with whitespace or without @', () => {
    fc.assert(
      fc.property(fc.emailAddress(), (email) => {
        expect(isEmail(email)).toBe(email.length <= 254);
      }),
    );
    fc.assert(
      fc.property(fc.string(), (input) => {
        if (!input.includes('@') || /\s/.test(input)) expect(isEmail(input)).toBe(false);
      }),
    );
  });
});

describe('safeContinue', () => {
  it('never leaves this site: always a local path, never protocol-relative', () => {
    const paths = fc.oneof(
      fc.string(),
      fc.string().map((s) => `/${s}`),
      fc.string().map((s) => `//${s}`),
      fc.constantFrom('/authorize', '/device', '/account', '/login/passkey', '/access/').chain((p) => fc.string().map((s) => p + s)),
    );
    fc.assert(
      fc.property(fc.option(paths, { nil: undefined }), (value) => {
        const target = safeContinue(value);
        expect(target.startsWith('/')).toBe(true);
        expect(target.startsWith('//')).toBe(false);
        // Resolved against the issuer it stays on the issuer.
        expect(new URL(target, 'https://login.kaboutersoft.be').origin).toBe('https://login.kaboutersoft.be');
      }),
    );
  });
});
