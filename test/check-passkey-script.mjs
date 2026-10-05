// /passkey.js must parse as a script (the Workers test pool can't evaluate
// code; Node can). Run by `npm test` before vitest.
import { PASSKEY_SCRIPT } from '../src/passkey-script.ts';
new Function(PASSKEY_SCRIPT);
console.log('passkey.js: the script parses');
