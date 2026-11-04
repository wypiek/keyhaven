// Password / passphrase / PIN generator with unbiased CSPRNG sampling.

import { WORDS } from './wordlist.js';

const SETS = {
  lower: 'abcdefghijklmnopqrstuvwxyz',
  upper: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
  digits: '0123456789',
  symbols: '!@#$%^&*()-_=+[]{};:,.<>/?~',
};
const AMBIGUOUS = 'Il1O0o|`\'"';

export const DEFAULT_GENERATOR = {
  kind: 'random',
  length: 20,
  lower: true,
  upper: true,
  digits: true,
  symbols: true,
  avoidAmbiguous: false,
  words: 5,
  separator: '-',
  capitalize: true,
  includeNumber: true,
  pinLength: 6,
};

/** Uniform integer in [0, n). */
export function randomInt(n) {
  const max = Math.floor(0x100000000 / n) * n;
  const buf = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < max) return buf[0] % n;
  }
}

function randomPassword(o) {
  const sets = ['lower', 'upper', 'digits', 'symbols']
    .filter((k) => o[k])
    .map((k) => [...SETS[k]].filter((c) => !o.avoidAmbiguous || !AMBIGUOUS.includes(c)));
  if (!sets.length) sets.push([...SETS.lower], [...SETS.digits]);
  const all = sets.flat();
  const len = Math.max(sets.length, Math.min(128, Math.max(4, o.length | 0)));
  for (;;) {
    const pw = Array.from({ length: len }, () => all[randomInt(all.length)]);
    if (sets.every((set) => pw.some((c) => set.includes(c)))) return pw.join('');
  }
}

function passphrase(o) {
  const n = Math.min(15, Math.max(3, o.words | 0));
  const words = Array.from({ length: n }, () => {
    const w = WORDS[randomInt(WORDS.length)];
    return o.capitalize ? w[0].toUpperCase() + w.slice(1) : w;
  });
  if (o.includeNumber) words[randomInt(n)] += String(randomInt(10));
  return words.join(String(o.separator ?? '-').slice(0, 3));
}

export function generatePassword(opts = {}) {
  const o = { ...DEFAULT_GENERATOR, ...opts };
  if (o.kind === 'passphrase') return passphrase(o);
  if (o.kind === 'pin') {
    const len = Math.min(32, Math.max(4, o.pinLength | 0));
    return Array.from({ length: len }, () => randomInt(10)).join('');
  }
  return randomPassword(o);
}

/** Entropy in bits of the generator configuration (not of a given string). */
export function generatorEntropy(opts = {}) {
  const o = { ...DEFAULT_GENERATOR, ...opts };
  if (o.kind === 'passphrase') return o.words * Math.log2(WORDS.length) + (o.includeNumber ? Math.log2(10 * o.words) : 0);
  if (o.kind === 'pin') return o.pinLength * Math.log2(10);
  let pool = 0;
  for (const k of ['lower', 'upper', 'digits', 'symbols']) {
    if (o[k]) pool += [...SETS[k]].filter((c) => !o.avoidAmbiguous || !AMBIGUOUS.includes(c)).length;
  }
  return o.length * Math.log2(pool || 36);
}
