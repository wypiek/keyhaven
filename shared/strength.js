// Lightweight password strength estimator: pattern-aware entropy with penalties for
// common passwords, dictionary words, repeats, sequences and keyboard walks.

import { WORDS } from './wordlist.js';

const COMMON = new Set(
  ('123456 password 12345678 qwerty 123456789 12345 1234 111111 1234567 dragon 123123 baseball abc123 ' +
    'football monkey letmein 696969 shadow master 666666 qwertyuiop 123321 mustang 1234567890 michael 654321 ' +
    'superman 1qaz2wsx 7777777 121212 000000 qazwsx 123qwe killer trustno1 jordan jennifer zxcvbnm asdfgh ' +
    'hunter buster soccer harley batman andrew tigger sunshine iloveyou 2000 charlie robert thomas hockey ' +
    'ranger daniel starwars klaster 112233 george computer michelle jessica pepper 1111 zxcvbn 555555 11111111 ' +
    '131313 freedom 777777 pass maggie 159753 aaaaaa ginger princess joshua cheese amanda summer love ashley ' +
    'nicole chelsea biteme matthew access yankees 987654321 dallas austin thunder taylor matrix minecraft ' +
    'welcome admin login passw0rd password1 password123 qwerty123 iloveyou1 abcdef abcd1234 secret changeme ' +
    'whatever hello default guest root toor test test123 p@ssw0rd p@ssword letmein1 football1 monkey1 ' +
    'qwertz azerty asdf asdfghjkl zaq12wsx 1q2w3e4r 1q2w3e 1q2w3e4r5t q1w2e3r4 samsung google apple')
    .split(' '),
);
const DICT = new Set(WORDS.filter((w) => w.length >= 4));
const KEYBOARD_ROWS = ['qwertyuiop', 'asdfghjkl', 'zxcvbnm', '1234567890', 'qwertzuiop', 'azertyuiop'];
const LEET = { '@': 'a', 4: 'a', 3: 'e', 1: 'i', '!': 'i', 0: 'o', $: 's', 5: 's', 7: 't' };

function poolSize(pw) {
  let p = 0;
  if (/[a-z]/.test(pw)) p += 26;
  if (/[A-Z]/.test(pw)) p += 26;
  if (/[0-9]/.test(pw)) p += 10;
  if (/[^a-zA-Z0-9]/.test(pw)) p += 33;
  if (/[^\x00-\x7f]/.test(pw)) p += 100;
  return p || 1;
}

function isSequence(s) {
  if (s.length < 3) return false;
  const d = s.charCodeAt(1) - s.charCodeAt(0);
  if (Math.abs(d) !== 1) return false;
  for (let i = 2; i < s.length; i++) if (s.charCodeAt(i) - s.charCodeAt(i - 1) !== d) return false;
  return true;
}

export function estimateStrength(pw) {
  if (!pw) return { score: 0, bits: 0, label: 'Empty', warning: '' };
  const lower = pw.toLowerCase();
  const unleet = [...lower].map((c) => LEET[c] ?? c).join('');
  if (COMMON.has(lower) || COMMON.has(unleet) || COMMON.has(lower.replace(/\d+$/, ''))) {
    return { score: 0, bits: 4, label: 'Very weak', warning: 'This is one of the most common passwords' };
  }

  let bits = 0;
  let warning = '';
  let i = 0;
  const chars = [...pw];
  const pool = poolSize(pw);
  while (i < chars.length) {
    // repeated run
    let j = i;
    while (j + 1 < chars.length && chars[j + 1] === chars[i]) j++;
    if (j - i >= 2) {
      bits += Math.log2(pool) + Math.log2(j - i + 1);
      warning ||= 'Avoid repeated characters';
      i = j + 1;
      continue;
    }
    // sequence / keyboard walk (length >= 3)
    let k = i + 2;
    let matched = 0;
    while (k < chars.length) {
      const seg = lower.slice(i, k + 1);
      if (isSequence(seg) || KEYBOARD_ROWS.some((r) => r.includes(seg))) matched = k;
      else break;
      k++;
    }
    if (matched) {
      bits += Math.log2(pool) + 2;
      warning ||= 'Avoid sequences and keyboard patterns';
      i = matched + 1;
      continue;
    }
    // dictionary word (longest match, 4..12 chars)
    let word = 0;
    for (let L = Math.min(12, chars.length - i); L >= 4; L--) {
      if (DICT.has(unleet.slice(i, i + L))) {
        word = L;
        break;
      }
    }
    if (word) {
      bits += Math.log2(DICT.size) + (/[A-Z]/.test(pw.slice(i, i + word)) ? 1 : 0);
      i += word;
      continue;
    }
    bits += Math.log2(pool);
    i++;
  }
  if (/^\d+$/.test(pw)) warning ||= 'Numbers alone are easy to guess';
  if (/^(19|20)\d\d$/.test(pw.slice(-4))) {
    bits -= 4;
    warning ||= 'Years are easy to guess';
  }
  bits = Math.max(0, Math.round(bits));
  const score = bits < 28 ? 0 : bits < 40 ? 1 : bits < 60 ? 2 : bits < 80 ? 3 : 4;
  if (!warning && score < 3 && pw.length < 12) warning = 'Use at least 12 characters';
  return { score, bits, label: ['Very weak', 'Weak', 'Fair', 'Strong', 'Excellent'][score], warning };
}

/** Human-readable offline crack time for an attacker doing 1e10 guesses/s. */
export function crackTime(bits) {
  const secs = 2 ** bits / 2 / 1e10;
  if (secs < 1) return 'instantly';
  if (secs < 60) return `${Math.round(secs)} seconds`;
  if (secs < 3600) return `${Math.round(secs / 60)} minutes`;
  if (secs < 86400) return `${Math.round(secs / 3600)} hours`;
  if (secs < 86400 * 365) return `${Math.round(secs / 86400)} days`;
  if (secs < 86400 * 365 * 1000) return `${Math.round(secs / 86400 / 365)} years`;
  return 'millennia+';
}
