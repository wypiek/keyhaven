// Client-side cryptography. Everything secret is derived and encrypted here; the server
// only ever receives an authentication key (HKDF output, not the password) and ciphertext.
//
//   masterKey = Argon2id(NFKC(password), salt, m=64 MiB, t=3, p=4)        (32 bytes)
//   authKey   = HKDF-SHA256(masterKey, info="keyhaven/auth")             -> sent to server
//   kek       = HKDF-SHA256(masterKey, info="keyhaven/enc")              -> never leaves device
//   vaultKey  = random 256-bit key, stored on server wrapped by kek (AES-256-GCM)
//   item      = AES-256-GCM(vaultKey, JSON, aad="keyhaven/item:<id>")    -> binds ciphertext to its id

import { argon2id } from '../vendor/argon2.js';

const te = new TextEncoder();
const td = new TextDecoder();

export function b64encode(bytes) {
  let s = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(s);
}

export function b64decode(str) {
  const bin = atob(str);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomBytes(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

export function newKdfParams() {
  return { algorithm: 'argon2id', memory: 65536, iterations: 3, parallelism: 4, salt: b64encode(randomBytes(16)) };
}

/** Refuse parameters a malicious or compromised server could use to weaken the KDF. */
export function validateKdf(kdf) {
  const ok =
    kdf &&
    kdf.algorithm === 'argon2id' &&
    Number.isInteger(kdf.memory) && kdf.memory >= 32768 && kdf.memory <= 1048576 &&
    Number.isInteger(kdf.iterations) && kdf.iterations >= 2 && kdf.iterations <= 20 &&
    Number.isInteger(kdf.parallelism) && kdf.parallelism >= 1 && kdf.parallelism <= 8 &&
    typeof kdf.salt === 'string' && b64decode(kdf.salt).length >= 16;
  if (!ok) throw new Error('The server sent unsafe key-derivation parameters. Refusing to continue.');
}

export async function deriveMasterKey(password, kdf) {
  validateKdf(kdf);
  return argon2id({
    password: password.normalize('NFKC'),
    salt: b64decode(kdf.salt),
    parallelism: kdf.parallelism,
    iterations: kdf.iterations,
    memorySize: kdf.memory,
    hashLength: 32,
    outputType: 'binary',
  });
}

export async function deriveSubkeys(masterKey) {
  const base = await crypto.subtle.importKey('raw', masterKey, 'HKDF', false, ['deriveBits']);
  const hkdf = (info) =>
    crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: te.encode(info) }, base, 256);
  const authKey = new Uint8Array(await hkdf('keyhaven/auth'));
  const kekRaw = new Uint8Array(await hkdf('keyhaven/enc'));
  const kek = await crypto.subtle.importKey('raw', kekRaw, 'AES-GCM', false, ['encrypt', 'decrypt']);
  kekRaw.fill(0);
  return { authKey: b64encode(authKey), kek };
}

export async function importAesKey(raw) {
  return crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function encryptBytes(key, bytes, aad) {
  const iv = randomBytes(12);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: te.encode(aad) }, key, bytes);
  return `v1.${b64encode(iv)}.${b64encode(new Uint8Array(ct))}`;
}

async function decryptBytes(key, str, aad) {
  const parts = typeof str === 'string' ? str.split('.') : [];
  if (parts.length !== 3 || parts[0] !== 'v1') throw new Error('Unsupported ciphertext format');
  const pt = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: b64decode(parts[1]), additionalData: te.encode(aad) },
    key,
    b64decode(parts[2]),
  );
  return new Uint8Array(pt);
}

export const wrapKey = (kek, rawVaultKey) => encryptBytes(kek, rawVaultKey, 'keyhaven/wrap');

export async function unwrapKey(kek, wrapped) {
  try {
    return await decryptBytes(kek, wrapped, 'keyhaven/wrap');
  } catch {
    throw new Error('Incorrect master password');
  }
}

export const encryptItem = (vaultKey, item) =>
  encryptBytes(vaultKey, te.encode(JSON.stringify(item)), `keyhaven/item:${item.id}`);

export async function decryptItem(vaultKey, id, data) {
  const item = JSON.parse(td.decode(await decryptBytes(vaultKey, data, `keyhaven/item:${id}`)));
  if (item.id !== id) throw new Error('Item id mismatch');
  return item;
}

export function uuid() {
  return crypto.randomUUID();
}
