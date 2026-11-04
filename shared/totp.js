// RFC 6238 TOTP via WebCrypto. Accepts base32 secrets or otpauth:// URIs.

const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

function base32Decode(input) {
  const s = input.replace(/[\s=-]/g, '').toUpperCase();
  if (!s) throw new Error('Empty secret');
  let bits = 0;
  let value = 0;
  const out = [];
  for (const ch of s) {
    const idx = B32.indexOf(ch);
    if (idx < 0) throw new Error('Secret is not valid base32');
    value = (value << 5) | idx;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  if (!out.length) throw new Error('Secret is too short');
  return new Uint8Array(out);
}

export function parseTotp(input) {
  const raw = String(input || '').trim();
  if (!raw) throw new Error('Empty secret');
  if (/^otpauth:\/\//i.test(raw)) {
    const u = new URL(raw);
    if (u.host.toLowerCase() === 'hotp') throw new Error('HOTP codes are not supported');
    const p = u.searchParams;
    const secret = p.get('secret');
    if (!secret) throw new Error('otpauth URI has no secret');
    const algo = (p.get('algorithm') || 'SHA1').toUpperCase();
    let digits = parseInt(p.get('digits') || '6', 10);
    let period = parseInt(p.get('period') || '30', 10);
    if (!(digits >= 6 && digits <= 10)) digits = 6;
    if (!(period > 0 && period <= 300)) period = 30;
    const label = decodeURIComponent(u.pathname.replace(/^\/+/, ''));
    return {
      secret: base32Decode(secret),
      digits,
      period,
      algorithm: algo === 'SHA256' ? 'SHA-256' : algo === 'SHA512' ? 'SHA-512' : 'SHA-1',
      issuer: p.get('issuer') || label.split(':')[0] || '',
      account: label.includes(':') ? label.split(':').slice(1).join(':') : label,
    };
  }
  return { secret: base32Decode(raw), digits: 6, period: 30, algorithm: 'SHA-1', issuer: '', account: '' };
}

export function isValidTotp(input) {
  try {
    parseTotp(input);
    return true;
  } catch {
    return false;
  }
}

export async function totpCode(input, now = Date.now()) {
  const spec = parseTotp(input);
  const secs = Math.floor(now / 1000);
  const counter = Math.floor(secs / spec.period);
  const msg = new Uint8Array(8);
  let c = counter;
  for (let i = 7; i >= 0; i--) {
    msg[i] = c & 0xff;
    c = Math.floor(c / 256);
  }
  const key = await crypto.subtle.importKey('raw', spec.secret, { name: 'HMAC', hash: spec.algorithm }, false, ['sign']);
  const h = new Uint8Array(await crypto.subtle.sign('HMAC', key, msg));
  const off = h[h.length - 1] & 0x0f;
  const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
  const code = String(bin % 10 ** spec.digits).padStart(spec.digits, '0');
  return { code, period: spec.period, remaining: spec.period - (secs % spec.period) };
}
