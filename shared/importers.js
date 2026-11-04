// Importers for common password-manager exports, plus Keyhaven's own export format.
// Supported: Keyhaven JSON, Bitwarden JSON/CSV, 1Password CSV, Chrome/Edge/Brave/Helium CSV,
// Firefox CSV, LastPass CSV, Proton Pass CSV and generic CSVs with recognisable headers.

export function parseCsv(text) {
  const rows = [];
  let row = [];
  let field = '';
  let q = false;
  text = text.replace(/^﻿/, '');
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else q = false;
      } else field += c;
    } else if (c === '"') q = true;
    else if (c === ',') {
      row.push(field);
      field = '';
    } else if (c === '\n' || c === '\r') {
      if (c === '\r' && text[i + 1] === '\n') i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = '';
    } else field += c;
  }
  if (field !== '' || row.length) {
    row.push(field);
    rows.push(row);
  }
  return rows.filter((r) => r.some((f) => f.trim() !== ''));
}

export function toCsv(rows) {
  return rows
    .map((r) => r.map((f) => (/[",\r\n]/.test(f) ? `"${String(f).replace(/"/g, '""')}"` : String(f ?? ''))).join(','))
    .join('\r\n');
}

const pick = (obj, ...keys) => {
  for (const k of keys) if (obj[k] != null && String(obj[k]).trim() !== '') return String(obj[k]);
  return '';
};

function blank(type = 'login') {
  return { type, title: '', favorite: false, tags: [], notes: '', username: '', password: '', urls: [], totp: '', fields: [] };
}

function fromCsv(text) {
  const rows = parseCsv(text);
  if (rows.length < 2) throw new Error('The CSV file has no entries');
  const headers = rows[0].map((h) => h.trim().toLowerCase());
  const items = [];
  for (const r of rows.slice(1)) {
    const o = {};
    headers.forEach((h, i) => (o[h] = r[i] ?? ''));
    const it = blank();
    const bwType = pick(o, 'type').toLowerCase();
    if (bwType === 'note' || bwType === 'securenote') it.type = 'note';
    it.title = pick(o, 'name', 'title', 'item name', 'hostname');
    it.username = pick(o, 'username', 'login_username', 'login', 'user', 'email', 'login name');
    it.password = pick(o, 'password', 'login_password');
    it.totp = pick(o, 'totp', 'login_totp', 'otpauth', 'one-time password', 'otp', 'onetimepassword');
    it.notes = pick(o, 'notes', 'note', 'extra', 'comments', 'notes plain');
    const url = pick(o, 'url', 'login_uri', 'website', 'uri', 'web site', 'origin');
    it.urls = url.split(/[,\n]/).map((s) => s.trim()).filter(Boolean);
    const tags = pick(o, 'tags', 'folder', 'grouping', 'vault', 'category');
    it.tags = tags.split(/[;,/]/).map((s) => s.trim()).filter(Boolean);
    it.favorite = /^(1|true|yes)$/i.test(pick(o, 'favorite', 'fav'));
    if (it.type === 'login' && !it.username && !it.password && !it.urls.length && it.notes) it.type = 'note';
    if (!it.title) it.title = it.urls[0] ? hostOf(it.urls[0]) : it.username || 'Imported item';
    if (it.password || it.username || it.notes || it.urls.length) items.push(it);
  }
  return items;
}

function hostOf(u) {
  try {
    return new URL(/:\/\//.test(u) ? u : `https://${u}`).hostname.replace(/^www\./, '');
  } catch {
    return u;
  }
}

function fromBitwardenJson(j) {
  const folders = Object.fromEntries((j.folders || []).map((f) => [f.id, f.name]));
  return (j.items || []).map((b) => {
    const t = { 1: 'login', 2: 'note', 3: 'card', 4: 'identity' }[b.type] || 'note';
    const it = blank(t);
    it.title = b.name || 'Imported item';
    it.notes = b.notes || '';
    it.favorite = !!b.favorite;
    if (b.folderId && folders[b.folderId]) it.tags = [folders[b.folderId]];
    if (b.login) {
      it.username = b.login.username || '';
      it.password = b.login.password || '';
      it.totp = b.login.totp || '';
      it.urls = (b.login.uris || []).map((u) => u.uri).filter(Boolean);
    }
    if (b.card) {
      it.card = {
        cardholder: b.card.cardholderName || '', number: b.card.number || '', expMonth: b.card.expMonth || '',
        expYear: b.card.expYear || '', cvv: b.card.code || '', pin: '',
      };
    }
    if (b.identity) {
      const i = b.identity;
      it.identity = {
        firstName: i.firstName || '', lastName: i.lastName || '', email: i.email || '', phone: i.phone || '',
        company: i.company || '', address1: i.address1 || '', address2: i.address2 || '', city: i.city || '',
        state: i.state || '', postalCode: i.postalCode || '', country: i.country || '',
      };
    }
    it.fields = (b.fields || []).map((f) => ({ label: f.name || '', value: f.value || '', hidden: f.type === 1 }));
    return it;
  });
}

export function importFile(text, filename = '') {
  const trimmed = text.trim();
  if (trimmed.startsWith('{') || trimmed.startsWith('[')) {
    let j;
    try {
      j = JSON.parse(trimmed);
    } catch {
      throw new Error('The file is not valid JSON');
    }
    if (j.encrypted) throw new Error('Encrypted exports are not supported — export unencrypted JSON or CSV instead');
    if (j.format === 'keyhaven-export' && Array.isArray(j.items)) {
      return j.items.map(({ id, ...rest }) => ({ ...blank(rest.type), ...rest }));
    }
    if (Array.isArray(j.items)) return fromBitwardenJson(j);
    throw new Error('Unrecognised JSON export');
  }
  if (/\.1pux$/i.test(filename)) throw new Error('Export from 1Password as CSV instead of 1PUX');
  return fromCsv(text);
}
