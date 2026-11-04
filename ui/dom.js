// Tiny DOM helpers. All user data goes through textContent / attributes — never innerHTML.

const SVG_NS = 'http://www.w3.org/2000/svg';

const ICONS = {
  lock: ['R3,11,18,11,2', 'M7 11V7a5 5 0 0 1 10 0v4'],
  unlock: ['R3,11,18,11,2', 'M7 11V7a5 5 0 0 1 9.9-1'],
  key: ['C7.5,15.5,5.5', 'm21 2-9.6 9.6', 'm15.5 7.5 3 3L22 7l-3-3'],
  search: ['C11,11,8', 'm21 21-4.3-4.3'],
  plus: ['M5 12h14', 'M12 5v14'],
  star: ['M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z'],
  trash: ['M3 6h18', 'M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6', 'M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2'],
  copy: ['R9,9,13,13,2', 'M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1'],
  eye: ['M2 12s3-7 10-7 10 7 10 7-3 7-10 7-10-7-10-7Z', 'C12,12,3'],
  eyeOff: ['M9.88 9.88a3 3 0 1 0 4.24 4.24', 'M10.73 5.08A10.4 10.4 0 0 1 12 5c7 0 10 7 10 7a13.2 13.2 0 0 1-1.67 2.68', 'M6.61 6.61A13.5 13.5 0 0 0 2 12s3 7 10 7a9.7 9.7 0 0 0 5.39-1.61', 'm2 2 20 20'],
  refresh: ['M21 12a9 9 0 1 1-3-6.7L21 8', 'M21 3v5h-5'],
  sliders: ['M4 21v-7', 'M4 10V3', 'M12 21v-9', 'M12 8V3', 'M20 21v-5', 'M20 12V3', 'M1 14h6', 'M9 8h6', 'M17 16h6'],
  shield: ['M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z'],
  shieldCheck: ['M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z', 'm9 12 2 2 4-4'],
  globe: ['C12,12,10', 'M2 12h20', 'M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z'],
  card: ['R2,5,20,14,2', 'M2 10h20'],
  note: ['M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z', 'M14 2v6h6', 'M16 13H8', 'M16 17H8'],
  user: ['M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2', 'C12,7,4'],
  tag: ['M12 2H2v10l9.29 9.29a1 1 0 0 0 1.41 0l8.59-8.59a1 1 0 0 0 0-1.41z', 'C7,7,1.5'],
  external: ['M15 3h6v6', 'M10 14 21 3', 'M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6'],
  x: ['M18 6 6 18', 'M6 6l12 12'],
  check: ['M20 6 9 17l-5-5'],
  clock: ['C12,12,10', 'M12 6v6l4 2'],
  download: ['M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4', 'M7 10l5 5 5-5', 'M12 15V3'],
  upload: ['M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4', 'M17 8l-5-5-5 5', 'M12 3v12'],
  wand: ['M15 4V2', 'M15 16v-2', 'M8 9h2', 'M20 9h2', 'M17.8 11.8 19 13', 'M17.8 6.2 19 5', 'M3 21l9-9', 'M12.2 6.2 11 5'],
  edit: ['M17 3a2.85 2.85 0 1 1 4 4L7.5 20.5 2 22l1.5-5.5Z'],
  grid: ['R3,3,7,7,1', 'R14,3,7,7,1', 'R14,14,7,7,1', 'R3,14,7,7,1'],
  logout: ['M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4', 'M16 17l5-5-5-5', 'M21 12H9'],
  monitor: ['R2,3,20,14,2', 'M8 21h8', 'M12 17v4'],
  alert: ['M10.29 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z', 'M12 9v4', 'M12 17h.01'],
  chevronRight: ['m9 18 6-6-6-6'],
  chevronDown: ['m6 9 6 6 6-6'],
  arrowLeft: ['M19 12H5', 'M12 19l-7-7 7-7'],
  zap: ['M13 2 3 14h9l-1 8 10-12h-9l1-8z'],
  server: ['R2,2,20,8,2', 'R2,14,20,8,2', 'M6 6h.01', 'M6 18h.01'],
  undo: ['M3 7v6h6', 'M21 17a9 9 0 0 0-15-6.7L3 13'],
  minus: ['M5 12h14'],
  history: ['M3 12a9 9 0 1 0 3-6.7L3 8', 'M3 3v5h5', 'M12 7v5l4 2'],
  hash: ['M4 9h16', 'M4 15h16', 'M10 3 8 21', 'M16 3l-2 18'],
};

export function icon(name, size = 18, cls = '') {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.setAttribute('fill', 'none');
  svg.setAttribute('stroke', 'currentColor');
  svg.setAttribute('stroke-width', '1.8');
  svg.setAttribute('stroke-linecap', 'round');
  svg.setAttribute('stroke-linejoin', 'round');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('class', `icon ${cls}`.trim());
  for (const d of ICONS[name] || []) {
    let el;
    if (d[0] === 'R') {
      const [x, y, w, hh, r] = d.slice(1).split(',');
      el = document.createElementNS(SVG_NS, 'rect');
      Object.entries({ x, y, width: w, height: hh, rx: r }).forEach(([k, v]) => el.setAttribute(k, v));
    } else if (d[0] === 'C') {
      const [cx, cy, r] = d.slice(1).split(',');
      el = document.createElementNS(SVG_NS, 'circle');
      Object.entries({ cx, cy, r }).forEach(([k, v]) => el.setAttribute(k, v));
    } else {
      el = document.createElementNS(SVG_NS, 'path');
      el.setAttribute('d', d);
    }
    svg.appendChild(el);
  }
  return svg;
}

export function logo(size = 28) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 64 64');
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.setAttribute('class', 'logo');
  svg.setAttribute('aria-hidden', 'true');
  const p1 = document.createElementNS(SVG_NS, 'path');
  p1.setAttribute('d', 'M32 4 8 13v17c0 15 10.4 25.6 24 30 13.6-4.4 24-15 24-30V13L32 4z');
  p1.setAttribute('fill', 'var(--accent)');
  const p2 = document.createElementNS(SVG_NS, 'path');
  p2.setAttribute('d', 'M32 20a7 7 0 0 0-3.5 13.06L26 44h12l-2.5-10.94A7 7 0 0 0 32 20z');
  p2.setAttribute('fill', 'var(--accent-ink)');
  svg.append(p1, p2);
  return svg;
}

/** h('div.cls#id', {attrs, on:{click}}, ...children) */
export function h(spec, attrs, ...children) {
  if (attrs == null || typeof attrs !== 'object' || attrs instanceof Node || Array.isArray(attrs)) {
    children.unshift(attrs);
    attrs = {};
  }
  const [, tag = 'div', rest = ''] = spec.match(/^([a-z0-9-]*)(.*)$/i) || [];
  const el = document.createElement(tag || 'div');
  for (const part of rest.match(/[.#][^.#]+/g) || []) {
    if (part[0] === '.') el.classList.add(part.slice(1));
    else el.id = part.slice(1);
  }
  for (const [k, v] of Object.entries(attrs)) {
    if (v == null || v === false) continue;
    if (k === 'on') for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
    else if (k === 'class') el.classList.add(...String(v).split(/\s+/).filter(Boolean));
    else if (k === 'style' && typeof v === 'object') Object.assign(el.style, v);
    else if (k === 'value') el.value = v;
    else if (k === 'checked') el.checked = !!v;
    else if (k === 'dataset') Object.assign(el.dataset, v);
    else if (v === true) el.setAttribute(k, '');
    else el.setAttribute(k, v);
  }
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

export function clear(el) {
  while (el.firstChild) el.removeChild(el.firstChild);
  return el;
}

/** Colour-coded password rendering: digits and symbols highlighted. */
export function passwordSpan(pw) {
  const span = h('span.pw');
  for (const ch of pw) {
    const cls = /[0-9]/.test(ch) ? 'd' : /[a-zA-Z]/.test(ch) ? '' : 's';
    span.append(cls ? h(`span.${cls}`, ch) : document.createTextNode(ch));
  }
  return span;
}

const HUES = [12, 32, 48, 140, 168, 196, 214, 250, 280, 320, 340];

// ---- website icons: batched, cached per page ----

let iconLoader = null;
const iconMem = new Map(); // host → dataUrl | null (settled)
const inflight = new Map(); // host → Promise (shared by every avatar asking for it)
let iconQueue = new Map(); // host → resolve, waiting for the next batch
let iconTimer = null;

/** fn(hosts[]) → Promise<{host: dataUrl|null}>; null disables icons. */
export function setIconLoader(fn) {
  iconLoader = fn;
}

async function flushIcons() {
  const batch = iconQueue;
  iconQueue = new Map();
  iconTimer = null;
  let result = {};
  try {
    result = (await iconLoader?.([...batch.keys()])) || {};
  } catch {
    /* offline */
  }
  for (const [h, done] of batch) {
    const v = result[h] || null;
    if (h in result) iconMem.set(h, v);
    inflight.delete(h);
    done(v);
  }
}

function requestIcon(host) {
  if (iconMem.has(host)) return Promise.resolve(iconMem.get(host));
  if (!inflight.has(host)) {
    inflight.set(host, new Promise((resolve) => {
      iconQueue.set(host, resolve);
      if (!iconTimer) iconTimer = setTimeout(flushIcons, 25);
    }));
  }
  return inflight.get(host);
}

function iconHost(item) {
  if (item.type !== 'login') return '';
  for (const u of item.urls || []) {
    try {
      const h = new URL(/:\/\//.test(u) ? u : `https://${u}`).hostname.toLowerCase().replace(/^www\./, '');
      if (/^[a-z0-9.-]+\.[a-z]{2,}$/.test(h)) return h;
    } catch { /* skip */ }
  }
  return '';
}

/** Verified seal: smooth scalloped badge with a white check. */
export function verifiedBadge(domain, size = 15) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.setAttribute('class', 'verified');
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', `Verified: ${domain}`);
  const t = document.createElementNS(SVG_NS, 'title');
  t.textContent = `Verified — ${domain} is a well-known website`;
  const seal = document.createElementNS(SVG_NS, 'path');
  seal.setAttribute('d', 'M3.85 8.62a4 4 0 0 1 4.78-4.77 4 4 0 0 1 6.74 0 4 4 0 0 1 4.78 4.78 4 4 0 0 1 0 6.74 4 4 0 0 1-4.77 4.78 4 4 0 0 1-6.75 0 4 4 0 0 1-4.78-4.77 4 4 0 0 1 0-6.76Z');
  seal.setAttribute('fill', 'currentColor');
  const check = document.createElementNS(SVG_NS, 'path');
  check.setAttribute('d', 'm8.6 12.1 2.3 2.3 4.6-4.7');
  check.setAttribute('fill', 'none');
  check.setAttribute('stroke', '#fff');
  check.setAttribute('stroke-width', '2');
  check.setAttribute('stroke-linecap', 'round');
  check.setAttribute('stroke-linejoin', 'round');
  svg.append(t, seal, check);
  return svg;
}

/** Keyhaven mark: a keyhole, drawn in currentColor. */
export function mark(size = 14) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 24 24');
  svg.setAttribute('width', size);
  svg.setAttribute('height', size);
  svg.setAttribute('aria-hidden', 'true');
  const c = document.createElementNS(SVG_NS, 'circle');
  c.setAttribute('cx', '12');
  c.setAttribute('cy', '9.5');
  c.setAttribute('r', '4.5');
  c.setAttribute('fill', 'currentColor');
  const p = document.createElementNS(SVG_NS, 'path');
  p.setAttribute('d', 'M9.6 12h4.8l1.6 9H8z');
  p.setAttribute('fill', 'currentColor');
  svg.append(c, p);
  return svg;
}

/** True if the icon's visible pixels are mostly very light (e.g. a white logo on transparency). */
function isLightIcon(img) {
  try {
    const c = document.createElement('canvas');
    c.width = c.height = 24;
    const ctx = c.getContext('2d', { willReadFrequently: true });
    ctx.drawImage(img, 0, 0, 24, 24);
    const d = ctx.getImageData(0, 0, 24, 24).data;
    let lum = 0;
    let n = 0;
    for (let i = 0; i < d.length; i += 4) {
      const a = d[i + 3] / 255;
      if (a < 0.4) continue;
      lum += (0.2126 * d[i] + 0.7152 * d[i + 1] + 0.0722 * d[i + 2]) / 255;
      n++;
    }
    return n > 20 && lum / n > 0.86 && n < 24 * 24 * 0.9;
  } catch {
    return false;
  }
}

export function avatar(item, size = 36) {
  const icons = { note: 'note', card: 'card', identity: 'user' };
  const seed = (item.urls?.[0] || item.title || '?').replace(/^https?:\/\/(www\.)?/, '');
  let hash = 0;
  for (const c of seed) hash = (hash * 31 + c.charCodeAt(0)) >>> 0;
  const el = h('div.avatar', {
    style: { width: `${size}px`, height: `${size}px`, '--hue': HUES[hash % HUES.length], fontSize: `${Math.round(size * 0.42)}px` },
  });
  if (icons[item.type]) el.append(icon(icons[item.type], Math.round(size * 0.5)));
  else el.textContent = (item.title || seed || '?').trim().charAt(0).toUpperCase() || '?';
  const host = iconLoader && iconHost(item);
  if (host) {
    requestIcon(host).then((url) => {
      if (!url) return;
      const img = new Image();
      img.alt = '';
      img.decoding = 'async';
      img.onload = () => {
        if (img.naturalWidth < 8) return;
        el.replaceChildren(img);
        el.classList.add('has-icon');
        if (isLightIcon(img)) el.classList.add('light-icon');
      };
      img.src = url;
    });
  }
  return el;
}

export function timeAgo(ms) {
  if (!ms) return 'never';
  const s = Math.round((Date.now() - ms) / 1000);
  if (s < 45) return 'just now';
  const units = [[60, 'minute'], [3600, 'hour'], [86400, 'day'], [2592000, 'month'], [31536000, 'year']];
  let out = `${Math.round(s / 60)} minutes ago`;
  for (let i = units.length - 1; i >= 0; i--) {
    if (s >= units[i][0]) {
      const n = Math.round(s / units[i][0]);
      out = `${n} ${units[i][1]}${n === 1 ? '' : 's'} ago`;
      break;
    }
  }
  return out;
}

export function formatDate(ms) {
  return ms ? new Date(ms).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' }) : '—';
}

export function cardBrand(num) {
  const n = (num || '').replace(/\D/g, '');
  if (/^4/.test(n)) return 'Visa';
  if (/^(5[1-5]|2[2-7])/.test(n)) return 'Mastercard';
  if (/^3[47]/.test(n)) return 'American Express';
  if (/^6(011|5)/.test(n)) return 'Discover';
  if (/^35/.test(n)) return 'JCB';
  if (/^3(0[0-5]|[68])/.test(n)) return 'Diners Club';
  return n ? 'Card' : '';
}

export function itemSubtitle(it) {
  if (it.type === 'login') return (it.username || (it.urls[0] || '').replace(/^https?:\/\/(www\.)?/, '')) + (it.passkeys?.length ? ' · passkey' : '');
  if (it.type === 'card') return it.card.number ? `${cardBrand(it.card.number)} •••• ${it.card.number.slice(-4)}` : 'Card';
  if (it.type === 'identity') return [it.identity.firstName, it.identity.lastName].filter(Boolean).join(' ') || it.identity.email;
  return (it.notes || '').split('\n')[0].slice(0, 80);
}

// ---- instance branding ----

export function inkFor(hex) {
  const n = parseInt(hex.slice(1), 16);
  const [r, g, b] = [(n >> 16) & 255, (n >> 8) & 255, n & 255].map((v) => {
    const c = v / 255;
    return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
  });
  return 0.2126 * r + 0.7152 * g + 0.0722 * b > 0.4 ? '#111113' : '#ffffff';
}

/** Apply an instance's accent colour and name to the current page. */
export function applyBranding(b) {
  const root = document.documentElement;
  if (b?.accent && /^#[0-9a-f]{6}$/i.test(b.accent)) {
    root.style.setProperty('--primary', b.accent);
    root.style.setProperty('--primary-ink', inkFor(b.accent));
  } else {
    root.style.removeProperty('--primary');
    root.style.removeProperty('--primary-ink');
  }
  if (b?.name) document.title = b.name;
}

/** The instance logo if one is set, otherwise the Keyhaven keyhole on an accent tile. */
export function brandMark(b, size = 22, cls = 'mark') {
  if (b?.logo && /^data:image\/png;base64,[A-Za-z0-9+/=]+$/.test(b.logo)) {
    const img = new Image();
    img.src = b.logo;
    img.alt = '';
    img.width = img.height = size;
    img.className = `${cls} brand-logo`;
    return img;
  }
  const el = document.createElement('span');
  el.className = cls;
  el.style.width = el.style.height = `${size}px`;
  el.append(mark(Math.round(size * 0.58)));
  return el;
}
