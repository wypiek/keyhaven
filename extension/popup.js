// Keyhaven toolbar popup: sign in / unlock, site suggestions, quick copy & fill, generator.

import { h, icon, mark, clear, passwordSpan, avatar, itemSubtitle, setIconLoader, verifiedBadge, applyBranding, brandMark } from './ui/dom.js';
import { itemVerified, setVerifiedDomains } from './shared/verified.js';
import { rpc, backend } from './bridge.js';
import { totpCode } from './shared/totp.js';
import { generatePassword, DEFAULT_GENERATOR, generatorEntropy } from './shared/generator.js';
import { crackTime, estimateStrength } from './shared/strength.js';
import { displayHost, itemMatchScore } from './shared/urlmatch.js';

const root = document.getElementById('popup');
const call = backend.call;
let status = null;
let items = [];
let tab = null;
let view = 'main';
let current = null;
let query = '';
let timers = [];
let sel = 0;

const toastsEl = h('div.toasts');
document.body.append(toastsEl);
function toast(msg, err = false) {
  const t = h(`div.toast${err ? '.err' : ''}`, icon(err ? 'alert' : 'check', 15), msg);
  toastsEl.append(t);
  setTimeout(() => t.remove(), err ? 3800 : 2000);
}
const fail = (e) => toast(e?.message || String(e), true);

async function copy(text, label, sensitive = true) {
  if (!text) return;
  try {
    await backend.copy(text, sensitive);
    toast(label);
  } catch (e) {
    fail(e);
  }
}

async function load() {
  [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  status = await call('status');
  setIconLoader(status.unlocked && status.settings?.showIcons !== false ? (hosts) => call('icons', { hosts }) : null);
  setVerifiedDomains(status.verifiedDomains ?? null);
  if (status.loggedIn) applyBranding(status.branding);
  items = status.unlocked ? await call('list') : [];
  render();
  if (status.unlocked) call('sync').then(async () => {
    items = await call('list');
    if (view === 'main') renderMain();
  }).catch(() => {});
}

chrome.runtime.onMessage.addListener(async (msg) => {
  if (msg?.type !== 'kh:event' || msg.evt === 'settings') return;
  const was = status?.unlocked;
  status = await call('status');
  if (status.unlocked) items = await call('list');
  if (was !== status.unlocked || view === 'main') render();
});

function render() {
  timers.forEach(clearInterval);
  timers = [];
  clear(root);
  if (!status.loggedIn) return root.append(renderSignIn());
  if (!status.unlocked) return root.append(renderUnlock());
  if (view === 'detail' && current) return root.append(head(), renderDetail());
  if (view === 'generator') return root.append(head(), renderGenerator());
  root.append(head(), searchBar(), mainBody(), foot());
  renderMain();
}

function head() {
  return h('div.p-head',
    view !== 'main' ? h('button.icon-btn', { title: 'Back', on: { click: () => { view = 'main'; render(); } } }, icon('arrowLeft', 16)) : brandMark(status.branding, 20, 'p-mark'),
    h('span.name', view === 'generator' ? 'Generator' : status.branding?.name || 'Keyhaven'),
    h('div.acts',
      h('button.icon-btn', { title: 'Password generator', on: { click: () => { view = 'generator'; render(); } } }, icon('wand', 16)),
      h('button.icon-btn', { title: 'Open vault in a tab', on: { click: () => openVault() } }, icon('external', 16)),
      h('button.icon-btn', { title: 'Lock', on: { click: () => call('lock').then(load) } }, icon('lock', 16))));
}

function openVault(item) {
  rpc('kh:openVault', { item });
  window.close();
}

// ---------- auth ----------

function renderSignIn() {
  const server = h('input.input', { placeholder: 'https://vault.example.com', value: backend.lastServer(), spellcheck: 'false' });
  const email = h('input.input', { type: 'email', placeholder: 'Email', autocomplete: 'username' });
  const pw = h('input.input', { type: 'password', placeholder: 'Master password', autocomplete: 'current-password' });
  const insecure = h('input', { type: 'checkbox' });
  const insecureRow = h('label.check', { style: { display: 'none', margin: '-6px 0 12px' } }, insecure, h('span', 'Allow insecure HTTP (testing only)'));
  server.addEventListener('input', () => {
    insecureRow.style.display = /^http:\/\//i.test(server.value) && !/^http:\/\/(localhost|127\.)/i.test(server.value) ? '' : 'none';
  });
  const err = h('div.error-text');
  const btn = h('button.btn.primary.block', { type: 'submit' }, 'Sign in');
  const form = h('form', { on: { submit: async (e) => {
    e.preventDefault();
    err.textContent = '';
    btn.disabled = true;
    clear(btn).append(h('span.spinner'), 'Signing in…');
    try {
      await call('login', { serverUrl: server.value, email: email.value, password: pw.value, allowInsecure: insecure.checked });
      backend.rememberServer(server.value.trim());
      await load();
    } catch (e2) {
      err.textContent = e2.message;
      btn.disabled = false;
      btn.textContent = 'Sign in';
    }
  } } },
  h('div.field', h('label.label', 'Server URL'), server), insecureRow,
  h('div.field', h('label.label', 'Email'), email),
  h('div.field', h('label.label', 'Master password'), pw),
  btn, err);
  setTimeout(() => (server.value ? email : server).focus(), 0);
  return h('div.p-auth',
    h('div.auth-brand', h('div.mark', mark(18)), h('div', h('h1', 'Keyhaven'), h('p', 'Sign in to your server.'))),
    form,
    h('div.auth-foot', h('span.muted', 'New here?'), h('button.link', { on: { click: () => openVault() } }, 'Create an account')));
}

function renderUnlock() {
  const pw = h('input.input', { type: 'password', placeholder: 'Master password', autocomplete: 'current-password' });
  const err = h('div.error-text');
  const btn = h('button.btn.primary.block', { type: 'submit' }, 'Unlock');
  const form = h('form', { on: { submit: async (e) => {
    e.preventDefault();
    if (!pw.value) return;
    btn.disabled = true;
    clear(btn).append(h('span.spinner'), 'Unlocking…');
    try {
      await call('unlock', { password: pw.value });
      await load();
    } catch (e2) {
      err.textContent = e2.message;
      btn.disabled = false;
      btn.textContent = 'Unlock';
      pw.select();
    }
  } } }, h('div.field', pw), btn, err);
  setTimeout(() => pw.focus(), 0);
  return h('div.p-auth',
    h('div.auth-brand', brandMark(status.branding, 34), h('div', h('h1', 'Locked'), h('p', status.email))),
    form,
    h('div.auth-foot', h('span.muted', displayHost(status.serverUrl)), h('button.link.muted', { on: { click: () => openVault() } }, 'Open vault')));
}

// ---------- main list ----------

let searchInput;
let bodyEl;

function searchBar() {
  searchInput = h('input.input', { type: 'search', placeholder: 'Search Keyhaven', value: query, spellcheck: 'false' });
  searchInput.addEventListener('input', () => {
    query = searchInput.value;
    sel = 0;
    renderMain();
  });
  searchInput.addEventListener('keydown', (e) => {
    const rows = [...bodyEl.querySelectorAll('.p-row')];
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      sel = Math.max(0, Math.min(rows.length - 1, sel + (e.key === 'ArrowDown' ? 1 : -1)));
      rows.forEach((r, i) => r.classList.toggle('sel', i === sel));
      rows[sel]?.scrollIntoView({ block: 'nearest' });
    } else if (e.key === 'Enter') {
      rows[sel]?.dispatchEvent(new CustomEvent('kh-activate'));
    }
  });
  setTimeout(() => searchInput.focus(), 0);
  return h('div.p-search', h('div.search', icon('search', 16), searchInput));
}

function mainBody() {
  bodyEl = h('div.p-body');
  return bodyEl;
}

function foot() {
  return h('div.p-foot',
    h('button.btn.sm', { on: { click: () => openVault() } }, 'Open vault'),
    h('button.btn.sm', { on: { click: () => openVault('new') } }, 'New item'));
}

async function fillItem(it, force = false) {
  if (!tab?.id) return;
  try {
    const r = await rpc('kh:fill', { id: it.id, tabId: tab.id, force });
    if (r.mismatch && !r.filled) {
      if (confirm(`“${it.title}” isn't saved for ${displayHost(tab.url)}. Fill it anyway?`)) return fillItem(it, true);
      return;
    }
    if (!r.filled) return toast('No login form found on this page', true);
    window.close();
  } catch (e) {
    fail(e);
  }
}

function titleLine(it, tag = 'div.t') {
  const v = itemVerified(it);
  return h(`${tag}.title-line`, h('span', it.title), v && verifiedBadge(v, 13));
}

function row(it, { suggested = false } = {}) {
  const isLogin = it.type === 'login';
  const r = h('div.p-row', avatar(it, 28),
    h('div.grow', titleLine(it), h('div.s', itemSubtitle(it))),
    h(`div.ra${suggested ? '.always' : ''}`,
      isLogin && it.password && h('button.tbtn', { on: { click: (e) => { e.stopPropagation(); copy(it.password, 'Password copied'); } } }, 'Copy'),
      isLogin && suggested && h('button.btn.sm', { on: { click: (e) => { e.stopPropagation(); fillItem(it); } } }, 'Fill'),
      h('button.icon-btn.sm', { title: 'Details', on: { click: (e) => { e.stopPropagation(); showDetail(it); } } }, icon('chevronRight', 15))));
  const activate = () => (isLogin && suggested ? fillItem(it) : showDetail(it));
  r.addEventListener('click', activate);
  r.addEventListener('kh-activate', activate);
  return r;
}

async function renderSavePrompt() {
  if (!tab?.id) return null;
  const p = await rpc('kh:savePrompt', { tabId: tab.id }).catch(() => null);
  if (!p || p.kind === 'locked') return null;
  const box = h('div.p-save',
    h('div.t', p.kind === 'update' ? `Update password for ${p.title}?` : 'Save the login you just used?'),
    h('div.s', `${p.username || '(no username)'} · ${p.host}`),
    h('div.row',
      h('button.btn.sm', { on: { click: async () => { await rpc('kh:resolveSave', { tabId: tab.id, action: 'dismiss' }); box.remove(); } } }, 'Not now'),
      h('button.btn.sm.primary', { on: { click: async () => {
        try {
          const r = await rpc('kh:resolveSave', { tabId: tab.id, action: 'save' });
          box.remove();
          if (r?.saved) toast(r.updated ? 'Password updated' : 'Login saved');
          items = await call('list');
          renderMain();
        } catch (e) {
          fail(e);
        }
      } } }, p.kind === 'update' ? 'Update' : 'Save')));
  return box;
}

async function renderMain() {
  if (!bodyEl) return;
  const live = items.filter((i) => !i.deletedAt);
  clear(bodyEl);
  const save = await renderSavePrompt();
  if (save) bodyEl.append(save);
  const q = query.trim().toLowerCase();
  if (q) {
    const words = q.split(/\s+/);
    const res = live.filter((i) => {
      const hay = [i.title, i.username, ...i.urls, ...i.tags, i.card.number.slice(-4), i.identity.email].join(' ').toLowerCase();
      return words.every((w) => hay.includes(w));
    }).sort((a, b) => a.title.localeCompare(b.title));
    if (!res.length) bodyEl.append(h('div.p-empty', `No items match “${query}”`));
    res.slice(0, 60).forEach((it) => bodyEl.append(row(it, { suggested: tab?.url && itemMatchScore(it, tab.url) > 0 })));
  } else {
    const site = tab?.url && /^https?:/.test(tab.url) ? displayHost(tab.url) : '';
    const matches = site ? live.filter((i) => itemMatchScore(i, tab.url) > 0)
      .sort((a, b) => itemMatchScore(b, tab.url) - itemMatchScore(a, tab.url) || (b.lastUsedAt || 0) - (a.lastUsedAt || 0)) : [];
    if (site) {
      bodyEl.append(h('div.p-section', site));
      if (matches.length) matches.forEach((it) => bodyEl.append(row(it, { suggested: true })));
      else bodyEl.append(h('div.p-empty', 'Nothing saved for this site.'));
    }
    const favs = live.filter((i) => i.favorite && !matches.includes(i));
    if (favs.length) {
      bodyEl.append(h('div.p-section', h('span', 'Favorites')));
      favs.sort((a, b) => a.title.localeCompare(b.title)).forEach((it) => bodyEl.append(row(it)));
    }
    const recent = live.filter((i) => !i.favorite && !matches.includes(i))
      .sort((a, b) => Math.max(b.lastUsedAt || 0, b.updatedAt) - Math.max(a.lastUsedAt || 0, a.updatedAt)).slice(0, 8);
    if (recent.length) {
      bodyEl.append(h('div.p-section', h('span', 'Recent')));
      recent.forEach((it) => bodyEl.append(row(it)));
    }
    if (!live.length) bodyEl.append(h('div.p-empty', 'Nothing saved yet. Log in to a site and Keyhaven will offer to save it.'));
  }
  bodyEl.querySelectorAll('.p-row')[sel]?.classList.add('sel');
}

// ---------- detail ----------

function showDetail(it) {
  current = it;
  view = 'detail';
  render();
}

function frow(label, value, { secret = false, mono = false, copyLabel } = {}) {
  let shown = !secret;
  const v = h('div.v');
  const paint = () => clear(v).append(shown ? (secret || mono ? passwordSpan(value) : value) : '••••••••••');
  paint();
  const acts = h('div.acts');
  if (secret) {
    const eye = h('button.tbtn', 'Show');
    eye.addEventListener('click', (e) => {
      e.stopPropagation();
      shown = !shown;
      eye.textContent = shown ? 'Hide' : 'Show';
      paint();
    });
    acts.append(eye);
  }
  acts.append(h('button.tbtn', 'Copy'));
  const r = h('div.frow.copyable', h('div.grow', h('div.k', label), v), acts);
  r.addEventListener('click', () => copy(value, copyLabel || `${label} copied`, secret));
  return r;
}

function renderDetail() {
  const it = current;
  const rows = [];
  if (it.type === 'login') {
    if (it.username) rows.push(frow('Username', it.username));
    if (it.password) rows.push(frow('Password', it.password, { secret: true }));
    if (it.totp) {
      const code = h('span.code', '…');
      const left = h('span.muted', { style: { fontSize: '12px' } });
      let val = '';
      const tick = async () => {
        try {
          const t = await totpCode(it.totp);
          val = t.code;
          code.textContent = t.code;
          left.textContent = `${t.remaining}s`;
        } catch {
          code.textContent = 'invalid';
        }
      };
      tick();
      timers.push(setInterval(tick, 1000));
      const r = h('div.frow.copyable', h('div.grow', h('div.k', 'One-time code'), h('div.totp', code, left)), h('div.acts', h('button.tbtn', 'Copy')));
      r.addEventListener('click', () => copy(val, 'Code copied'));
      rows.push(r);
    }
    for (const pk of it.passkeys || []) rows.push(h('div.frow', h('div.grow', h('div.k', 'Passkey'), h('div.v', `${pk.userName || it.username || 'account'} on ${pk.rpId}`))));
    it.urls.forEach((u) => rows.push(frow(displayHost(u) || 'Website', u, { copyLabel: 'URL copied' })));
  } else if (it.type === 'card') {
    if (it.card.cardholder) rows.push(frow('Cardholder', it.card.cardholder));
    if (it.card.number) rows.push(frow('Number', it.card.number, { secret: true }));
    if (it.card.expMonth || it.card.expYear) rows.push(frow('Expires', `${it.card.expMonth}/${it.card.expYear}`));
    if (it.card.cvv) rows.push(frow('Security code', it.card.cvv, { secret: true }));
  } else if (it.type === 'identity') {
    const i = it.identity;
    const name = [i.firstName, i.lastName].filter(Boolean).join(' ');
    if (name) rows.push(frow('Name', name));
    if (i.email) rows.push(frow('Email', i.email));
    if (i.phone) rows.push(frow('Phone', i.phone));
  }
  it.fields.forEach((f) => rows.push(frow(f.label || 'Field', f.value, { secret: f.hidden })));
  if (it.notes) rows.push(h('div.frow', h('div.grow', h('div.k', 'Notes'), h('div.notes-v', it.notes.length > 400 ? `${it.notes.slice(0, 400)}…` : it.notes))));
  const canFill = it.type === 'login' && tab?.id && /^https?:/.test(tab.url || '');
  return h('div.p-detail',
    h('div.detail-head', avatar(it, 32), h('div.grow', titleLine(it, 'h2'), h('div.meta', itemSubtitle(it)))),
    rows.length ? h('div.card', rows) : h('div.p-empty', 'No fields'),
    h('div.row', { style: { gap: '8px' } },
      canFill && h('button.btn.primary.grow', { on: { click: () => fillItem(it) } }, 'Fill'),
      h('button.btn.grow', { on: { click: () => openVault(it.id) } }, 'Edit')));
}

// ---------- generator ----------

function renderGenerator() {
  let o;
  try {
    o = { ...DEFAULT_GENERATOR, ...JSON.parse(localStorage.getItem('keyhaven.generator') || '{}') };
  } catch {
    o = { ...DEFAULT_GENERATOR };
  }
  const out = h('div.pw');
  const info = h('div.muted', { style: { fontSize: '12px', margin: '-4px 0 14px' } });
  let pw = '';
  const regen = () => {
    localStorage.setItem('keyhaven.generator', JSON.stringify(o));
    pw = generatePassword(o);
    clear(out).append(passwordSpan(pw));
    const bits = Math.round(generatorEntropy(o));
    info.textContent = `${estimateStrength(pw).label} · ${bits} bits · ${crackTime(bits)} to crack`;
  };
  const opts = h('div.gen-opts');
  const paint = () => {
    clear(opts);
    opts.append(h('div.segmented', ['random', 'passphrase', 'pin'].map((k) =>
      h(`button${o.kind === k ? '.on' : ''}`, { on: { click: () => { o.kind = k; paint(); regen(); } } }, { random: 'Random', passphrase: 'Words', pin: 'PIN' }[k]))));
    const slider = (label, key, min, max) => {
      const val = h('span.val', o[key]);
      const r = h('input', { type: 'range', min, max, value: o[key] });
      r.addEventListener('input', () => { o[key] = +r.value; val.textContent = r.value; regen(); });
      return h('div', h('div.opt-row', h('span.lbl', label), val), r);
    };
    const tog = (label, key) => {
      const inp = h('input', { type: 'checkbox', checked: o[key] });
      inp.addEventListener('change', () => { o[key] = inp.checked; regen(); });
      return h('label.opt-row', { style: { cursor: 'pointer' } }, h('span', label), h('span.toggle', inp, h('span')));
    };
    if (o.kind === 'random') opts.append(slider('Length', 'length', 8, 64), tog('Uppercase', 'upper'), tog('Lowercase', 'lower'), tog('Digits', 'digits'), tog('Symbols', 'symbols'));
    else if (o.kind === 'passphrase') opts.append(slider('Words', 'words', 3, 12), tog('Capitalize', 'capitalize'), tog('Include number', 'includeNumber'));
    else opts.append(slider('Digits', 'pinLength', 4, 16));
  };
  paint();
  regen();
  const canFill = tab?.id && /^https?:/.test(tab.url || '');
  return h('div.p-gen',
    h('div.gen-out', out, h('button.icon-btn', { title: 'Regenerate', on: { click: regen } }, icon('refresh', 16))),
    info,
    h('div.row', { style: { gap: '8px', marginBottom: '16px' } },
      h('button.btn.primary.grow', { on: { click: () => copy(pw, 'Password copied') } }, icon('copy', 15), 'Copy'),
      canFill && h('button.btn.grow', { on: { click: async () => {
        const ok = await rpc('kh:fillGenerated', { tabId: tab.id, password: pw });
        if (ok) window.close();
        else toast('Click into a password field first', true);
      } } }, icon('zap', 15), 'Fill')),
    opts);
}

load().catch((e) => {
  clear(root).append(h('div.p-auth', h('div.banner.danger', icon('alert', 18), h('div', e.message))));
});
