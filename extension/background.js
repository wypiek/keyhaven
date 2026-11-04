// Keyhaven extension service worker.
//
// Holds the VaultClient. The decrypted vault key lives in chrome.storage.session
// (memory only, cleared when the browser closes, not readable by content scripts).
// Extension pages (popup, vault tab) get the full RPC surface. Content scripts get a
// narrow API, and every credential request is checked against the *browser-reported*
// URL of the requesting frame (sender.url), never anything the page claims.

import { VaultClient } from './shared/vault.js';
import { dispatch } from './shared/rpc.js';
import { deviceName } from './shared/device.js';
import { totpCode } from './shared/totp.js';
import { generatePassword } from './shared/generator.js';
import { itemMatchScore, displayHost, baseDomain, originFor } from './shared/urlmatch.js';
import { makeCredential, getAssertion, rpIdAllowed, supportsES256 } from './shared/passkey.js';
import { verifiedDomain, setVerifiedDomains } from './shared/verified.js';

const EXT_ORIGIN = chrome.runtime.getURL('');

const store = (area) => ({
  get: async (k) => (await area.get(k))[k],
  set: (k, v) => area.set({ [k]: v }),
  remove: (k) => area.remove(k),
});

chrome.storage.session.setAccessLevel?.({ accessLevel: 'TRUSTED_CONTEXTS' }).catch(() => {});

const vault = new VaultClient({
  storage: store(chrome.storage.local),
  session: store(chrome.storage.session),
  deviceName: deviceName('extension'),
  onChange: (evt) => {
    chrome.runtime.sendMessage({ type: 'kh:event', evt }).catch(() => {});
    if (evt !== 'settings') refreshBadge();
  },
});

// ---------- lifecycle ----------

chrome.runtime.onInstalled.addListener(async ({ reason }) => {
  setupMenus();
  if (reason === 'install') chrome.tabs.create({ url: chrome.runtime.getURL('vault.html') });
});
chrome.runtime.onStartup.addListener(setupMenus);

function setupMenus() {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({ id: 'kh-fill', title: 'Autofill login', contexts: ['editable'] });
    chrome.contextMenus.create({ id: 'kh-generate', title: 'Fill a generated password', contexts: ['editable'] });
    chrome.contextMenus.create({ id: 'kh-open', title: 'Open Keyhaven vault', contexts: ['action'] });
  });
}

chrome.alarms.create('kh-tick', { periodInMinutes: 1 });
chrome.alarms.onAlarm.addListener(async (a) => {
  await vault.ready;
  if (a.name === 'kh-tick') {
    if (await vault.checkAutoLock()) return;
    const n = ((await chrome.storage.session.get('tickCount')).tickCount || 0) + 1;
    await chrome.storage.session.set({ tickCount: n });
    if (vault.account && n % 5 === 0) vault.sync().catch(() => {});
  } else if (a.name === 'kh-clip') {
    clearClipboard();
  }
});

// ---------- clipboard (offscreen document) ----------

async function ensureOffscreen() {
  if (await chrome.offscreen.hasDocument()) return;
  await chrome.offscreen
    .createDocument({ url: 'offscreen.html', reasons: ['CLIPBOARD'], justification: 'Copy secrets and clear them from the clipboard' })
    .catch((e) => {
      if (!/single offscreen/i.test(e.message)) throw e;
    });
}

let clipTimer;
async function copyText(text, sensitive) {
  await ensureOffscreen();
  await chrome.runtime.sendMessage({ target: 'offscreen', type: 'write', text });
  clearTimeout(clipTimer);
  await chrome.alarms.clear('kh-clip');
  const secs = vault.settings.clipboardClearSeconds;
  if (sensitive && secs) {
    clipTimer = setTimeout(clearClipboard, secs * 1000);
    // Backup in case the worker is suspended before the timer fires.
    chrome.alarms.create('kh-clip', { when: Date.now() + Math.max(30, secs) * 1000 });
  }
}

async function clearClipboard() {
  clearTimeout(clipTimer);
  await chrome.alarms.clear('kh-clip');
  try {
    await ensureOffscreen();
    await chrome.runtime.sendMessage({ target: 'offscreen', type: 'write', text: '' });
  } catch {
    /* ignore */
  }
}

// ---------- badge ----------

async function refreshBadge(tabId) {
  try {
    await vault.ready;
    const tabs = tabId ? [await chrome.tabs.get(tabId)] : await chrome.tabs.query({ active: true });
    for (const tab of tabs) {
      if (!tab?.id) continue;
      const n = vault.unlocked && tab.url ? vault.matchLogins(tab.url).length : 0;
      await chrome.action.setBadgeText({ tabId: tab.id, text: n ? String(n) : '' });
      await chrome.action.setTitle({
        tabId: tab.id,
        title: !vault.account ? 'Keyhaven — not signed in' : vault.unlocked ? `Keyhaven${n ? ` — ${n} login${n === 1 ? '' : 's'} for this site` : ''}` : 'Keyhaven — locked',
      });
    }
  } catch {
    /* tab gone */
  }
}
chrome.action.setBadgeBackgroundColor({ color: '#e9b252' }).catch(() => {});
chrome.action.setBadgeTextColor?.({ color: '#1b1405' }).catch(() => {});
chrome.tabs.onActivated.addListener(({ tabId }) => refreshBadge(tabId));
chrome.tabs.onUpdated.addListener((tabId, info) => info.status === 'complete' && refreshBadge(tabId));

// ---------- filling ----------

const loginSummary = (it) => ({ id: it.id, title: it.title, username: it.username, hasTotp: !!it.totp, host: displayHost(it.urls[0] || '') });

/** Fill an item into every frame of a tab whose URL matches it (or the top frame if forced). */
async function fillTab(tabId, item, force = false) {
  const results = await chrome.scripting.executeScript({ target: { tabId, allFrames: true }, func: () => location.href }).catch(() => []);
  let frames = results.filter((r) => itemMatchScore(item, r.result) > 0);
  let mismatch = false;
  if (!frames.length) {
    if (!force) return { filled: 0, mismatch: true };
    frames = results.filter((r) => r.frameId === 0);
    mismatch = true;
  }
  const totp = item.totp ? (await totpCode(item.totp).catch(() => null))?.code : null;
  let filled = 0;
  for (const f of frames) {
    const ok = await chrome.tabs
      .sendMessage(tabId, { type: 'bg:fill', origin: new URL(f.result).origin, username: item.username, password: item.password, totp }, { frameId: f.frameId })
      .catch(() => false);
    if (ok) filled++;
  }
  if (filled) {
    vault.markUsed(item.id);
    if (totp) copyText(totp, true).catch(() => {});
  }
  return { filled, mismatch, totpCopied: !!(filled && totp) };
}

async function openPopupOrVault() {
  try {
    await chrome.action.openPopup();
  } catch {
    chrome.tabs.create({ url: chrome.runtime.getURL('vault.html') });
  }
}

chrome.commands.onCommand.addListener(async (cmd, tab) => {
  if (cmd !== 'autofill') return;
  await vault.ready;
  if (!vault.unlocked) return openPopupOrVault();
  const t = tab || (await chrome.tabs.query({ active: true, currentWindow: true }))[0];
  if (t?.id) chrome.tabs.sendMessage(t.id, { type: 'bg:autofill' }).catch(() => {});
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  await vault.ready;
  if (info.menuItemId === 'kh-open') return chrome.tabs.create({ url: chrome.runtime.getURL('vault.html') });
  if (!tab?.id) return;
  if (!vault.unlocked && info.menuItemId === 'kh-fill') return openPopupOrVault();
  const target = { frameId: info.frameId || 0 };
  if (info.menuItemId === 'kh-fill') chrome.tabs.sendMessage(tab.id, { type: 'bg:autofill' }, target).catch(() => {});
  if (info.menuItemId === 'kh-generate') {
    const password = generatePassword();
    chrome.tabs.sendMessage(tab.id, { type: 'bg:fillGenerated', password }, target).catch(() => {});
  }
});

// ---------- save prompts ----------

const PENDING_TTL = 3 * 60 * 1000;

async function getPending(tabId) {
  const p = (await chrome.storage.session.get(`pending:${tabId}`))[`pending:${tabId}`];
  if (p && Date.now() - p.ts < PENDING_TTL) return p;
  return null;
}
const setPending = (tabId, p) => chrome.storage.session.set({ [`pending:${tabId}`]: p });
const dropPending = (tabId) => chrome.storage.session.remove(`pending:${tabId}`);
chrome.tabs.onRemoved.addListener((tabId) => {
  dropPending(tabId);
  chrome.storage.session.remove(`user:${tabId}`);
});

async function neverList() {
  return (await chrome.storage.local.get('neverSave')).neverSave || [];
}

async function onCaptured(sender, { username, password }) {
  const url = sender.url;
  const tabId = sender.tab.id;
  if (!/^https?:/.test(url) || !vault.settings.offerToSave) return;
  const host = new URL(url).hostname;
  if ((await neverList()).includes(host)) return;
  username = String(username || '').slice(0, 500);
  password = String(password || '').slice(0, 2000);
  const userKey = `user:${tabId}`;
  if (!password) {
    if (username) await chrome.storage.session.set({ [userKey]: { username, domain: baseDomain(host), ts: Date.now() } });
    return;
  }
  if (!username) {
    const u = (await chrome.storage.session.get(userKey))[userKey];
    if (u && u.domain === baseDomain(host) && Date.now() - u.ts < 10 * 60000) username = u.username;
  }
  if (vault.unlocked) {
    const same = vault.matchLogins(url).find((it) => it.password === password && (!username || it.username === username));
    if (same) {
      await dropPending(tabId);
      return;
    }
  }
  await setPending(tabId, { url: originFor(url), host, username, password, ts: Date.now() });
}

/** What the save banner should show for this tab (never includes the password). */
async function savePrompt(tabId) {
  const p = await getPending(tabId);
  if (!p) return null;
  if (!vault.account) return null;
  if (!vault.unlocked) return { kind: 'locked', host: p.host, username: p.username };
  const matches = vault.matchLogins(p.url);
  if (matches.some((it) => it.password === p.password && (!p.username || it.username === p.username))) {
    await dropPending(tabId);
    return null;
  }
  const existing = matches.find((it) => p.username && it.username === p.username) || (!p.username && matches.length === 1 ? matches[0] : null);
  setVerifiedDomains(vault.status().verifiedDomains);
  const verified = verifiedDomain(p.url);
  if (existing) return { kind: 'update', host: p.host, username: p.username || existing.username, id: existing.id, title: existing.title, verified };
  return { kind: 'save', host: p.host, username: p.username, verified };
}

async function resolveSave(tabId, action) {
  const p = await getPending(tabId);
  if (!p) return null;
  if (action === 'never') {
    const list = await neverList();
    if (!list.includes(p.host)) await chrome.storage.local.set({ neverSave: [...list, p.host] });
    return dropPending(tabId);
  }
  if (action === 'dismiss') return dropPending(tabId);
  vault.requireUnlocked();
  const prompt = await savePrompt(tabId);
  if (!prompt) return null;
  const item = await vault.saveCaptured({ url: p.url, username: p.username, password: p.password, updateId: prompt.kind === 'update' ? prompt.id : null });
  await dropPending(tabId);
  return { saved: true, title: item.title, updated: prompt.kind === 'update' };
}

// ---------- passkeys ----------

const domErr = (name, message) => ({ error: { name, message } });

/** Passkeys only for the top frame, on a secure origin, with a valid RP id for that origin. */
function passkeyContext(sender, rpIdOpt) {
  if (sender.frameId !== 0) return null;
  const origin = new URL(sender.url).origin;
  const rpId = String(rpIdOpt || new URL(origin).hostname).toLowerCase();
  return rpIdAllowed(rpId, origin) ? { origin, rpId } : null;
}

function validCreateOptions(o) {
  return o && typeof o.challenge === 'string' && o.rp && o.user && typeof o.user.id === 'string' && o.user.id.length > 0 &&
    supportsES256(o.pubKeyCredParams) && o.authenticatorSelection?.authenticatorAttachment !== 'cross-platform';
}

function passkeyCreatePrepare(sender, o) {
  const ctx = passkeyContext(sender, o?.rp?.id);
  if (!ctx || !validCreateOptions(o) || !vault.account) return { fallback: true };
  if (!vault.unlocked) return { locked: true, rpId: ctx.rpId };
  const exclude = (o.excludeCredentials || []).map((c) => c.id);
  return {
    rpId: ctx.rpId,
    userName: o.user.name || o.user.displayName || '',
    excluded: exclude.length > 0 && vault.passkeysFor(ctx.rpId, exclude).length > 0,
    replaces: vault.passkeysFor(ctx.rpId).some((x) => x.passkey.userHandle === o.user.id),
  };
}

async function passkeyCreate(sender, o) {
  const ctx = passkeyContext(sender, o?.rp?.id);
  if (!ctx || !validCreateOptions(o)) return domErr('NotAllowedError', 'This site cannot use Keyhaven passkeys');
  if (!vault.unlocked) return domErr('NotAllowedError', 'Keyhaven is locked');
  const exclude = (o.excludeCredentials || []).map((c) => c.id);
  if (exclude.length && vault.passkeysFor(ctx.rpId, exclude).length) return domErr('InvalidStateError', 'A passkey for this account already exists');
  const { passkey, response } = await makeCredential(o, ctx.origin);
  await vault.storePasskey(passkey, ctx.origin);
  return { result: response };
}

function passkeyGetPrepare(sender, o) {
  const ctx = passkeyContext(sender, o?.rpId);
  if (!ctx || typeof o?.challenge !== 'string' || !vault.account) return { fallback: true };
  if (!vault.unlocked) return { locked: true, rpId: ctx.rpId };
  const allow = (o.allowCredentials || []).map((c) => c.id);
  const found = vault.passkeysFor(ctx.rpId, allow);
  if (!found.length) return { fallback: true };
  return {
    rpId: ctx.rpId,
    candidates: found.map(({ item, passkey }) => ({ credentialId: passkey.credentialId, userName: passkey.userName || item.username, title: item.title })),
  };
}

async function passkeyGet(sender, o, credentialId) {
  const ctx = passkeyContext(sender, o?.rpId);
  if (!ctx || !vault.unlocked) return domErr('NotAllowedError', 'Keyhaven is locked');
  const allow = (o.allowCredentials || []).map((c) => c.id);
  const m = vault.passkeysFor(ctx.rpId, allow).find((x) => x.passkey.credentialId === credentialId);
  if (!m) return domErr('NotAllowedError', 'Passkey not found');
  const result = await getAssertion(m.passkey, o, ctx.origin);
  vault.touchPasskey(m.item.id, credentialId);
  return { result };
}

// ---------- messaging ----------

async function handleTrusted(msg, sender) {
  switch (msg.type) {
    case 'kh:rpc':
      return dispatch(vault, msg.method, msg.params || {});
    case 'kh:copy':
      return copyText(String(msg.text || ''), !!msg.sensitive);
    case 'kh:fill': {
      const item = vault.getItem(msg.id);
      const res = await fillTab(msg.tabId, item, !!msg.force);
      return res;
    }
    case 'kh:savePrompt':
      return savePrompt(msg.tabId);
    case 'kh:resolveSave':
      return resolveSave(msg.tabId, msg.action);
    case 'kh:fillGenerated':
      return chrome.tabs.sendMessage(msg.tabId, { type: 'bg:fillGenerated', password: msg.password }, { frameId: 0 }).catch(() => false);
    case 'kh:openVault':
      return chrome.tabs.create({ url: chrome.runtime.getURL(`vault.html${msg.item ? `#item=${encodeURIComponent(msg.item)}` : ''}`) });
    default:
      throw new Error('Unknown message');
  }
}

async function handleContent(msg, sender) {
  const url = sender.url || '';
  const tabId = sender.tab?.id;
  if (tabId == null || !/^https?:/.test(url)) return null;
  switch (msg.type) {
    case 'cs:query': {
      const s = vault.status();
      if (!s.loggedIn) return { state: 'signedOut', inline: s.settings.showInlineMenu };
      if (!s.unlocked) return { state: 'locked', inline: s.settings.showInlineMenu };
      return { state: 'unlocked', inline: s.settings.showInlineMenu, logins: vault.matchLogins(url).slice(0, 12).map(loginSummary) };
    }
    case 'cs:fill':
    case 'cs:fillBest': {
      if (!vault.unlocked) return null;
      const item = msg.type === 'cs:fill' ? vault.getItem(msg.id) : vault.matchLogins(url)[0];
      if (!item || itemMatchScore(item, url) === 0) return null; // only for the frame's real origin
      await vault.touch();
      vault.markUsed(item.id);
      const totp = item.totp ? (await totpCode(item.totp).catch(() => null))?.code : null;
      if (totp && msg.copyTotp !== false) copyText(totp, true).catch(() => {});
      return { username: item.username, password: item.password, totp };
    }
    case 'cs:totp': {
      if (!vault.unlocked) return null;
      const item = vault.getItem(msg.id);
      if (!item?.totp || itemMatchScore(item, url) === 0) return null;
      return (await totpCode(item.totp)).code;
    }
    case 'cs:passkeyCreatePrepare':
      return passkeyCreatePrepare(sender, msg.options);
    case 'cs:passkeyCreate':
      return passkeyCreate(sender, msg.options);
    case 'cs:passkeyGetPrepare':
      return passkeyGetPrepare(sender, msg.options);
    case 'cs:passkeyGet':
      return passkeyGet(sender, msg.options, msg.credentialId);
    case 'cs:cards': {
      if (!vault.account) return { state: 'signedOut' };
      if (!vault.unlocked) return { state: 'locked' };
      const cards = vault.listItems().filter((i) => i.type === 'card' && !i.deletedAt && i.card.number);
      return { state: 'unlocked', cards: cards.map((i) => ({ id: i.id, title: i.title, last4: i.card.number.slice(-4), holder: i.card.cardholder })) };
    }
    case 'cs:fillCard': {
      if (!vault.unlocked) return null;
      const it = vault.getItem(msg.id);
      if (it.type !== 'card') return null;
      await vault.touch();
      return { ...it.card };
    }
    case 'cs:generate':
      return generatePassword();
    case 'cs:captured':
      return onCaptured(sender, msg);
    case 'cs:checkSave':
      return savePrompt(tabId);
    case 'cs:saveDecision':
      return resolveSave(tabId, msg.action);
    case 'cs:openPopup':
      return openPopupOrVault();
    default:
      return null;
  }
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg?.target === 'offscreen' || sender.id !== chrome.runtime.id) return false;
  const trusted = typeof sender.url === 'string' && sender.url.startsWith(EXT_ORIGIN);
  const run = async () => {
    await vault.ready;
    if (trusted && msg.type?.startsWith('kh:')) return handleTrusted(msg, sender);
    if (!trusted && msg.type?.startsWith('cs:')) return handleContent(msg, sender);
    throw new Error('Not allowed');
  };
  run().then(
    (result) => sendResponse({ ok: true, result }),
    (e) => sendResponse({ ok: false, error: e?.message || String(e) }),
  );
  return true;
});
