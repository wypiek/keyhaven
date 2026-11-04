// VaultClient: account, unlock, sync and item operations against a keyhaven-server.
// Storage is injected so the same code runs in the extension service worker
// (chrome.storage.local + chrome.storage.session) and in the web vault (localStorage + memory).

import { Api, ApiError, normalizeServerUrl } from './api.js';
import * as kc from './crypto.js';
import { estimateStrength } from './strength.js';
import { isValidTotp } from './totp.js';
import { itemMatchScore, originFor } from './urlmatch.js';
import { toCsv } from './importers.js';

export const ITEM_TYPES = ['login', 'note', 'card', 'identity'];

export const DEFAULT_SETTINGS = {
  autoLockMinutes: 15,
  clipboardClearSeconds: 30,
  showInlineMenu: true,
  offerToSave: true,
  showIcons: true,
};

export function normalizeItem(raw = {}) {
  const s = (v) => (v == null ? '' : String(v));
  const type = ITEM_TYPES.includes(raw.type) ? raw.type : 'login';
  const card = raw.card || {};
  const id = raw.identity || {};
  return {
    id: s(raw.id),
    type,
    title: s(raw.title).trim(),
    favorite: !!raw.favorite,
    tags: [...new Set((raw.tags || []).map((t) => s(t).trim()).filter(Boolean))],
    notes: s(raw.notes),
    username: s(raw.username),
    password: s(raw.password),
    urls: (raw.urls || []).map((u) => s(u).trim()).filter(Boolean),
    totp: s(raw.totp).trim(),
    card: {
      cardholder: s(card.cardholder), number: s(card.number).replace(/\s+/g, ''), expMonth: s(card.expMonth),
      expYear: s(card.expYear), cvv: s(card.cvv), pin: s(card.pin),
    },
    identity: {
      firstName: s(id.firstName), lastName: s(id.lastName), email: s(id.email), phone: s(id.phone),
      company: s(id.company), address1: s(id.address1), address2: s(id.address2), city: s(id.city),
      state: s(id.state), postalCode: s(id.postalCode), country: s(id.country),
    },
    fields: (raw.fields || [])
      .map((f) => ({ label: s(f.label), value: s(f.value), hidden: !!f.hidden }))
      .filter((f) => f.label || f.value),
    passwordHistory: (raw.passwordHistory || []).slice(0, 20),
    passkeys: (raw.passkeys || [])
      .filter((k) => k && k.credentialId && k.privateKey && k.rpId)
      .map((k) => ({
        credentialId: s(k.credentialId), rpId: s(k.rpId).toLowerCase(), rpName: s(k.rpName), userHandle: s(k.userHandle),
        userName: s(k.userName), userDisplayName: s(k.userDisplayName), privateKey: s(k.privateKey),
        algorithm: k.algorithm || -7, createdAt: k.createdAt || 0, lastUsedAt: k.lastUsedAt || 0,
      })),
    createdAt: raw.createdAt || 0,
    updatedAt: raw.updatedAt || 0,
    passwordChangedAt: raw.passwordChangedAt || 0,
    lastUsedAt: raw.lastUsedAt || 0,
    deletedAt: raw.deletedAt || null,
  };
}

export class VaultClient {
  /**
   * @param {{storage: Store, session: Store, deviceName: string, onChange?: (evt:string)=>void}} opts
   * Store = { get(key): Promise<any>, set(key, value): Promise<void>, remove(key): Promise<void> }
   */
  constructor({ storage, session, deviceName, onChange }) {
    this.storage = storage;
    this.session = session;
    this.deviceName = deviceName;
    this.onChange = onChange || (() => {});
    this.account = null;
    this.cache = {};
    this.items = new Map();
    this.key = null;
    this.settings = { ...DEFAULT_SETTINGS };
    this.syncing = null;
    this.lastSyncError = '';
    this.ready = this.init();
  }

  async init() {
    this.account = (await this.storage.get('account')) || null;
    this.cache = (await this.storage.get('cache')) || {};
    this.settings = { ...DEFAULT_SETTINGS, ...((await this.storage.get('settings')) || {}) };
    const raw = await this.session.get('vaultKey');
    if (this.account && raw) {
      try {
        await this.setKey(kc.b64decode(raw), false);
      } catch {
        await this.session.remove('vaultKey');
      }
    }
  }

  // ---------- state ----------

  get unlocked() {
    return !!this.key;
  }

  status() {
    return {
      loggedIn: !!this.account,
      unlocked: this.unlocked,
      email: this.account?.email || '',
      serverUrl: this.account?.serverUrl || '',
      itemCount: [...this.items.values()].filter((i) => !i.deletedAt).length,
      lastSync: this.account?.lastSync || 0,
      syncError: this.lastSyncError,
      settings: this.settings,
      role: this.account?.instance?.role || this.account?.role || 'user',
      branding: this.account?.instance?.branding || null,
      notice: this.account?.instance?.notice || '',
      iconsEnabled: this.account?.instance?.iconsEnabled !== false,
      verifiedDomains: this.account?.instance?.verifiedDomains ?? null,
    };
  }

  /** Pull branding, notice, features, verified domains and this user's role from the server. */
  async refreshInstance() {
    if (!this.account) return;
    try {
      const inst = await this.api().instance();
      const changed = JSON.stringify(inst) !== JSON.stringify(this.account.instance || null);
      this.account.instance = inst;
      await this.saveAccount();
      if (changed) this.onChange('instance');
    } catch (e) {
      if (e instanceof ApiError && e.status === 401) await this.handleAuthError(e);
    }
  }

  /** Admin API passthrough, limited to /api/admin/. The server re-checks the role on every call. */
  async admin(method, path, body) {
    this.requireUnlocked();
    if (typeof path !== 'string' || !path.startsWith('/api/admin/') || path.includes('..')) throw new Error('Invalid admin path');
    if (!['GET', 'PUT', 'POST', 'DELETE'].includes(method)) throw new Error('Invalid method');
    await this.touch();
    const res = await this.api().request(method, path, method === 'GET' || method === 'DELETE' ? undefined : body || {}).catch((e) => this.handleAuthError(e));
    if (method !== 'GET') await this.refreshInstance();
    return res;
  }

  api() {
    if (!this.account) throw new Error('Not signed in');
    return new Api(this.account.serverUrl, this.account.token);
  }

  requireUnlocked() {
    if (!this.key) throw new Error('Vault is locked');
  }

  async touch() {
    await this.session.set('lastActivity', Date.now());
  }

  async checkAutoLock() {
    if (!this.unlocked || !this.settings.autoLockMinutes) return false;
    const last = (await this.session.get('lastActivity')) || Date.now();
    if (Date.now() - last > this.settings.autoLockMinutes * 60000) {
      await this.lock();
      return true;
    }
    return false;
  }

  async setKey(raw, persist = true) {
    this.key = await kc.importAesKey(raw);
    if (persist) await this.session.set('vaultKey', kc.b64encode(raw));
    await this.touch();
    await this.decryptAll();
  }

  async decryptAll() {
    const items = new Map();
    for (const [id, entry] of Object.entries(this.cache)) {
      try {
        items.set(id, normalizeItem(await kc.decryptItem(this.key, id, entry.data)));
      } catch (e) {
        console.warn('Keyhaven: could not decrypt item', id, e);
      }
    }
    this.items = items;
  }

  async saveAccount() {
    await this.storage.set('account', this.account);
  }

  async saveCache() {
    await this.storage.set('cache', this.cache);
  }

  // ---------- account ----------

  static async serverInfo(url, allowInsecure) {
    const base = normalizeServerUrl(url, allowInsecure);
    const cfg = await new Api(base).config();
    if (cfg.name !== 'Keyhaven') throw new Error('That server is not a Keyhaven server');
    return { ...cfg, serverUrl: base };
  }

  async register({ serverUrl, email, password, inviteCode, allowInsecure }) {
    const base = normalizeServerUrl(serverUrl, allowInsecure);
    if ((password || '').length < 10) throw new Error('Master password must be at least 10 characters');
    const kdf = kc.newKdfParams();
    const master = await kc.deriveMasterKey(password, kdf);
    const { authKey, kek } = await kc.deriveSubkeys(master);
    master.fill(0);
    const vaultKey = kc.randomBytes(32);
    const wrappedKey = await kc.wrapKey(kek, vaultKey);
    const res = await new Api(base).register({
      email, authKey, kdf, wrappedKey, inviteCode: inviteCode || null, device: this.deviceName,
    });
    this.account = {
      serverUrl: base, email: res.email, userId: res.userId, token: res.token, kdf, wrappedKey, revision: 0, lastSync: 0,
    };
    this.cache = {};
    await this.saveAccount();
    await this.saveCache();
    await this.setKey(vaultKey);
    vaultKey.fill(0);
    await this.sync().catch(() => {});
    this.onChange('state');
    return this.status();
  }

  async login({ serverUrl, email, password, allowInsecure }) {
    const base = normalizeServerUrl(serverUrl, allowInsecure);
    const api = new Api(base);
    const { kdf } = await api.prelogin(email);
    const master = await kc.deriveMasterKey(password, kdf);
    const { authKey, kek } = await kc.deriveSubkeys(master);
    master.fill(0);
    const res = await api.login({ email, authKey, device: this.deviceName });
    const raw = await kc.unwrapKey(kek, res.wrappedKey);
    const sameAccount = this.account && this.account.userId === res.userId && this.account.serverUrl === base;
    this.account = {
      serverUrl: base, email: res.email, userId: res.userId, token: res.token, kdf: res.kdf,
      wrappedKey: res.wrappedKey, revision: sameAccount ? this.account.revision : 0, lastSync: 0,
    };
    if (!sameAccount) this.cache = {};
    await this.saveAccount();
    await this.saveCache();
    await this.setKey(raw);
    raw.fill(0);
    await this.sync();
    this.onChange('state');
    return this.status();
  }

  /** Offline unlock using the locally cached wrapped key. */
  async unlock(password) {
    if (!this.account) throw new Error('Not signed in');
    if (!password) throw new Error('Enter your master password');
    const master = await kc.deriveMasterKey(password, this.account.kdf);
    const { kek } = await kc.deriveSubkeys(master);
    master.fill(0);
    const raw = await kc.unwrapKey(kek, this.account.wrappedKey);
    await this.setKey(raw);
    raw.fill(0);
    this.onChange('state');
    this.sync().catch(() => {});
    return this.status();
  }

  async lock() {
    this.key = null;
    this.items = new Map();
    this.iconCache = null;
    await this.session.remove('vaultKey');
    await this.session.remove('iconCache');
    this.onChange('state');
  }

  async logout() {
    if (this.account) {
      try {
        await this.api().logout();
      } catch {
        /* offline or already revoked */
      }
    }
    this.key = null;
    this.items = new Map();
    this.account = null;
    this.cache = {};
    await this.session.remove('vaultKey');
    await this.storage.remove('account');
    await this.storage.remove('cache');
    await this.session.remove('iconCache');
    this.iconCache = null;
    this.onChange('state');
  }

  async handleAuthError(e) {
    if (e instanceof ApiError && e.status === 401) {
      await this.logout();
      throw new Error('Your session expired or was revoked. Sign in again.');
    }
    throw e;
  }

  /** Check a master password locally; returns the server auth key and raw vault key. */
  async verifyPassword(password) {
    if (!password) throw new Error('Enter your master password');
    const master = await kc.deriveMasterKey(password, this.account.kdf);
    const { authKey, kek } = await kc.deriveSubkeys(master);
    master.fill(0);
    const raw = await kc.unwrapKey(kek, this.account.wrappedKey);
    return { authKey, raw };
  }

  async changePassword(current, next) {
    this.requireUnlocked();
    if ((next || '').length < 10) throw new Error('New master password must be at least 10 characters');
    if (next === current) throw new Error('The new master password is the same as the current one');
    const { authKey, raw } = await this.verifyPassword(current);
    const newKdf = kc.newKdfParams();
    const nm = await kc.deriveMasterKey(next, newKdf);
    const { authKey: newAuthKey, kek } = await kc.deriveSubkeys(nm);
    nm.fill(0);
    const newWrappedKey = await kc.wrapKey(kek, raw);
    raw.fill(0);
    await this.api().changePassword({ authKey, newAuthKey, newKdf, newWrappedKey }).catch((e) => this.handleAuthError(e));
    this.account.kdf = newKdf;
    this.account.wrappedKey = newWrappedKey;
    await this.saveAccount();
    return true;
  }

  async deleteAccount(password) {
    const { authKey, raw } = await this.verifyPassword(password);
    raw.fill(0);
    await this.api().deleteAccount(authKey);
    this.account.token = null;
    await this.logout();
  }

  async sessions() {
    return (await this.api().sessions().catch((e) => this.handleAuthError(e))).sessions;
  }

  async revokeSession(id) {
    await this.api().revokeSession(id).catch((e) => this.handleAuthError(e));
  }

  async updateSettings(patch) {
    this.settings = { ...this.settings, ...patch };
    this.settings.autoLockMinutes = Math.max(0, Math.min(1440, Number(this.settings.autoLockMinutes) || 0));
    this.settings.clipboardClearSeconds = Math.max(0, Math.min(600, Number(this.settings.clipboardClearSeconds) || 0));
    await this.storage.set('settings', this.settings);
    this.onChange('settings');
    return this.settings;
  }

  // ---------- sync ----------

  sync() {
    if (!this.syncing) this.syncing = this._sync().finally(() => (this.syncing = null));
    return this.syncing;
  }

  async _sync() {
    if (!this.account) return;
    const api = this.api();
    try {
      const acct = await api.account();
      if (acct.wrappedKey !== this.account.wrappedKey || JSON.stringify(acct.kdf) !== JSON.stringify(this.account.kdf)) {
        // Master password changed on another device: future offline unlocks need the new one.
        kc.validateKdf(acct.kdf);
        this.account.kdf = acct.kdf;
        this.account.wrappedKey = acct.wrappedKey;
      }
      this.refreshInstance();
      const res = await api.sync(this.account.revision || 0);
      if (res.full) this.cache = {};
      let changed = res.full;
      for (const row of res.items) {
        if (row.deleted || !row.data) {
          if (this.cache[row.id]) changed = true;
          delete this.cache[row.id];
          this.items.delete(row.id);
        } else {
          this.cache[row.id] = { data: row.data, revision: row.revision };
          changed = true;
          if (this.key) {
            try {
              this.items.set(row.id, normalizeItem(await kc.decryptItem(this.key, row.id, row.data)));
            } catch (e) {
              console.warn('Keyhaven: could not decrypt item', row.id, e);
            }
          }
        }
      }
      if (res.full && this.key) await this.decryptAll();
      this.account.revision = res.revision;
      this.account.lastSync = Date.now();
      this.lastSyncError = '';
      await this.saveAccount();
      if (changed) {
        await this.saveCache();
        this.onChange('items');
      }
    } catch (e) {
      this.lastSyncError = e.message;
      if (e instanceof ApiError && e.status === 401) await this.handleAuthError(e);
      throw e;
    }
  }

  // ---------- items ----------

  listItems() {
    this.requireUnlocked();
    return [...this.items.values()];
  }

  getItem(id) {
    this.requireUnlocked();
    const it = this.items.get(id);
    if (!it) throw new Error('Item not found');
    return it;
  }

  async persist(items) {
    const enc = [];
    for (const it of items) enc.push({ id: it.id, data: await kc.encryptItem(this.key, it) });
    const api = this.api();
    let res;
    try {
      res = enc.length === 1 ? await api.putItem(enc[0].id, enc[0].data) : await api.putItems(enc);
    } catch (e) {
      if (e instanceof ApiError && e.status === 0) throw new Error("Can't reach your server — changes need a connection");
      await this.handleAuthError(e);
    }
    for (const [i, e] of enc.entries()) {
      this.cache[e.id] = { data: e.data, revision: res.revision };
      this.items.set(e.id, items[i]);
    }
    await this.saveCache();
    // Pull anything else that changed meanwhile (keeps revision cursor correct).
    await this.sync().catch(() => {});
    this.onChange('items');
  }

  validate(item) {
    if (!item.title) throw new Error('Give the item a title');
    if (item.totp && !isValidTotp(item.totp)) throw new Error('The one-time password secret is not valid');
  }

  async saveItem(input) {
    this.requireUnlocked();
    await this.touch();
    const now = Date.now();
    const item = normalizeItem(input);
    if (!item.title && item.type === 'login' && item.urls[0]) {
      try {
        item.title = new URL(/:\/\//.test(item.urls[0]) ? item.urls[0] : `https://${item.urls[0]}`).hostname.replace(/^www\./, '');
      } catch { /* ignore */ }
    }
    this.validate(item);
    const existing = item.id && this.items.get(item.id);
    if (existing) {
      item.createdAt = existing.createdAt;
      item.passwordHistory = existing.passwordHistory || [];
      item.lastUsedAt = input.lastUsedAt ?? existing.lastUsedAt;
      item.deletedAt = existing.deletedAt;
      if (existing.password && existing.password !== item.password) {
        item.passwordHistory = [{ password: existing.password, changedAt: now }, ...item.passwordHistory].slice(0, 20);
        item.passwordChangedAt = now;
      } else {
        item.passwordChangedAt = existing.passwordChangedAt || existing.createdAt;
      }
    } else {
      item.id = kc.uuid();
      item.createdAt = now;
      item.passwordChangedAt = now;
      item.deletedAt = null;
    }
    item.updatedAt = now;
    await this.persist([item]);
    return item;
  }

  async patchItem(id, patch) {
    const it = { ...this.getItem(id), ...patch };
    await this.persist([it]);
    return it;
  }

  async markUsed(id) {
    try {
      await this.patchItem(id, { lastUsedAt: Date.now() });
    } catch {
      /* best effort */
    }
  }

  trashItem(id) {
    return this.patchItem(id, { deletedAt: Date.now(), updatedAt: Date.now() });
  }

  restoreItem(id) {
    return this.patchItem(id, { deletedAt: null, updatedAt: Date.now() });
  }

  async deleteItem(id) {
    this.requireUnlocked();
    await this.api().deleteItem(id).catch((e) => this.handleAuthError(e));
    delete this.cache[id];
    this.items.delete(id);
    await this.saveCache();
    await this.sync().catch(() => {});
    this.onChange('items');
  }

  async emptyTrash() {
    for (const it of this.listItems().filter((i) => i.deletedAt)) await this.deleteItem(it.id);
  }

  async importItems(list) {
    this.requireUnlocked();
    const now = Date.now();
    const items = list.map((raw) => {
      const it = normalizeItem(raw);
      it.id = kc.uuid();
      it.createdAt = it.updatedAt = it.passwordChangedAt = now;
      it.deletedAt = null;
      if (!it.title) it.title = 'Imported item';
      if (it.totp && !isValidTotp(it.totp)) {
        it.notes = `${it.notes}\n\nOriginal one-time password value: ${it.totp}`.trim();
        it.totp = '';
      }
      return it;
    });
    for (let i = 0; i < items.length; i += 500) await this.persist(items.slice(i, i + 500));
    return items.length;
  }

  async exportItems(password, format) {
    this.requireUnlocked();
    (await this.verifyPassword(password)).raw.fill(0);
    const items = this.listItems().filter((i) => !i.deletedAt);
    if (format === 'csv') {
      return toCsv([
        ['type', 'title', 'url', 'username', 'password', 'totp', 'notes', 'tags', 'favorite'],
        ...items.map((i) => [i.type, i.title, i.urls.join(','), i.username, i.password, i.totp, i.notes, i.tags.join(';'), i.favorite ? '1' : '']),
      ]);
    }
    return JSON.stringify({ format: 'keyhaven-export', version: 1, exportedAt: new Date().toISOString(), items }, null, 2);
  }

  /** Logins matching a page URL, best first. */
  matchLogins(pageUrl) {
    if (!this.key) return [];
    return [...this.items.values()]
      .map((it) => ({ it, score: itemMatchScore(it, pageUrl) }))
      .filter((m) => m.score > 0)
      .sort((a, b) => b.score - a.score || (b.it.lastUsedAt || 0) - (a.it.lastUsedAt || 0) || a.it.title.localeCompare(b.it.title))
      .map((m) => m.it);
  }

  /** Save or update a login captured from a form submission. Returns the saved item. */
  async saveCaptured({ url, username, password, updateId }) {
    if (updateId) {
      const it = this.getItem(updateId);
      return this.saveItem({ ...it, password, username: username || it.username });
    }
    return this.saveItem({ type: 'login', title: '', username, password, urls: [originFor(url)] });
  }

  // ---------- website icons ----------

  /** Favicons for hosts, fetched via this account's server (never a third party). host → data URL | null. */
  async icons(hosts) {
    // Cached in session (memory) storage only, so the list of sites never sits on disk.
    if (!this.account || !this.key || !this.settings.showIcons || this.account.instance?.iconsEnabled === false) return {};
    if (!this.iconCache) this.iconCache = (await this.session.get('iconCache')) || {};
    const now = Date.now();
    const out = {};
    const todo = [];
    for (const h of new Set(hosts.map((x) => String(x).toLowerCase().replace(/^www\./, '')))) {
      if (!/^[a-z0-9.-]+\.[a-z]{2,}$/.test(h)) continue;
      const c = this.iconCache[h];
      if (c && now - c.ts < (c.data ? 7 : 1) * 86400000) out[h] = c.data;
      else todo.push(h);
    }
    const { serverUrl, token } = this.account;
    this.iconInflight ||= new Map();
    const fetchOne = (h) => {
      if (!this.iconInflight.has(h)) this.iconInflight.set(h, fetchRaw(h).finally(() => this.iconInflight.delete(h)));
      return this.iconInflight.get(h).then(() => {
        if (this.iconCache && h in this.iconCache) out[h] = this.iconCache[h].data;
      });
    };
    const fetchRaw = async (h) => {
      try {
        const r = await fetch(`${serverUrl}/api/icon?host=${encodeURIComponent(h)}`, {
          headers: { Authorization: `Bearer ${token}` }, credentials: 'omit', redirect: 'error',
        });
        let data = null;
        if (r.ok) {
          const buf = new Uint8Array(await r.arrayBuffer());
          const mime = (r.headers.get('content-type') || '').split(';')[0];
          if (buf.length && buf.length <= 100 * 1024 && /^image\//.test(mime)) data = `data:${mime};base64,${kc.b64encode(buf)}`;
        } else if (r.status !== 404 && r.status !== 400) {
          return; // transient (offline, rate limited): don't cache
        }
        if (this.iconCache) this.iconCache[h] = { data, ts: now };
      } catch {
        /* offline */
      }
    };
    for (let i = 0; i < Math.min(todo.length, 60); i += 6) await Promise.all(todo.slice(i, i + 6).map(fetchOne));
    if (todo.length) {
      const keys = Object.keys(this.iconCache);
      if (keys.length > 400) keys.sort((a, b) => this.iconCache[a].ts - this.iconCache[b].ts).slice(0, keys.length - 400).forEach((k) => delete this.iconCache[k]);
      await this.session.set('iconCache', this.iconCache);
    }
    return out;
  }

  // ---------- passkeys ----------

  /** All passkeys for an RP id, with the item they live in. */
  passkeysFor(rpId, allowIds = []) {
    if (!this.key) return [];
    const out = [];
    for (const it of this.items.values()) {
      if (it.deletedAt) continue;
      for (const pk of it.passkeys) {
        if (pk.rpId !== rpId) continue;
        if (allowIds.length && !allowIds.includes(pk.credentialId)) continue;
        out.push({ item: it, passkey: pk });
      }
    }
    return out.sort((a, b) => (b.passkey.lastUsedAt || 0) - (a.passkey.lastUsedAt || 0));
  }

  /** Store a new passkey: attach to the matching login (same site + username) or create one. */
  async storePasskey(passkey, origin) {
    this.requireUnlocked();
    const logins = this.matchLogins(origin);
    const target =
      logins.find((it) => it.passkeys.some((k) => k.rpId === passkey.rpId && k.userHandle === passkey.userHandle)) ||
      logins.find((it) => passkey.userName && it.username === passkey.userName);
    if (target) {
      const passkeys = target.passkeys.filter((k) => !(k.rpId === passkey.rpId && k.userHandle === passkey.userHandle));
      return this.saveItem({ ...target, passkeys: [...passkeys, passkey] });
    }
    return this.saveItem({
      type: 'login', title: passkey.rpName || passkey.rpId, username: passkey.userName, password: '',
      urls: [originFor(origin)], passkeys: [passkey],
    });
  }

  async touchPasskey(itemId, credentialId) {
    try {
      const it = this.getItem(itemId);
      const now = Date.now();
      await this.patchItem(itemId, {
        lastUsedAt: now,
        passkeys: it.passkeys.map((k) => (k.credentialId === credentialId ? { ...k, lastUsedAt: now } : k)),
      });
    } catch {
      /* best effort */
    }
  }

  health() {
    this.requireUnlocked();
    const logins = this.listItems().filter((i) => !i.deletedAt && i.type === 'login' && i.password);
    const byPw = new Map();
    for (const it of logins) byPw.set(it.password, [...(byPw.get(it.password) || []), it.id]);
    const reused = [...byPw.values()].filter((ids) => ids.length > 1);
    const reusedSet = new Set(reused.flat());
    const weak = logins.filter((i) => estimateStrength(i.password).score < 3).map((i) => i.id);
    const yearAgo = Date.now() - 365 * 86400000;
    const old = logins.filter((i) => (i.passwordChangedAt || i.createdAt) < yearAgo).map((i) => i.id);
    const insecure = logins.filter((i) => i.urls.some((u) => /^http:\/\//i.test(u) && !/^http:\/\/(localhost|127\.)/i.test(u))).map((i) => i.id);
    const noTotp = logins.filter((i) => !i.totp).length;
    const problems = new Set([...weak, ...reusedSet, ...old, ...insecure]);
    const score = logins.length ? Math.round(100 * (1 - problems.size / logins.length)) : 100;
    return { score, total: logins.length, weak, reused, old, insecure, noTotp };
  }
}
