// Keyhaven vault app — shared by the web vault (served by keyhaven-server) and the
// extension's full-page vault. `backend` abstracts where the VaultClient lives.

import { h, icon, logo, mark, clear, passwordSpan, avatar, timeAgo, formatDate, cardBrand, itemSubtitle, setIconLoader, verifiedBadge, applyBranding, brandMark, inkFor } from './dom.js';
import { itemVerified, setVerifiedDomains, DEFAULT_DOMAINS } from '../shared/verified.js';
import { generatePassword, DEFAULT_GENERATOR, generatorEntropy } from '../shared/generator.js';
import { estimateStrength, crackTime } from '../shared/strength.js';
import { totpCode, isValidTotp } from '../shared/totp.js';
import { displayHost, parseLoose } from '../shared/urlmatch.js';

const TYPE_META = {
  login: { label: 'Login', plural: 'Logins', icon: 'key' },
  note: { label: 'Secure note', plural: 'Secure notes', icon: 'note' },
  card: { label: 'Card', plural: 'Cards', icon: 'card' },
  identity: { label: 'Identity', plural: 'Identities', icon: 'user' },
};

const GEN_KEY = 'keyhaven.generator';
const loadGen = () => {
  try {
    return { ...DEFAULT_GENERATOR, ...JSON.parse(localStorage.getItem(GEN_KEY) || '{}') };
  } catch {
    return { ...DEFAULT_GENERATOR };
  }
};
const saveGen = (o) => localStorage.setItem(GEN_KEY, JSON.stringify(o));

export function mountApp(root, backend) {
  const S = {
    status: null,
    items: [],
    view: 'all',
    query: '',
    sort: localStorage.getItem('keyhaven.sort') || 'name',
    selected: null,
    mode: 'view', // view | edit | new
    draft: null,
    dirty: false,
    wt: 'weak',
    authMode: 'login',
  };
  let timers = [];
  let shell = null;
  const toastsEl = h('div.toasts');
  document.body.append(toastsEl);

  // ---------- helpers ----------

  const call = (m, p) => backend.call(m, p);

  function toast(msg, kind = 'ok') {
    const t = h(`div.toast${kind === 'err' ? '.err' : ''}`, icon(kind === 'err' ? 'alert' : 'check', 16), msg);
    toastsEl.append(t);
    setTimeout(() => t.remove(), kind === 'err' ? 4200 : 2400);
  }

  const fail = (e) => toast(e?.message || String(e), 'err');

  async function copy(text, what = 'Copied', sensitive = true) {
    if (!text) return;
    try {
      await backend.copy(text, sensitive);
      const secs = S.status?.settings?.clipboardClearSeconds;
      toast(sensitive && secs ? `${what} — clears in ${secs}s` : what);
    } catch (e) {
      fail(e);
    }
  }

  function busy(btn, on, label) {
    if (!btn) return;
    if (on) {
      btn.dataset.label = btn.textContent;
      btn.disabled = true;
      clear(btn).append(h('span.spinner'), label || 'Working…');
    } else {
      btn.disabled = false;
      btn.textContent = btn.dataset.label || btn.textContent;
    }
  }

  function modal(build) {
    return new Promise((resolve) => {
      const back = h('div.modal-back');
      const close = (v) => {
        back.remove();
        document.removeEventListener('keydown', onKey, true);
        resolve(v);
      };
      const onKey = (e) => {
        if (e.key === 'Escape') {
          e.stopPropagation();
          close(null);
        }
      };
      document.addEventListener('keydown', onKey, true);
      back.addEventListener('mousedown', (e) => e.target === back && close(null));
      back.append(h('div.modal', build(close)));
      document.body.append(back);
      back.querySelector('input, button.primary, button.danger')?.focus();
    });
  }

  const confirmBox = ({ title, body, ok = 'Confirm', danger = false }) =>
    modal((close) => [
      h('h3', title),
      h('p', body),
      h('div.foot',
        h('button.btn', { on: { click: () => close(false) } }, 'Cancel'),
        h(`button.btn.${danger ? 'danger' : 'primary'}`, { on: { click: () => close(true) } }, ok)),
    ]);

  const askPassword = ({ title, body, ok = 'Continue' }) =>
    modal((close) => {
      const inp = h('input.input', { type: 'password', placeholder: 'Master password', autocomplete: 'current-password' });
      const submit = () => inp.value && close(inp.value);
      inp.addEventListener('keydown', (e) => e.key === 'Enter' && submit());
      return [
        h('h3', title),
        h('p', body),
        inp,
        h('div.foot', h('button.btn', { on: { click: () => close(null) } }, 'Cancel'), h('button.btn.primary', { on: { click: submit } }, ok)),
      ];
    });

  function passwordInput(attrs = {}, { generate = false, onInput } = {}) {
    const inp = h('input.input.mono', { type: 'password', spellcheck: 'false', autocomplete: 'off', ...attrs });
    const eye = h('button.icon-btn.sm', { type: 'button', title: 'Show / hide', tabindex: '-1' }, icon('eye', 16));
    eye.addEventListener('click', () => {
      const show = inp.type === 'password';
      inp.type = show ? 'text' : 'password';
      clear(eye).append(icon(show ? 'eyeOff' : 'eye', 16));
    });
    const adorn = h('div.adorn', eye);
    if (generate) {
      const g = h('button.icon-btn.sm', { type: 'button', title: 'Generate password', tabindex: '-1' }, icon('wand', 16));
      g.addEventListener('click', () =>
        openGeneratorPopover(g, (pw) => {
          inp.value = pw;
          inp.type = 'text';
          inp.dispatchEvent(new Event('input', { bubbles: true }));
        }),
      );
      adorn.append(g);
    }
    if (onInput) inp.addEventListener('input', () => onInput(inp.value));
    return { wrap: h('div.input-wrap', inp, adorn), input: inp };
  }

  function strengthMeter() {
    const bars = h('div.meter', { 'data-score': '-1' }, h('i'), h('i'), h('i'), h('i'), h('i'));
    const label = h('div.meter-label', h('span'), h('span'));
    const el = h('div', bars, label);
    const update = (pw) => {
      if (!pw) {
        bars.dataset.score = '-1';
        label.firstChild.textContent = '';
        label.lastChild.textContent = '';
        return;
      }
      const s = estimateStrength(pw);
      bars.dataset.score = s.score;
      label.firstChild.textContent = s.warning ? `${s.label} — ${s.warning}` : s.label;
      label.lastChild.textContent = `~${s.bits} bits · cracked ${crackTime(s.bits)}`;
    };
    return { el, update };
  }

  // ---------- data ----------

  async function refreshStatus() {
    S.status = await call('status');
    const on = S.status?.unlocked && S.status.settings?.showIcons !== false;
    setIconLoader(on ? (hosts) => call('icons', { hosts }) : null);
    setVerifiedDomains(S.status?.verifiedDomains ?? null);
    if (S.status?.loggedIn) applyBranding(S.status.branding);
  }

  const brandName = () => S.status?.branding?.name || 'Keyhaven';
  const isAdmin = () => S.status?.role === 'admin';

  const titleWithTick = (it, tag = 'div.t') => {
    const v = itemVerified(it);
    return h(`${tag}.title-line`, h('span', it.title || 'Untitled'), v && verifiedBadge(v, 14));
  };

  async function loadItems() {
    S.items = S.status?.unlocked ? await call('list') : [];
  }

  async function full() {
    try {
      await refreshStatus();
      await loadItems();
    } catch (e) {
      fail(e);
    }
    if (backend.initialItem === 'new' && S.status?.unlocked) {
      backend.initialItem = null;
      render();
      return startNew();
    }
    if (backend.initialItem && S.items.some((i) => i.id === backend.initialItem)) {
      S.selected = backend.initialItem;
      backend.initialItem = null;
    }
    if (!S.selected && window.innerWidth > 640) S.selected = filtered()[0]?.id || null;
    render();
  }

  backend.onEvent(async (evt) => {
    const wasUnlocked = S.status?.unlocked;
    await refreshStatus().catch(() => {});
    if (evt === 'items' && S.status?.unlocked) {
      await loadItems().catch(() => {});
      if (shell && S.mode === 'view') {
        renderSidebar();
        renderList();
        renderDetail();
      } else if (shell) {
        renderSidebar();
        renderList();
      }
      return;
    }
    if (evt === 'settings') return;
    if (evt === 'instance' && shell) {
      renderSidebar();
      renderList();
      if (TOOL_VIEWS.includes(S.view) && S.view !== 'admin') renderDetail();
      if (S.view === 'admin' && !isAdmin()) navigate('all');
      return;
    }
    if (wasUnlocked !== S.status?.unlocked || !S.status?.loggedIn) {
      await loadItems().catch(() => {});
      render();
    }
  });

  // ---------- top-level render ----------

  function render() {
    timers.forEach(clearInterval);
    timers = [];
    shell = null;
    clear(root);
    if (!S.status) return root.append(h('div.auth', h('div.spinner')));
    if (!S.status.loggedIn) return root.append(renderAuth());
    if (!S.status.unlocked) return root.append(renderLocked());
    root.append(renderShell());
  }

  // ---------- auth ----------

  function renderAuth() {
    const isReg = S.authMode === 'register';
    const brandSlot = h('div', brandMark(null, 36));
    const brandTitle = h('h1', 'Keyhaven');
    const brandSub = h('p', isReg ? 'Create an account on your server.' : 'Sign in to your server.');
    const fixedServer = backend.fixedServer;
    const server = h('input.input', {
      placeholder: 'https://vault.example.com', value: fixedServer || backend.lastServer?.() || '', autocomplete: 'url', spellcheck: 'false',
    });
    const pill = h('div.server-pill', h('span.dot'), h('span', fixedServer ? 'This server' : 'Enter the URL of your Keyhaven server'));
    const insecure = h('input', { type: 'checkbox' });
    const insecureRow = h('label.check', { style: { display: 'none', marginTop: '8px' } }, insecure,
      h('span', 'Allow insecure HTTP (only for testing on a trusted network)'));
    const email = h('input.input', { type: 'email', placeholder: 'you@example.com', autocomplete: 'username', spellcheck: 'false' });
    const pwField = passwordInput({ placeholder: 'Master password', autocomplete: isReg ? 'new-password' : 'current-password' }, {
      onInput: (v) => meter?.update(v),
    });
    const meter = isReg ? strengthMeter() : null;
    const confirm = isReg ? passwordInput({ placeholder: 'Repeat master password', autocomplete: 'new-password' }) : null;
    const invite = h('input.input.mono', { placeholder: 'KH-XXXXX-XXXXX', spellcheck: 'false' });
    const inviteField = h('div.field', { style: { display: 'none' } }, h('label.label', 'Invite code'), invite,
      h('div.hint', 'This server is invite-only. The admin creates codes with `keyhaven-server invite`.'));
    const ack = h('input', { type: 'checkbox' });
    const err = h('div.error-text');
    const submit = h('button.btn.primary.block', { type: 'submit' }, isReg ? 'Create account' : 'Sign in');

    let infoTimer;
    async function checkServer() {
      const url = fixedServer || server.value.trim();
      const isHttpRemote = /^http:\/\//i.test(url) && !/^http:\/\/(localhost|127\.|\[::1\])/i.test(url);
      insecureRow.style.display = isHttpRemote ? '' : 'none';
      if (!url) return;
      pill.className = 'server-pill';
      pill.lastChild.textContent = 'Checking server…';
      try {
        const info = await call('serverInfo', { url, allowInsecure: insecure.checked });
        pill.className = 'server-pill ok';
        const mode = { open: 'open registration', invite: 'invite-only', closed: 'registration closed' }[info.signups];
        pill.lastChild.textContent = `${info.branding?.name && info.branding.name !== 'Keyhaven' ? `${info.branding.name} · ` : ''}Keyhaven ${info.version} · ${mode}`;
        if (info.branding) {
          applyBranding(info.branding);
          brandSlot.replaceChildren(brandMark(info.branding, 36));
          brandTitle.textContent = info.branding.name || 'Keyhaven';
          if (info.branding.tagline) brandSub.textContent = info.branding.tagline;
        }
        inviteField.style.display = isReg && info.signups === 'invite' ? '' : 'none';
        return info;
      } catch (e) {
        pill.className = 'server-pill bad';
        pill.lastChild.textContent = e.message;
      }
    }
    server.addEventListener('input', () => {
      clearTimeout(infoTimer);
      infoTimer = setTimeout(checkServer, 450);
    });
    insecure.addEventListener('change', checkServer);
    setTimeout(checkServer, 0);

    const form = h('form', {
      on: {
        submit: async (e) => {
          e.preventDefault();
          err.textContent = '';
          const password = pwField.input.value;
          const serverUrl = fixedServer || server.value.trim();
          if (!serverUrl) return (err.textContent = 'Enter your server URL');
          if (!email.value.trim()) return (err.textContent = 'Enter your email');
          if (isReg) {
            if (password.length < 10) return (err.textContent = 'Use at least 10 characters for your master password');
            if (estimateStrength(password).score < 2) return (err.textContent = 'That master password is too easy to guess');
            if (password !== confirm.input.value) return (err.textContent = 'The passwords don’t match');
            if (!ack.checked) return (err.textContent = 'Please confirm you understand the password can’t be recovered');
          }
          busy(submit, true, isReg ? 'Creating vault…' : 'Unlocking…');
          try {
            const params = { serverUrl, email: email.value.trim(), password, allowInsecure: insecure.checked };
            if (isReg) params.inviteCode = invite.value.trim();
            await call(isReg ? 'register' : 'login', params);
            backend.rememberServer?.(serverUrl);
            await full();
            toast(isReg ? 'Vault created' : 'Signed in');
          } catch (e2) {
            busy(submit, false);
            err.textContent = e2.message;
          }
        },
      },
    },
    !fixedServer && h('div.field', h('label.label', 'Server URL'), server, insecureRow),
    fixedServer && h('div', { style: { marginBottom: '14px' } }, pill),
    h('div.field', h('label.label', 'Email'), email),
    h('div.field', h('label.label', 'Master password'), pwField.wrap, meter?.el),
    isReg && h('div.field', h('label.label', 'Confirm master password'), confirm.wrap),
    inviteField,
    isReg && h('p.warning-box', 'Your master password can’t be reset by anyone, including the server admin. Use a long passphrase you will remember.'),
    isReg && h('label.check', { style: { marginBottom: '16px' } }, ack, h('span', 'I understand my master password cannot be recovered')),
    submit,
    err);

    if (!fixedServer) form.querySelector('.field').append(pill);

    const tabs = h('div.segmented.tabs',
      h(`button${!isReg ? '.on' : ''}`, { type: 'button', on: { click: () => { S.authMode = 'login'; render(); } } }, 'Sign in'),
      h(`button${isReg ? '.on' : ''}`, { type: 'button', on: { click: () => { S.authMode = 'register'; render(); } } }, 'Create account'));

    setTimeout(() => (fixedServer || server.value ? email : server).focus(), 0);
    return h('div.auth', h('div.auth-card',
      h('div.auth-brand', brandSlot, h('div', brandTitle, brandSub)),
      tabs, form));
  }

  function renderLocked() {
    const pw = passwordInput({ placeholder: 'Master password', autocomplete: 'current-password' });
    const err = h('div.error-text');
    const btn = h('button.btn.primary.block', { type: 'submit' }, 'Unlock');
    const form = h('form', {
      on: {
        submit: async (e) => {
          e.preventDefault();
          err.textContent = '';
          if (!pw.input.value) return;
          busy(btn, true, 'Unlocking…');
          try {
            await call('unlock', { password: pw.input.value });
            await full();
          } catch (e2) {
            busy(btn, false);
            err.textContent = e2.message;
            pw.input.select();
          }
        },
      },
    },
    h('div.lock-email', h('div', S.status.email), h('div.muted', { style: { fontSize: '12.5px' } }, displayHost(S.status.serverUrl) || S.status.serverUrl)),
    h('div.field', pw.wrap),
    btn,
    err,
    h('div.auth-foot',
      h('span.muted', 'Works offline'),
      h('button.link.muted', {
        type: 'button',
        on: { click: async () => (await confirmBox({ title: 'Sign out?', body: 'This removes the cached vault from this device. Your data stays on the server.', ok: 'Sign out' })) && call('logout').then(full) },
      }, 'Sign out')));
    setTimeout(() => pw.input.focus(), 0);
    return h('div.auth', h('div.auth-card',
      h('div.auth-brand', brandMark(S.status.branding, 36), h('div', h('h1', S.status.branding?.name && S.status.branding.name !== 'Keyhaven' ? `${S.status.branding.name} is locked` : 'Locked'), h('p', 'Enter your master password to unlock.'))),
      form));
  }

  // ---------- shell ----------

  const TOOL_VIEWS = ['watchtower', 'generator', 'settings', 'admin'];

  function renderShell() {
    shell = {
      root: h('div.shell'),
      sidebar: h('aside.sidebar'),
      list: h('section.listpane'),
      detail: h('main.detail'),
    };
    shell.root.append(shell.sidebar, shell.list, shell.detail);
    buildListPane();
    renderSidebar();
    renderList();
    renderDetail();
    return shell.root;
  }

  function counts() {
    const live = S.items.filter((i) => !i.deletedAt);
    const c = { all: live.length, favorites: live.filter((i) => i.favorite).length, trash: S.items.length - live.length };
    for (const t of Object.keys(TYPE_META)) c[t] = live.filter((i) => i.type === t).length;
    const tags = {};
    for (const i of live) for (const t of i.tags) tags[t] = (tags[t] || 0) + 1;
    return { c, tags };
  }

  async function navigate(view) {
    if (!(await guardDirty())) return;
    S.view = view;
    S.mode = 'view';
    S.draft = null;
    if (!TOOL_VIEWS.includes(view)) {
      const vis = filtered();
      if (!vis.some((i) => i.id === S.selected)) S.selected = vis[0]?.id || null;
    }
    renderSidebar();
    renderList();
    renderDetail();
  }

  function renderSidebar() {
    const { c, tags } = counts();
    const nav = (view, ic, label, count) =>
      h(`button.nav${S.view === view ? '.on' : ''}`, { title: label, on: { click: () => navigate(view) } }, icon(ic, 17), h('span', label),
        count != null && h('span.count', count));
    const st = S.status;
    const syncLine = h(`div.sync-line${st.syncError ? '.err' : ''}`, { title: st.syncError || 'Click to sync now', style: { cursor: 'pointer' } },
      h('span.dot'), h('span', st.syncError ? 'Offline, using cached copy' : `Synced ${timeAgo(st.lastSync)}`));
    syncLine.addEventListener('click', async () => {
      syncLine.lastChild.textContent = 'Syncing…';
      try {
        await call('sync');
        await refreshStatus();
        await loadItems();
        renderSidebar();
        renderList();
        toast('Vault synced');
      } catch (e) {
        fail(e);
        await refreshStatus().catch(() => {});
        renderSidebar();
      }
    });
    clear(shell.sidebar).append(
      h('div.side-brand', brandMark(st.branding, 22), h('span', brandName())),
      h('div.side-scroll',
        nav('all', 'grid', 'All items', c.all),
        nav('favorites', 'star', 'Favorites', c.favorites),
        h('div.side-group', h('div.side-title', 'Categories'),
          ...Object.entries(TYPE_META).map(([t, m]) => nav(t, m.icon, m.plural, c[t]))),
        Object.keys(tags).length > 0 && h('div.side-group', h('div.side-title', 'Tags'),
          ...Object.keys(tags).sort().map((t) => nav(`tag:${t}`, 'tag', t, tags[t]))),
        h('div.side-group', h('div.side-title', 'Tools'),
          nav('watchtower', 'shieldCheck', 'Password health'),
          nav('generator', 'wand', 'Generator'),
          nav('trash', 'trash', 'Trash', c.trash || null)),
        isAdmin() && h('div.side-group', h('div.side-title', 'Server'), nav('admin', 'server', 'Admin'))),
      h('div.side-foot',
        syncLine,
        nav('settings', 'sliders', 'Settings'),
        h('button.nav', { title: 'Ctrl+L', on: { click: () => call('lock').then(full) } }, icon('lock', 17), h('span', 'Lock'))),
    );
    shell.root.classList.toggle('tool', TOOL_VIEWS.includes(S.view));
  }

  function filtered() {
    const q = S.query.trim().toLowerCase();
    let list = S.items.filter((i) => (S.view === 'trash' ? i.deletedAt : !i.deletedAt));
    if (S.view === 'favorites') list = list.filter((i) => i.favorite);
    else if (TYPE_META[S.view]) list = list.filter((i) => i.type === S.view);
    else if (S.view.startsWith('tag:')) list = list.filter((i) => i.tags.includes(S.view.slice(4)));
    if (q) {
      const words = q.split(/\s+/);
      list = list.filter((i) => {
        const hay = [i.title, i.username, ...i.urls, ...i.tags, i.identity.email, i.card.cardholder, i.card.number.slice(-4),
          i.type === 'note' ? i.notes : ''].join(' ').toLowerCase();
        return words.every((w) => hay.includes(w));
      });
    }
    const byName = (a, b) => a.title.localeCompare(b.title, undefined, { sensitivity: 'base' });
    if (S.sort === 'recent') list.sort((a, b) => b.updatedAt - a.updatedAt);
    else if (S.sort === 'used') list.sort((a, b) => (b.lastUsedAt || 0) - (a.lastUsedAt || 0) || byName(a, b));
    else list.sort(byName);
    return list;
  }

  let searchInput;
  let listBody;
  let listMeta;

  function buildListPane() {
    searchInput = h('input.input', { type: 'search', placeholder: 'Search vault', value: S.query, spellcheck: 'false' });
    searchInput.addEventListener('input', () => {
      S.query = searchInput.value;
      renderList();
    });
    searchInput.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        moveSelection(e.key === 'ArrowDown' ? 1 : -1);
      } else if (e.key === 'Enter') {
        const first = filtered()[0];
        if (first) select(first.id);
      }
    });
    const newBtn = h('button.btn.primary', { title: 'New item (Ctrl+N)', on: { click: () => startNew() } }, icon('plus', 16), 'New');
    listMeta = h('div.list-meta');
    listBody = h('div.list', { tabindex: '-1' });
    noticeSlot = h('div');
    shell.list.append(
      h('div.list-head', h('div.search', icon('search', 16), searchInput, h('span.kbd', '/')), newBtn),
      noticeSlot,
      listMeta,
      listBody,
    );
  }

  let noticeSlot;

  function renderNotice() {
    if (!noticeSlot) return;
    const n = S.status?.notice || '';
    const key = `keyhaven.notice.${n.length}.${[...n].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 7)}`;
    clear(noticeSlot);
    if (!n || localStorage.getItem(key)) return;
    noticeSlot.append(h('div.notice-bar', h('span', n),
      h('button.tbtn', { title: 'Dismiss', on: { click: () => { localStorage.setItem(key, '1'); clear(noticeSlot); } } }, 'Dismiss')));
  }

  function renderList() {
    if (!listBody) return;
    renderNotice();
    const list = filtered();
    const sortSel = h('select.sort-select', { title: 'Sort' },
      h('option', { value: 'name' }, 'By name'), h('option', { value: 'recent' }, 'Recently edited'), h('option', { value: 'used' }, 'Recently used'));
    sortSel.value = S.sort;
    sortSel.addEventListener('change', () => {
      S.sort = sortSel.value;
      localStorage.setItem('keyhaven.sort', S.sort);
      renderList();
    });
    const label = S.view === 'trash' ? 'in trash' : 'items';
    clear(listMeta).append(h('span', `${list.length} ${list.length === 1 ? label.replace('items', 'item') : label}`), sortSel);
    clear(listBody);
    if (S.view === 'trash' && list.length) {
      listBody.append(h('div', { style: { padding: '0 8px 8px' } },
        h('button.btn.sm.danger', { on: { click: emptyTrash } }, icon('trash', 14), 'Empty trash')));
    }
    if (!list.length) {
      listBody.append(h('div.empty', icon(S.query ? 'search' : S.view === 'trash' ? 'trash' : 'key', 32),
        h('h3', S.query ? 'No matches' : S.view === 'trash' ? 'Trash is empty' : 'Nothing here yet'),
        h('p', S.query ? 'Try a different search.' : S.view === 'trash' ? 'Deleted items stay here until you empty the trash.' : 'Add your first item, or import from another password manager in Settings.'),
        !S.query && S.view !== 'trash' && h('button.btn.primary', { on: { click: () => startNew() } }, icon('plus', 16), 'New item')));
      return;
    }
    for (const it of list) {
      const row = h(`div.list-item${it.id === S.selected ? '.on' : ''}`, { dataset: { id: it.id } },
        avatar(it, 36),
        h('div.grow', titleWithTick(it), h('div.s', itemSubtitle(it) || TYPE_META[it.type].label)),
        it.favorite && icon('star', 14, 'fav'));
      row.addEventListener('click', () => select(it.id));
      row.addEventListener('dblclick', () => it.type === 'login' && it.password && copy(it.password, 'Password copied'));
      listBody.append(row);
    }
  }

  async function guardDirty() {
    if ((S.mode === 'edit' || S.mode === 'new') && S.dirty) {
      return confirmBox({ title: 'Discard changes?', body: 'You have unsaved changes to this item.', ok: 'Discard', danger: true });
    }
    return true;
  }

  async function select(id) {
    if (S.selected === id && S.mode === 'view') return;
    if (!(await guardDirty())) return;
    S.selected = id;
    S.mode = 'view';
    S.draft = null;
    shell.root.classList.add('has-detail');
    listBody.querySelectorAll('.list-item').forEach((el) => el.classList.toggle('on', el.dataset.id === id));
    listBody.querySelector('.list-item.on')?.scrollIntoView({ block: 'nearest' });
    renderDetail();
  }

  function moveSelection(d) {
    const list = filtered();
    if (!list.length) return;
    const i = list.findIndex((x) => x.id === S.selected);
    const next = list[Math.max(0, Math.min(list.length - 1, i < 0 ? 0 : i + d))];
    select(next.id);
  }

  async function emptyTrash() {
    const n = S.items.filter((i) => i.deletedAt).length;
    if (!(await confirmBox({ title: 'Empty trash?', body: `Permanently delete ${n} item${n === 1 ? '' : 's'}. This cannot be undone.`, ok: 'Delete forever', danger: true }))) return;
    try {
      await call('emptyTrash');
      await loadItems();
      S.selected = null;
      renderSidebar();
      renderList();
      renderDetail();
      toast('Trash emptied');
    } catch (e) {
      fail(e);
    }
  }

  // ---------- detail ----------

  function renderDetail() {
    timers.forEach(clearInterval);
    timers = [];
    if (!shell) return;
    const d = clear(shell.detail);
    if (S.view === 'generator') return d.append(renderGeneratorPage());
    if (S.view === 'watchtower') return d.append(renderWatchtower());
    if (S.view === 'settings') return d.append(renderSettings());
    if (S.view === 'admin') return d.append(renderAdmin());
    if (S.mode === 'new' || S.mode === 'edit') return d.append(renderEditor());
    const it = S.items.find((i) => i.id === S.selected);
    if (!it) {
      return d.append(h('div.empty', h('p', S.items.length ? 'No item selected.' : 'Your vault is empty.')));
    }
    d.append(renderItem(it));
  }

  function backButton() {
    return h('button.icon-btn', { class: 'mobile-back', title: 'Back', on: { click: () => shell.root.classList.remove('has-detail') } }, icon('arrowLeft', 18));
  }

  function fieldRow(label, value, { secret = false, mono = false, copyLabel, extra = [], link } = {}) {
    let shown = !secret;
    const v = h(`div.v${mono || secret ? '.mono' : ''}`);
    const paint = () => {
      clear(v);
      if (shown) v.append(secret || mono ? passwordSpan(value) : value);
      else v.append('••••••••••••');
    };
    paint();
    const acts = h('div.acts');
    if (secret) {
      const eye = h('button.tbtn', shown ? 'Hide' : 'Show');
      eye.addEventListener('click', () => {
        shown = !shown;
        eye.textContent = shown ? 'Hide' : 'Show';
        paint();
      });
      acts.append(eye);
    }
    if (link) acts.append(h('button.tbtn', { on: { click: () => backend.openUrl(link) } }, 'Open'));
    acts.append(h('button.tbtn', { on: { click: () => copy(value, copyLabel || `${label} copied`, secret) } }, 'Copy'));
    return h('div.frow', h('div.grow', h('div.k', label, ...extra), v), acts);
  }

  function totpRow(secret) {
    const code = h('span.code', '••• •••');
    const C = 2 * Math.PI * 9;
    const fg = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    const bg = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    for (const c of [bg, fg]) {
      c.setAttribute('cx', '11');
      c.setAttribute('cy', '11');
      c.setAttribute('r', '9');
    }
    bg.setAttribute('class', 'bg');
    fg.setAttribute('class', 'fg');
    fg.setAttribute('stroke-dasharray', C);
    const ring = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    ring.setAttribute('viewBox', '0 0 22 22');
    ring.setAttribute('class', 'ring');
    ring.append(bg, fg);
    const secs = h('span.muted', { style: { fontSize: '12px', fontVariantNumeric: 'tabular-nums' } });
    let current = '';
    const tick = async () => {
      try {
        const t = await totpCode(secret);
        current = t.code;
        code.textContent = t.code.length === 6 ? `${t.code.slice(0, 3)} ${t.code.slice(3)}` : t.code;
        fg.setAttribute('stroke-dashoffset', C * (1 - t.remaining / t.period));
        ring.classList.toggle('low', t.remaining <= 5);
        secs.textContent = `${t.remaining}s`;
      } catch {
        code.textContent = 'Invalid secret';
      }
    };
    tick();
    timers.push(setInterval(tick, 1000));
    return h('div.frow',
      h('div.grow', h('div.k', 'One-time code'), h('div.totp', code, ring, secs)),
      h('div.acts', h('button.tbtn', { on: { click: () => copy(current, 'Code copied') } }, 'Copy')));
  }

  function renderItem(it) {
    const inTrash = !!it.deletedAt;
    const meta = TYPE_META[it.type];
    const fav = h(`button.icon-btn${it.favorite ? '.on' : ''}`, { title: it.favorite ? 'Unfavorite' : 'Favorite' }, icon('star', 18));
    fav.addEventListener('click', async () => {
      try {
        await call('favorite', { id: it.id, value: !it.favorite });
        await loadItems();
        renderSidebar();
        renderList();
        renderDetail();
      } catch (e) {
        fail(e);
      }
    });
    const actions = inTrash
      ? [
          h('button.btn.sm', { on: { click: () => restore(it) } }, icon('undo', 15), 'Restore'),
          h('button.btn.sm.danger', { on: { click: () => destroy(it) } }, icon('trash', 15), 'Delete forever'),
        ]
      : [
          fav,
          h('button.btn.sm', { title: 'Move to trash', on: { click: () => trash(it) } }, 'Delete'),
          h('button.btn.sm', { title: 'Edit (E)', on: { click: () => startEdit(it) } }, 'Edit'),
        ];

    const banners = [];
    if (inTrash) banners.push(h('p.note-line', `In trash since ${formatDate(it.deletedAt)}.`));
    if (it.type === 'login' && it.password && !inTrash) {
      const reusedCount = S.items.filter((x) => x.id !== it.id && !x.deletedAt && x.password === it.password).length;
      const s = estimateStrength(it.password);
      if (reusedCount) banners.push(h('p.note-line.warn', `Same password as ${reusedCount} other item${reusedCount === 1 ? '' : 's'}.`));
      else if (s.score < 2) banners.push(h('p.note-line.warn', `Weak password${s.warning ? ` (${s.warning.toLowerCase()})` : ''}.`));
    }

    const sections = [];
    if (it.type === 'login') {
      const rows = [];
      if (it.username) rows.push(fieldRow('Username', it.username, { copyLabel: 'Username copied' }));
      if (it.password) {
        const s = estimateStrength(it.password);
        rows.push(fieldRow('Password', it.password, {
          secret: true, copyLabel: 'Password copied',
          extra: [h(`span.chip${s.score < 2 ? '.danger' : ''}`, ` · ${s.label.toLowerCase()}`)],
        }));
      }
      if (it.totp) rows.push(totpRow(it.totp));
      for (const pk of it.passkeys) {
        rows.push(h('div.frow', h('div.grow', h('div.k', 'Passkey'),
          h('div.v', `${pk.userName || pk.userDisplayName || it.username || 'account'} on ${pk.rpId}`),
          h('div.muted', { style: { fontSize: '12px' } }, `Created ${formatDate(pk.createdAt)}${pk.lastUsedAt ? ` · last used ${timeAgo(pk.lastUsedAt)}` : ''}`))));
      }
      if (rows.length) sections.push(h('div.card', rows));
      if (it.urls.length) {
        sections.push(h('div.card', it.urls.map((u) => {
          const href = parseLoose(u)?.href;
          const host = displayHost(u) || u;
          const full = u.replace(/\/$/, '');
          return h('div.frow',
            h('div.grow', h('div.k', 'Website'),
              h('div.v', href ? h('a', { href: '#', on: { click: (e) => { e.preventDefault(); backend.openUrl(href); } } }, host) : host),
              full !== host && full !== `https://${host}` && h('div.sub', full)),
            h('div.acts',
              href && h('button.tbtn', { on: { click: () => backend.openUrl(href) } }, 'Open'),
              h('button.tbtn', { on: { click: () => copy(u, 'URL copied', false) } }, 'Copy')));
        })));
      }
    } else if (it.type === 'card') {
      const c = it.card;
      const rows = [];
      if (c.cardholder) rows.push(fieldRow('Cardholder', c.cardholder));
      if (c.number) rows.push(fieldRow(cardBrand(c.number) || 'Number', c.number.replace(/(\d{4})(?=\d)/g, '$1 '), { secret: true, copyLabel: 'Card number copied' }));
      if (c.expMonth || c.expYear) rows.push(fieldRow('Expires', `${String(c.expMonth).padStart(2, '0')}/${c.expYear}`, { mono: true }));
      if (c.cvv) rows.push(fieldRow('Security code', c.cvv, { secret: true }));
      if (c.pin) rows.push(fieldRow('PIN', c.pin, { secret: true }));
      if (rows.length) sections.push(h('div.card', rows));
    } else if (it.type === 'identity') {
      const i = it.identity;
      const name = [i.firstName, i.lastName].filter(Boolean).join(' ');
      const addr = [i.address1, i.address2, [i.postalCode, i.city].filter(Boolean).join(' '), i.state, i.country].filter(Boolean).join('\n');
      const rows = [];
      if (name) rows.push(fieldRow('Name', name));
      if (i.email) rows.push(fieldRow('Email', i.email));
      if (i.phone) rows.push(fieldRow('Phone', i.phone));
      if (i.company) rows.push(fieldRow('Company', i.company));
      if (addr) rows.push(fieldRow('Address', addr));
      if (rows.length) sections.push(h('div.card', rows));
    }
    if (it.fields.length) {
      sections.push(h('div.card', h('div.card-title', 'Other fields'),
        it.fields.map((f) => fieldRow(f.label || 'Field', f.value, { secret: f.hidden }))));
    }
    if (it.notes) {
      sections.push(h('div.card', h('div.card-title', 'Notes'), h('div.frow', h('div.notes-v.grow', it.notes),
        h('div.acts', h('button.tbtn', { on: { click: () => copy(it.notes, 'Notes copied', false) } }, 'Copy')))));
    }
    if (it.passwordHistory.length) {
      const body = h('div', { style: { display: 'none' } },
        it.passwordHistory.map((p) => h('div.history-row', h('span.grow.mono', { style: { overflow: 'hidden', textOverflow: 'ellipsis' } }, '••••••••'),
          h('span.muted', timeAgo(p.changedAt)),
          h('button.tbtn', { on: { click: (e) => { const s = e.currentTarget.parentNode.firstChild; clear(s).append(passwordSpan(p.password)); } } }, 'Show'),
          h('button.tbtn', { on: { click: () => copy(p.password, 'Old password copied') } }, 'Copy'))));
      const toggle = h('button.history-toggle', `Previous passwords (${it.passwordHistory.length})`);
      toggle.addEventListener('click', () => (body.style.display = body.style.display ? '' : 'none'));
      sections.push(h('div.history-box', toggle, body));
    }

    const created = h('div.meta-grid',
      h('span', 'Created'), h('b', formatDate(it.createdAt)),
      h('span', 'Last edited'), h('b', formatDate(it.updatedAt)),
      it.type === 'login' && it.password && [h('span', 'Password changed'), h('b', formatDate(it.passwordChangedAt))],
      it.type === 'login' && [h('span', 'Last autofilled'), h('b', it.lastUsedAt ? timeAgo(it.lastUsedAt) : 'never')]);

    return h('div.detail-inner',
      h('div.detail-head', backButton(), avatar(it, 40), h('div.grow',
        titleWithTick(it, 'h2'),
        h('div.meta', h('span', meta.label),
          it.urls[0] && h('span', displayHost(it.urls[0])),
          it.tags.length > 0 && h('span', it.tags.join(', ')))),
      h('div.detail-actions', actions)),
      banners, sections, created);
  }

  async function trash(it) {
    try {
      await call('trash', { id: it.id });
      await loadItems();
      const next = filtered()[0];
      S.selected = next?.id || null;
      renderSidebar();
      renderList();
      renderDetail();
      toast('Moved to trash');
    } catch (e) {
      fail(e);
    }
  }

  async function restore(it) {
    try {
      await call('restore', { id: it.id });
      await loadItems();
      S.selected = filtered()[0]?.id || null;
      renderSidebar();
      renderList();
      renderDetail();
      toast('Item restored');
    } catch (e) {
      fail(e);
    }
  }

  async function destroy(it) {
    if (!(await confirmBox({ title: 'Delete forever?', body: `“${it.title}” will be permanently deleted from all your devices.`, ok: 'Delete forever', danger: true }))) return;
    try {
      await call('delete', { id: it.id });
      await loadItems();
      S.selected = filtered()[0]?.id || null;
      renderSidebar();
      renderList();
      renderDetail();
      toast('Item deleted');
    } catch (e) {
      fail(e);
    }
  }

  // ---------- editor ----------

  function blankItem(type) {
    return {
      id: '', type, title: '', favorite: false, tags: [], notes: '', username: '', password: '', urls: [''], totp: '', passkeys: [],
      card: { cardholder: '', number: '', expMonth: '', expYear: '', cvv: '', pin: '' },
      identity: { firstName: '', lastName: '', email: '', phone: '', company: '', address1: '', address2: '', city: '', state: '', postalCode: '', country: '' },
      fields: [],
    };
  }

  async function startNew(type) {
    if (!(await guardDirty())) return;
    if (TOOL_VIEWS.includes(S.view) || S.view === 'trash') {
      S.view = 'all';
      renderSidebar();
      renderList();
    }
    S.mode = 'new';
    S.dirty = false;
    S.draft = blankItem(type || (TYPE_META[S.view] ? S.view : 'login'));
    shell.root.classList.add('has-detail');
    renderDetail();
  }

  function startEdit(it) {
    S.mode = 'edit';
    S.dirty = false;
    S.draft = structuredClone(it);
    if (S.draft.type === 'login' && !S.draft.urls.length) S.draft.urls = [''];
    renderDetail();
  }

  function renderEditor() {
    const d = S.draft;
    const isNew = S.mode === 'new';
    const markDirty = () => (S.dirty = true);
    const bind = (obj, key, attrs = {}, tag = 'input.input') => {
      const el = h(tag, { value: obj[key] ?? '', spellcheck: 'false', ...attrs });
      el.addEventListener('input', () => {
        obj[key] = el.value;
        markDirty();
      });
      return el;
    };
    const field = (label, control, hint) => h('div.field', h('label.label', label), control, hint && h('div.hint', hint));

    const title = bind(d, 'title', { placeholder: TYPE_META[d.type].label + ' name', class: 'title-input' });
    const body = [];

    if (isNew) {
      body.push(h('div.type-picker', Object.entries(TYPE_META).map(([t, m]) =>
        h(`button${d.type === t ? '.on' : ''}`, { type: 'button', on: { click: () => { d.type = t; renderDetail(); } } }, icon(m.icon, 20), m.label))));
    }
    body.push(h('div.field', title));

    if (d.type === 'login') {
      const meter = strengthMeter();
      const pw = passwordInput({ value: d.password, placeholder: 'Password', autocomplete: 'new-password' }, {
        generate: true,
        onInput: (v) => {
          d.password = v;
          meter.update(v);
          markDirty();
        },
      });
      meter.update(d.password);
      const totpInput = bind(d, 'totp', { placeholder: 'Secret key or otpauth:// link', class: 'mono' });
      const totpHint = h('div.hint', 'Paste the setup key shown when enabling two-factor authentication.');
      totpInput.addEventListener('input', () => {
        const v = totpInput.value.trim();
        totpHint.textContent = !v ? 'Paste the setup key shown when enabling two-factor authentication.' : isValidTotp(v) ? '✓ Valid secret' : 'Not a valid base32 secret or otpauth link';
        totpHint.style.color = !v ? '' : isValidTotp(v) ? 'var(--ok)' : 'var(--danger)';
      });
      const urlRows = h('div');
      const paintUrls = () => {
        clear(urlRows);
        d.urls.forEach((u, i) => {
          const inp = h('input.input', { value: u, placeholder: 'https://example.com', spellcheck: 'false' });
          inp.addEventListener('input', () => {
            d.urls[i] = inp.value;
            markDirty();
          });
          urlRows.append(h('div.list-row', inp, d.urls.length > 1 && h('button.icon-btn', { type: 'button', title: 'Remove', on: { click: () => { d.urls.splice(i, 1); markDirty(); paintUrls(); } } }, icon('minus', 16))));
        });
        urlRows.append(h('button.btn.sm.ghost', { type: 'button', style: { marginBottom: '12px' }, on: { click: () => { d.urls.push(''); paintUrls(); urlRows.querySelectorAll('input')[d.urls.length - 1]?.focus(); } } }, icon('plus', 14), 'Add website'));
      };
      paintUrls();
      body.push(h('div.section',
        field('Username', bind(d, 'username', { placeholder: 'Username or email', autocomplete: 'off' })),
        field('Password', h('div', pw.wrap, meter.el)),
        field('One-time password (2FA)', totpInput, null), totpHint, h('div', { style: { height: '12px' } })));
      body.push(h('div.section', h('div.section-title', 'Websites'), urlRows));
      if (d.passkeys?.length) {
        const pkWrap = h('div');
        const paintPk = () => {
          clear(pkWrap);
          d.passkeys.forEach((pk, i) => pkWrap.append(h('div.list-row',
            h('div.grow', h('div', `${pk.userName || 'account'} on ${pk.rpId}`), h('div.muted', { style: { fontSize: '12px' } }, `Created ${formatDate(pk.createdAt)}`)),
            h('button.btn.sm.danger', { type: 'button', on: { click: async () => {
              if (!(await confirmBox({ title: 'Remove passkey?', body: `You won't be able to sign in to ${pk.rpId} with this passkey anymore. Remove it from the site's security settings too.`, ok: 'Remove', danger: true }))) return;
              d.passkeys.splice(i, 1);
              markDirty();
              paintPk();
            } } }, 'Remove'))));
          if (!d.passkeys.length) pkWrap.append(h('p.muted', { style: { fontSize: '13px' } }, 'Passkey removed. Save to apply.'));
        };
        paintPk();
        body.push(h('div.section', h('div.section-title', 'Passkeys'), pkWrap));
      }
    } else if (d.type === 'card') {
      const c = d.card;
      const num = bind(c, 'number', { placeholder: '1234 5678 9012 3456', inputmode: 'numeric', class: 'mono', autocomplete: 'off' });
      const brand = h('div.hint', cardBrand(c.number));
      num.addEventListener('input', () => (brand.textContent = cardBrand(num.value)));
      body.push(h('div.section',
        field('Cardholder name', bind(c, 'cardholder', { autocomplete: 'off' })),
        h('div.field', h('label.label', 'Card number'), num, brand),
        h('div.grid3',
          field('Expiry month', bind(c, 'expMonth', { placeholder: 'MM', inputmode: 'numeric', maxlength: '2' })),
          field('Expiry year', bind(c, 'expYear', { placeholder: 'YYYY', inputmode: 'numeric', maxlength: '4' })),
          field('Security code', bind(c, 'cvv', { placeholder: 'CVV', type: 'password', inputmode: 'numeric', maxlength: '4', autocomplete: 'off' }))),
        field('PIN', bind(c, 'pin', { type: 'password', inputmode: 'numeric', autocomplete: 'off' }))));
    } else if (d.type === 'identity') {
      const i = d.identity;
      body.push(h('div.section',
        h('div.grid2', field('First name', bind(i, 'firstName')), field('Last name', bind(i, 'lastName'))),
        h('div.grid2', field('Email', bind(i, 'email', { type: 'email' })), field('Phone', bind(i, 'phone', { type: 'tel' }))),
        field('Company', bind(i, 'company'))));
      body.push(h('div.section', h('div.section-title', 'Address'),
        field('Address line 1', bind(i, 'address1')), field('Address line 2', bind(i, 'address2')),
        h('div.grid2', field('City', bind(i, 'city')), field('State / region', bind(i, 'state'))),
        h('div.grid2', field('Postal code', bind(i, 'postalCode')), field('Country', bind(i, 'country')))));
    }

    // custom fields
    const fieldsWrap = h('div');
    const paintFields = () => {
      clear(fieldsWrap);
      d.fields.forEach((f, i) => {
        const lbl = h('input.input', { value: f.label, placeholder: 'Label', style: { maxWidth: '180px' } });
        const val = h('input.input', { value: f.value, placeholder: 'Value', type: f.hidden ? 'password' : 'text', spellcheck: 'false' });
        lbl.addEventListener('input', () => { f.label = lbl.value; markDirty(); });
        val.addEventListener('input', () => { f.value = val.value; markDirty(); });
        const hid = h(`button.icon-btn${f.hidden ? '.on' : ''}`, { type: 'button', title: f.hidden ? 'Hidden field' : 'Visible field' }, icon(f.hidden ? 'eyeOff' : 'eye', 16));
        hid.addEventListener('click', () => { f.hidden = !f.hidden; markDirty(); paintFields(); });
        fieldsWrap.append(h('div.list-row', lbl, val, hid,
          h('button.icon-btn', { type: 'button', title: 'Remove', on: { click: () => { d.fields.splice(i, 1); markDirty(); paintFields(); } } }, icon('minus', 16))));
      });
      fieldsWrap.append(h('button.btn.sm.ghost', { type: 'button', style: { marginBottom: '12px' }, on: { click: () => { d.fields.push({ label: '', value: '', hidden: false }); paintFields(); } } }, icon('plus', 14), 'Add field'));
    };
    paintFields();
    body.push(h('div.section', h('div.section-title', 'Custom fields'), fieldsWrap));

    const tags = h('input.input', { value: d.tags.join(', '), placeholder: 'work, finance, family', spellcheck: 'false' });
    tags.addEventListener('input', () => { d.tags = tags.value.split(',').map((t) => t.trim()).filter(Boolean); markDirty(); });
    const notes = bind(d, 'notes', { placeholder: d.type === 'note' ? 'Write your secure note…' : 'Notes', rows: d.type === 'note' ? 12 : 4 }, 'textarea.textarea');
    body.push(h('div.section', field('Notes', notes), field('Tags', tags, 'Separate tags with commas')));

    const err = h('div.error-text');
    const saveBtn = h('button.btn.primary', { type: 'submit' }, icon('check', 16), isNew ? 'Create item' : 'Save changes');
    const form = h('form.editor', {
      on: {
        submit: async (e) => {
          e.preventDefault();
          err.textContent = '';
          busy(saveBtn, true, 'Saving…');
          try {
            const item = { ...d, urls: (d.urls || []).filter((u) => u.trim()) };
            const saved = await call('save', { item });
            S.dirty = false;
            S.mode = 'view';
            S.draft = null;
            S.selected = saved.id;
            await loadItems();
            renderSidebar();
            renderList();
            renderDetail();
            toast(isNew ? 'Item created' : 'Changes saved');
          } catch (e2) {
            busy(saveBtn, false);
            err.textContent = e2.message;
          }
        },
      },
    },
    h('div.detail-head', backButton(), h('h2', isNew ? `New ${TYPE_META[d.type].label.toLowerCase()}` : 'Edit item'),
      h('div.detail-actions', !isNew && h('label.check', h('input', { type: 'checkbox', checked: d.favorite, on: { change: (e) => { d.favorite = e.target.checked; markDirty(); } } }), 'Favorite'))),
    body, err,
    h('div.foot',
      h('button.btn', { type: 'button', on: { click: cancelEdit } }, 'Cancel'),
      saveBtn));
    setTimeout(() => (isNew ? title : form.querySelector('input'))?.focus(), 0);
    return h('div.detail-inner', form);
  }

  async function cancelEdit() {
    if (!(await guardDirty())) return;
    S.mode = 'view';
    S.draft = null;
    S.dirty = false;
    renderDetail();
  }

  // ---------- generator ----------

  function generatorControls(onChange) {
    const o = loadGen();
    const wrap = h('div.gen-opts');
    const paint = () => {
      saveGen(o);
      clear(wrap);
      const seg = h('div.segmented', ['random', 'passphrase', 'pin'].map((k) =>
        h(`button${o.kind === k ? '.on' : ''}`, { type: 'button', on: { click: () => { o.kind = k; paint(); } } }, { random: 'Random', passphrase: 'Passphrase', pin: 'PIN' }[k])));
      wrap.append(seg);
      const slider = (label, key, min, max) => {
        const val = h('span.val', o[key]);
        const r = h('input', { type: 'range', min, max, value: o[key] });
        r.addEventListener('input', () => { o[key] = +r.value; val.textContent = r.value; saveGen(o); onChange(o); });
        return h('div', h('div.opt-row', h('span.lbl', label), val), r);
      };
      const toggle = (label, key) => {
        const inp = h('input', { type: 'checkbox', checked: o[key] });
        inp.addEventListener('change', () => { o[key] = inp.checked; saveGen(o); onChange(o); });
        return h('label.opt-row', { style: { cursor: 'pointer' } }, h('span', label), h('span.toggle', inp, h('span')));
      };
      if (o.kind === 'random') {
        wrap.append(slider('Length', 'length', 8, 64), toggle('Uppercase (A–Z)', 'upper'), toggle('Lowercase (a–z)', 'lower'),
          toggle('Digits (0–9)', 'digits'), toggle('Symbols (!@#…)', 'symbols'), toggle('Avoid look-alike characters', 'avoidAmbiguous'));
      } else if (o.kind === 'passphrase') {
        const sep = h('select.select', { style: { width: 'auto', height: '32px' } }, ['-', '.', '_', ' ', ','].map((s) => h('option', { value: s }, s === ' ' ? 'space' : s)));
        sep.value = o.separator;
        sep.addEventListener('change', () => { o.separator = sep.value; saveGen(o); onChange(o); });
        wrap.append(slider('Words', 'words', 3, 12), h('div.opt-row', h('span', 'Separator'), sep), toggle('Capitalize words', 'capitalize'), toggle('Include a number', 'includeNumber'));
      } else {
        wrap.append(slider('Digits', 'pinLength', 4, 16));
      }
      onChange(o);
    };
    paint();
    return wrap;
  }

  function renderGeneratorPage() {
    const out = h('div.pw');
    const info = h('div.muted', { style: { fontSize: '13px', marginBottom: '20px' } });
    let current = '';
    let opts = loadGen();
    const regen = () => {
      current = generatePassword(opts);
      clear(out).append(passwordSpan(current));
      const bits = Math.round(generatorEntropy(opts));
      info.textContent = `${bits} bits of entropy · would take ${crackTime(bits)} to crack at 10 billion guesses/second`;
    };
    const controls = generatorControls((o) => { opts = o; regen(); });
    return h('div.detail-inner', { style: { maxWidth: '620px' } },
      h('h1.page-title', 'Password generator'),
      h('p.page-sub', 'Generated on this device.'),
      h('div.gen-out', out,
        h('button.icon-btn', { title: 'Regenerate', on: { click: regen } }, icon('refresh', 18)),
        h('button.btn.primary', { on: { click: () => copy(current, 'Password copied') } }, icon('copy', 16), 'Copy')),
      info,
      h('div.card', { style: { padding: '16px' } }, controls));
  }

  function openGeneratorPopover(anchor, onUse) {
    document.querySelector('.popover')?.remove();
    const out = h('div.pw', { style: { fontSize: '15px', flex: '1' } });
    let current = '';
    let opts = loadGen();
    const regen = () => {
      current = generatePassword(opts);
      clear(out).append(passwordSpan(current));
    };
    const pop = h('div.popover',
      h('div.gen-out', { style: { padding: '12px', minHeight: '0' } }, out, h('button.icon-btn', { type: 'button', title: 'Regenerate', on: { click: regen } }, icon('refresh', 16))),
      generatorControls((o) => { opts = o; regen(); }),
      h('div.row', { style: { marginTop: '14px', justifyContent: 'flex-end' } },
        h('button.btn.sm', { type: 'button', on: { click: () => close() } }, 'Cancel'),
        h('button.btn.sm.primary', { type: 'button', on: { click: () => { onUse(current); close(); } } }, 'Use password')));
    const r = anchor.getBoundingClientRect();
    pop.style.top = `${Math.min(window.innerHeight - 520, r.bottom + 8)}px`;
    pop.style.left = `${Math.max(12, Math.min(window.innerWidth - 352, r.right - 340))}px`;
    const onDoc = (e) => !pop.contains(e.target) && e.target !== anchor && close();
    const close = () => {
      pop.remove();
      document.removeEventListener('mousedown', onDoc, true);
    };
    setTimeout(() => document.addEventListener('mousedown', onDoc, true), 0);
    document.body.append(pop);
  }

  // ---------- watchtower ----------

  function renderWatchtower() {
    const wrap = h('div.detail-inner', h('h1.page-title', 'Password health'),
      h('p.page-sub', 'Checked on this device. Nothing is sent to the server.'));
    call('health').then((r) => {
      const cats = [
        ['weak', 'Weak', r.weak.length, 'easy to guess'],
        ['reused', 'Reused', r.reused.flat().length, 'same password on several sites'],
        ['old', 'Old', r.old.length, 'unchanged for over a year'],
        ['insecure', 'Insecure URL', r.insecure.length, 'saved with http://'],
      ];
      const listWrap = h('div');
      const paintList = () => {
        clear(listWrap);
        const groups = S.wt === 'reused' ? r.reused : (r[S.wt] || []).map((id) => [id]);
        if (!groups.length) return listWrap.append(h('p.muted', 'Nothing to fix.'));
        const single = S.wt !== 'reused' ? h('div.card') : null;
        if (single) listWrap.append(single);
        for (const group of groups) {
          const card = single || h('div.card');
          if (S.wt === 'reused') card.append(h('div.card-title', `Shared by ${group.length} items`));
          for (const id of group) {
            const it = S.items.find((x) => x.id === id);
            if (!it) continue;
            card.append(h('div.frow',
              avatar(it, 28),
              h('div.grow', h('div', it.title), h('div.muted', { style: { fontSize: '12.5px' } }, it.username || displayHost(it.urls[0] || ''))),
              S.wt === 'old' && h('span.muted', { style: { fontSize: '12.5px' } }, timeAgo(it.passwordChangedAt || it.createdAt)),
              h('button.btn.sm', { on: { click: () => { S.view = 'all'; S.query = ''; searchInput.value = ''; S.selected = id; renderSidebar(); renderList(); startEdit(it); } } }, 'Change')));
          }
          if (!single) listWrap.append(card);
        }
      };
      const list = h('div.health-list', cats.map(([k, t, n, d]) => {
        const b = h(`button.health-row${S.wt === k ? '.on' : ''}`, h(`span.n${n ? '.bad' : ''}`, n), h('span', t), h('span.d', d));
        b.addEventListener('click', () => {
          S.wt = k;
          list.querySelectorAll('.health-row').forEach((x) => x.classList.toggle('on', x === b));
          paintList();
        });
        return b;
      }));
      const summary = r.total
        ? `${r.total} login${r.total === 1 ? '' : 's'} checked. ${r.score}% have no issues.` + (r.noTotp ? ` ${r.noTotp} without a saved 2FA code.` : '')
        : 'No logins yet.';
      wrap.append(h('p.health-score', summary), list, listWrap);
      paintList();
    }).catch(fail);
    return wrap;
  }

  // ---------- admin ----------

  const A = (method, path, body) => call('admin', { method, path, body });
  let adminShow = null;

  function fmtBytes(n) {
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1024 / 1024).toFixed(1)} MB`;
  }

  function renderAdmin() {
    const tabs = [['overview', 'Overview'], ['users', 'Users'], ['invites', 'Invites'], ['branding', 'Branding'], ['verified', 'Verified sites'], ['server', 'Server']];
    const body = h('div');
    const bar = h('div.admin-tabs', tabs.map(([k, label]) => h('button', { dataset: { k }, on: { click: () => show(k) } }, label)));
    const pages = { overview: adminOverview, users: adminUsers, invites: adminInvites, branding: adminBranding, verified: adminVerified, server: adminServer };
    const show = (k) => {
      S.adminTab = k;
      bar.querySelectorAll('button').forEach((b) => b.classList.toggle('on', b.dataset.k === k));
      clear(body).append(h('p.muted', 'Loading…'));
      pages[k]().then((el) => S.adminTab === k && clear(body).append(el)).catch((e) => clear(body).append(h('p.note-line.warn', e.message)));
    };
    adminShow = show;
    setTimeout(() => show(S.adminTab || 'overview'), 0);
    return h('div.detail-inner', { style: { maxWidth: '880px' } },
      h('h1.page-title', 'Admin'),
      h('p.page-sub', 'Manage this server. Admins can’t see anyone’s passwords: every vault stays end-to-end encrypted.'),
      bar, body);
  }

  async function adminOverview() {
    const o = await A('GET', '/api/admin/overview');
    const stat = (n, l) => h('div.stat', h('div.n', n), h('div.l', l));
    const mode = { open: 'Open', invite: 'Invite only', closed: 'Closed' }[o.signups];
    return h('div',
      h('div.stat-grid',
        stat(o.users, o.users === 1 ? 'Account' : 'Accounts'),
        stat(o.admins, o.admins === 1 ? 'Admin' : 'Admins'),
        stat(o.items, 'Encrypted items'),
        stat(fmtBytes(o.dbBytes), 'Database size'),
        stat(mode, 'Registration'),
        stat(o.version, 'Server version')),
      h('div.card', h('div.set-row', h('div.grow', h('div.t', 'Command line'),
        h('div.d', 'On the server machine you can also run keyhaven-server invite, users, promote EMAIL, demote EMAIL and delete-user EMAIL.')))));
  }

  async function adminUsers() {
    const { users, me } = await A('GET', '/api/admin/users');
    const reload = () => adminShow?.('users');
    const rows = users.map((u) => {
      const self = u.id === me;
      const isAdm = u.role === 'admin';
      const act = async (fn, msg) => {
        try {
          await fn();
          toast(msg);
          await refreshStatus();
          reload();
        } catch (e) {
          fail(e);
        }
      };
      return h('tr',
        h('td', h('div', { style: { fontWeight: 500 } }, u.email, self && h('span.muted', ' (you)')),
          h('div.muted', { style: { fontSize: '12px' } }, `Joined ${formatDate(u.createdAt)}`)),
        h('td', h(`span.role-pill${isAdm ? '.admin' : ''}`, isAdm ? 'Admin' : 'User')),
        h('td.muted', u.items),
        h('td.muted', u.sessions),
        h('td.muted', u.lastActive ? timeAgo(u.lastActive) : 'never'),
        h('td.acts',
          h('button.tbtn', { on: { click: async () => {
            const ok = await confirmBox(isAdm
              ? { title: `Remove admin from ${u.email}?`, body: self ? 'You will lose access to this admin page.' : 'They keep their account and vault.', ok: 'Remove admin', danger: true }
              : { title: `Make ${u.email} an admin?`, body: 'Admins can manage accounts, invites, branding and server settings. They still can’t read anyone’s vault.', ok: 'Make admin' });
            if (ok) act(() => A('PUT', `/api/admin/users/${u.id}/role`, { role: isAdm ? 'user' : 'admin' }), isAdm ? 'Admin removed' : 'Admin added');
          } } }, isAdm ? 'Remove admin' : 'Make admin'),
          !self && h('button.tbtn', { on: { click: async () => {
            if (await confirmBox({ title: `Sign ${u.email} out everywhere?`, body: 'All their devices will need to sign in again. Their data is untouched.', ok: 'Sign out' })) {
              act(() => A('POST', `/api/admin/users/${u.id}/signout`, {}), 'Signed out of all devices');
            }
          } } }, 'Sign out'),
          !self && h('button.tbtn', { style: { color: 'var(--danger)' }, on: { click: async () => {
            if (await confirmBox({ title: `Delete ${u.email}?`, body: `This permanently erases the account and its ${u.items} encrypted item${u.items === 1 ? '' : 's'} from the server. It cannot be undone.`, ok: 'Delete account', danger: true })) {
              act(() => A('DELETE', `/api/admin/users/${u.id}`), 'Account deleted');
            }
          } } }, 'Delete')));
    });
    const wrap = h('div.card', h('table.utable',
      h('thead', h('tr', h('th', 'Account'), h('th', 'Role'), h('th', 'Items'), h('th', 'Devices'), h('th', 'Last active'), h('th', ''))),
      h('tbody', rows)));
    return h('div', wrap);
  }

  async function adminInvites() {
    const { invites, now } = await A('GET', '/api/admin/invites');
    const out = h('div');
    const days = h('select.select', { style: { width: 'auto' } }, [[1, '1 day'], [7, '7 days'], [30, '30 days'], [90, '90 days']].map(([v, l]) => h('option', { value: v }, l)));
    days.value = '7';
    const created = h('div');
    const create = h('button.btn.primary.sm', { on: { click: async () => {
      try {
        const r = await A('POST', '/api/admin/invites', { days: Number(days.value) });
        clear(created).append(h('div.code-box', { style: { margin: '0 14px 14px' } }, h('span', r.code),
          h('button.tbtn', { on: { click: () => copy(r.code, 'Invite code copied', false) } }, 'Copy')));
        refreshList();
      } catch (e) {
        fail(e);
      }
    } } }, 'Create invite');
    const list = h('div');
    const paint = (items, t) => {
      clear(list);
      if (!items.length) return list.append(h('div.set-row.muted', 'No invites yet.'));
      for (const i of items) {
        const status = i.usedBy ? `Used by ${i.usedBy}` : i.expiresAt < t ? 'Expired' : `Expires ${formatDate(i.expiresAt)}`;
        list.append(h('div.set-row', h('div.grow', h('div.t.mono', { style: { fontSize: '12.5px' } }, `KH-…${i.id.slice(0, 6)}`), h('div.d', `Created ${formatDate(i.createdAt)} · ${status}`)),
          !i.usedBy && i.expiresAt >= t && h('button.tbtn', { on: { click: async () => {
            try {
              await A('DELETE', `/api/admin/invites/${i.id}`);
              toast('Invite revoked');
              refreshList();
            } catch (e) {
              fail(e);
            }
          } } }, 'Revoke')));
      }
    };
    const refreshList = async () => {
      const r = await A('GET', '/api/admin/invites').catch(() => null);
      if (r) paint(r.invites, r.now);
    };
    paint(invites, now);
    out.append(
      h('div.settings-section', h('h3', 'New invite'), h('div.card',
        h('div.set-row', h('div.grow', h('div.t', 'One-time sign-up code'), h('div.d', 'Share it with the person you want to invite. Each code works once.')), days, create),
        created)),
      h('div.settings-section', h('h3', 'Recent invites'), h('div.card', list)));
    return out;
  }

  async function adminBranding() {
    const cfg = await A('GET', '/api/admin/settings');
    const name = h('input.input', { value: cfg.name, maxlength: '40' });
    const tagline = h('input.input', { value: cfg.tagline, maxlength: '120', placeholder: 'Shown on the sign-in screen' });
    const accentText = h('input.input.mono', { value: cfg.accent, placeholder: 'none', maxlength: '7', style: { width: '110px' } });
    const accentPick = h('input.swatch', { type: 'color', value: cfg.accent || '#3b82f6' });
    const notice = h('textarea.textarea', { maxlength: '500', rows: 3, placeholder: 'Optional message shown to every signed-in user, e.g. planned maintenance.' }, cfg.notice);
    let logo = cfg.logo;
    const preview = h('div.brand-preview');
    const paintPreview = () => {
      const b = { name: name.value || 'Keyhaven', accent: accentText.value, logo };
      const ok = /^#[0-9a-f]{6}$/i.test(b.accent);
      preview.style.setProperty('--primary', ok ? b.accent : '');
      preview.style.setProperty('--primary-ink', ok ? inkFor(b.accent) : '');
      if (!ok) { preview.style.removeProperty('--primary'); preview.style.removeProperty('--primary-ink'); }
      clear(preview).append(brandMark(b, 36), h('div', h('div', { style: { fontWeight: 600, fontSize: '15px' } }, b.name), h('div.muted', tagline.value || 'Sign in to your server.')),
        h('button.btn.primary.sm', { style: { marginLeft: 'auto' } }, 'Sign in'));
    };
    [name, tagline].forEach((el) => el.addEventListener('input', paintPreview));
    accentPick.addEventListener('input', () => { accentText.value = accentPick.value; paintPreview(); });
    accentText.addEventListener('input', () => { if (/^#[0-9a-f]{6}$/i.test(accentText.value)) accentPick.value = accentText.value; paintPreview(); });
    const file = h('input', { type: 'file', accept: 'image/png,image/jpeg,image/webp,image/gif,image/x-icon', style: { display: 'none' } });
    file.addEventListener('change', async () => {
      const f = file.files[0];
      if (!f) return;
      if (f.size > 2 * 1024 * 1024) return fail(new Error('Logo must be under 2 MB'));
      const dataUrl = await new Promise((res, rej) => { const fr = new FileReader(); fr.onload = () => res(fr.result); fr.onerror = rej; fr.readAsDataURL(f); });
      try {
        const r = await A('PUT', '/api/admin/logo', { image: dataUrl });
        logo = r.logo;
        paintPreview();
        toast('Logo updated');
      } catch (e) {
        fail(e);
      }
      file.value = '';
    });
    const save = h('button.btn.primary', { on: { click: async () => {
      try {
        await A('PUT', '/api/admin/settings', { name: name.value, tagline: tagline.value, accent: accentText.value.trim(), notice: notice.value });
        await refreshStatus();
        applyBranding(S.status.branding);
        renderSidebar();
        renderNotice();
        toast('Branding saved');
      } catch (e) {
        fail(e);
      }
    } } }, 'Save branding');
    paintPreview();
    const row = (t, d, control) => h('div.set-row', h('div.grow', h('div.t', t), d && h('div.d', d)), control);
    return h('div',
      h('div.settings-section', h('h3', 'Preview'), h('div.card', preview)),
      h('div.settings-section', h('h3', 'Identity'), h('div.card',
        h('div', { style: { padding: '14px 14px 0' } },
          h('div.field', h('label.label', 'Name'), name),
          h('div.field', h('label.label', 'Tagline'), tagline)),
        row('Accent colour', 'Used for primary buttons and the logo tile. Text colour adjusts automatically.',
          h('div.row', accentPick, accentText, h('button.tbtn', { on: { click: () => { accentText.value = ''; paintPreview(); } } }, 'None'))),
        row('Logo', 'PNG, JPEG, WebP, GIF or ICO. Shown at up to 128 px.',
          h('div.row', file, h('button.btn.sm', { on: { click: () => file.click() } }, 'Upload'),
            h('button.tbtn', { on: { click: async () => {
              try {
                await A('DELETE', '/api/admin/logo');
                logo = '';
                paintPreview();
                toast('Logo removed');
              } catch (e) {
                fail(e);
              }
            } } }, 'Remove'))))),
      h('div.settings-section', h('h3', 'Announcement'), h('div.card', h('div', { style: { padding: '14px' } }, notice,
        h('div.hint', 'Users can dismiss it; changing the text shows it again.')))),
      h('div.row', { style: { justifyContent: 'flex-end' } }, save));
  }

  async function adminVerified() {
    const cfg = await A('GET', '/api/admin/settings');
    const custom = Array.isArray(cfg.verifiedDomains);
    let list = [...(custom ? cfg.verifiedDomains : DEFAULT_DOMAINS)];
    let dirty = false;
    const count = h('span.muted');
    const filter = h('input.input', { type: 'search', placeholder: 'Filter', style: { maxWidth: '200px' } });
    const chips = h('div.domain-chips');
    const paint = () => {
      const q = filter.value.trim().toLowerCase();
      clear(chips);
      const shown = list.filter((d) => !q || d.includes(q));
      for (const d of shown.slice(0, 600)) {
        chips.append(h('span.domain-chip', d, h('button', { title: `Remove ${d}`, on: { click: () => { list = list.filter((x) => x !== d); dirty = true; paint(); } } }, '×')));
      }
      if (shown.length > 600) chips.append(h('span.muted', { style: { fontSize: '12.5px', alignSelf: 'center' } }, `+${shown.length - 600} more, use the filter`));
      if (!shown.length) chips.append(h('span.muted', { style: { fontSize: '13px' } }, q ? 'No matches.' : 'No verified domains. No site will get a tick.'));
      count.textContent = `${list.length} domain${list.length === 1 ? '' : 's'}${dirty ? ' · unsaved changes' : ''}`;
    };
    filter.addEventListener('input', paint);
    const add = h('input.input', { placeholder: 'example.com, another.org', spellcheck: 'false' });
    const addNow = () => {
      const parts = add.value.split(/[\s,;]+/).map((d) => d.trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/^www\./, '')).filter(Boolean);
      const bad = parts.filter((d) => !/^[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(d));
      if (bad.length) return fail(new Error(`Not a domain: ${bad.join(', ')}`));
      list = [...new Set([...list, ...parts])].sort();
      add.value = '';
      dirty = true;
      paint();
    };
    add.addEventListener('keydown', (e) => e.key === 'Enter' && (e.preventDefault(), addNow()));
    const save = h('button.btn.primary', { on: { click: async () => {
      try {
        await A('PUT', '/api/admin/verified', { domains: list });
        dirty = false;
        paint();
        await refreshStatus();
        renderList();
        toast('Verified sites saved');
      } catch (e) {
        fail(e);
      }
    } } }, 'Save list');
    const reset = h('button.btn', { on: { click: async () => {
      if (!(await confirmBox({ title: 'Reset to the built-in list?', body: `Your custom list is replaced by Keyhaven’s ${DEFAULT_DOMAINS.length} default domains.`, ok: 'Reset' }))) return;
      try {
        await A('PUT', '/api/admin/verified', { domains: null });
        list = [...DEFAULT_DOMAINS];
        dirty = false;
        paint();
        await refreshStatus();
        renderList();
        toast('Reset to built-in list');
      } catch (e) {
        fail(e);
      }
    } } }, 'Reset to built-in');
    paint();
    return h('div',
      h('p.muted', { style: { margin: '-6px 0 18px', fontSize: '13px' } },
        'Logins for these sites get a blue tick, and so do their subdomains (accounts.google.com counts as google.com). ',
        custom ? 'This server uses a custom list.' : 'This server uses the built-in list.'),
      h('div.settings-section', h('h3', 'Add domains'), h('div.card', h('div.set-row', add, h('button.btn.sm', { on: { click: addNow } }, 'Add')))),
      h('div.settings-section', h('div.row', { style: { marginBottom: '8px' } }, h('h3', { style: { margin: 0 } }, 'Domains'), count, h('span.grow'), filter),
        h('div.card', chips)),
      h('div.row', { style: { justifyContent: 'flex-end' } }, reset, save));
  }

  async function adminServer() {
    const [cfg, o] = await Promise.all([A('GET', '/api/admin/settings'), A('GET', '/api/admin/overview')]);
    const label = { open: 'Open', invite: 'Invite only', closed: 'Closed' };
    const mode = h('select.select', [['env', `Server default (${label[o.envSignups]})`], ['open', 'Open: anyone can create an account'], ['invite', 'Invite only'], ['closed', 'Closed: no new accounts']].map(([v, l]) => h('option', { value: v }, l)));
    mode.value = cfg.signups || 'env';
    const icons = h('input', { type: 'checkbox', checked: cfg.iconsEnabled });
    const saveSetting = async (patch, msg) => {
      try {
        await A('PUT', '/api/admin/settings', patch);
        await refreshStatus();
        toast(msg);
      } catch (e) {
        fail(e);
      }
    };
    mode.addEventListener('change', () => saveSetting({ signups: mode.value }, 'Registration updated'));
    icons.addEventListener('change', () => saveSetting({ iconsEnabled: icons.checked }, icons.checked ? 'Website icons on' : 'Website icons off'));
    const row = (t, d, control) => h('div.set-row', h('div.grow', h('div.t', t), d && h('div.d', d)), control);
    return h('div',
      h('div.settings-section', h('h3', 'Registration'), h('div.card',
        row('Who can create accounts', 'The first account is always allowed. Invite-only needs a code from the Invites tab.', mode))),
      h('div.settings-section', h('h3', 'Features'), h('div.card',
        row('Website icons', 'Let this server fetch site favicons for everyone. Turning it off also stops all outgoing icon requests.', h('label.toggle', icons, h('span'))))));
  }

  // ---------- settings ----------

  function renderSettings() {
    const st = S.status;
    const set = st.settings;
    const sel = (key, options) => {
      const s = h('select.select', options.map(([v, l]) => h('option', { value: v }, l)));
      s.value = String(set[key]);
      s.addEventListener('change', async () => {
        try {
          await call('settings', { patch: { [key]: Number(s.value) } });
          await refreshStatus();
          toast('Setting saved');
        } catch (e) {
          fail(e);
        }
      });
      return s;
    };
    const tog = (key) => {
      const inp = h('input', { type: 'checkbox', checked: set[key] });
      inp.addEventListener('change', async () => {
        await call('settings', { patch: { [key]: inp.checked } }).catch(fail);
        await refreshStatus();
      });
      return h('label.toggle', inp, h('span'));
    };
    const row = (t, d, control) => h('div.set-row', h('div.grow', h('div.t', t), d && h('div.d', d)), control);

    // change password
    const cur = passwordInput({ placeholder: 'Current master password', autocomplete: 'current-password' });
    const meter = strengthMeter();
    const nxt = passwordInput({ placeholder: 'New master password', autocomplete: 'new-password' }, { onInput: (v) => meter.update(v) });
    const nxt2 = passwordInput({ placeholder: 'Repeat new master password', autocomplete: 'new-password' });
    const cpErr = h('div.error-text');
    const cpBtn = h('button.btn.primary', { type: 'submit' }, 'Change master password');
    const cpForm = h('form.cp-form', { on: { submit: async (e) => {
      e.preventDefault();
      cpErr.textContent = '';
      if (nxt.input.value !== nxt2.input.value) return (cpErr.textContent = 'New passwords don’t match');
      if (estimateStrength(nxt.input.value).score < 2) return (cpErr.textContent = 'Choose a stronger master password');
      busy(cpBtn, true, 'Re-encrypting key…');
      try {
        await call('changePassword', { current: cur.input.value, next: nxt.input.value });
        [cur, nxt, nxt2].forEach((x) => (x.input.value = ''));
        meter.update('');
        toast('Master password changed. Other devices were signed out.');
      } catch (e2) {
        cpErr.textContent = e2.message;
      }
      busy(cpBtn, false);
    } } }, h('div.field', cur.wrap), h('div.field', nxt.wrap, meter.el), h('div.field', nxt2.wrap), cpBtn, cpErr);

    // sessions
    const sessWrap = h('div', h('div.set-row', h('span.muted', 'Loading devices…')));
    const loadSessions = () => call('sessions').then((list) => {
      clear(sessWrap);
      for (const s of list) {
        sessWrap.append(row(s.device + (s.current ? ' (this device)' : ''), `Last active ${timeAgo(s.lastUsedAt)} · ${s.ip} · signed in ${formatDate(s.createdAt)}`,
          !s.current && h('button.btn.sm', { on: { click: async () => { await call('revokeSession', { id: s.id }).catch(fail); loadSessions(); toast('Device signed out'); } } }, 'Sign out')));
      }
    }).catch((e) => { clear(sessWrap).append(h('div.set-row.muted', e.message)); });
    loadSessions();

    // import / export
    const fileInput = h('input', { type: 'file', accept: '.csv,.json,text/csv,application/json', style: { display: 'none' } });
    fileInput.addEventListener('change', async () => {
      const f = fileInput.files[0];
      if (!f) return;
      try {
        const text = await f.text();
        const n = await call('import', { text, filename: f.name });
        await loadItems();
        renderSidebar();
        renderList();
        toast(`Imported ${n} item${n === 1 ? '' : 's'}`);
      } catch (e) {
        fail(e);
      }
      fileInput.value = '';
    });
    const doExport = async (format) => {
      const pw = await askPassword({ title: 'Export vault', body: `The ${format.toUpperCase()} file will contain all your passwords in plain text. Store it safely and delete it when you’re done.`, ok: 'Export' });
      if (!pw) return;
      try {
        const content = await call('export', { password: pw, format });
        const stamp = new Date().toISOString().slice(0, 10);
        backend.download(`keyhaven-export-${stamp}.${format}`, content, format === 'csv' ? 'text/csv' : 'application/json');
      } catch (e) {
        fail(e);
      }
    };

    const delAccount = async () => {
      const pw = await askPassword({ title: 'Delete account permanently?', body: 'All items will be erased from the server and every device. This cannot be undone. Enter your master password to confirm.', ok: 'Delete account' });
      if (!pw) return;
      try {
        await call('deleteAccount', { password: pw });
        await full();
        toast('Account deleted');
      } catch (e) {
        fail(e);
      }
    };

    return h('div.detail-inner', { style: { maxWidth: '760px' } },
      h('h1.page-title', 'Settings'),
      h('p.page-sub', `${st.email} on ${displayHost(st.serverUrl) || st.serverUrl}`),
      h('div.settings-section', h('h3', 'Security'), h('div.card',
        row('Auto-lock', 'Lock the vault after this much inactivity', sel('autoLockMinutes', [[1, '1 minute'], [5, '5 minutes'], [15, '15 minutes'], [30, '30 minutes'], [60, '1 hour'], [240, '4 hours'], [0, 'Never (until browser closes)']])),
        row('Clear clipboard', 'Erase copied secrets from the clipboard after', sel('clipboardClearSeconds', [[15, '15 seconds'], [30, '30 seconds'], [60, '1 minute'], [120, '2 minutes'], [0, 'Never']])),
        row('Lock now', 'Shortcut: Ctrl+L', h('button.btn.sm', { on: { click: () => call('lock').then(full) } }, icon('lock', 14), 'Lock')))),
      backend.isExtension && h('div.settings-section', h('h3', 'Browser'), h('div.card',
        row('Inline autofill menu', 'Show the Keyhaven key icon inside login fields', tog('showInlineMenu')),
        row('Offer to save logins', 'Ask to save or update passwords when you sign in to sites', tog('offerToSave')),
        row('Keyboard autofill', 'Press Ctrl+Shift+L on a login page to fill the best match', h('span.kbd', 'Ctrl+Shift+L')))),
      h('div.settings-section', h('h3', 'Appearance'), h('div.card',
        row('Website icons', 'Your Keyhaven server fetches each site’s icon directly from the site. No third-party icon service is used.', (() => {
          const t = tog('showIcons');
          t.querySelector('input').addEventListener('change', () => setTimeout(renderList, 300));
          return t;
        })()))),
      h('div.settings-section', h('h3', 'Master password'), h('div.card', cpForm)),
      h('div.settings-section', h('h3', 'Devices'), h('div.card', sessWrap)),
      h('div.settings-section', h('h3', 'Import & export'), h('div.card',
        row('Import', 'From Bitwarden (JSON/CSV), 1Password (CSV), Chrome/Helium/Brave/Edge, Firefox, LastPass or Keyhaven exports', h('div', fileInput, h('button.btn.sm', { on: { click: () => fileInput.click() } }, icon('upload', 14), 'Choose file'))),
        row('Export', 'Unencrypted backup — handle with care', h('div.row', h('button.btn.sm', { on: { click: () => doExport('json') } }, icon('download', 14), 'JSON'), h('button.btn.sm', { on: { click: () => doExport('csv') } }, icon('download', 14), 'CSV'))))),
      h('div.settings-section', h('h3', 'Keyboard shortcuts'), h('div.card', h('div.shortcut-grid',
        ...[['Search', '/'], ['New item', 'Ctrl+N'], ['Edit selected item', 'E'], ['Copy password', 'Ctrl+Shift+C'], ['Copy username', 'Ctrl+Shift+U'], ['Copy one-time code', 'Ctrl+Shift+O'], ['Save item', 'Ctrl+S'], ['Navigate list', '↑ ↓'], ['Lock', 'Ctrl+L']]
          .flatMap(([a, b]) => [h('span', a), h('span.kbd', b)])))),
      h('div.settings-section', h('h3', 'Account'), h('div.card',
        row('Sign out', 'Remove the cached vault from this device', h('button.btn.sm', { on: { click: async () => (await confirmBox({ title: 'Sign out?', body: 'The encrypted cache on this device will be deleted. Your data stays on the server.', ok: 'Sign out' })) && call('logout').then(full) } }, icon('logout', 14), 'Sign out')),
        row('Delete account', 'Permanently erase your account and all items from the server', h('button.btn.sm.danger', { on: { click: delAccount } }, 'Delete account')))),
    );
  }

  // ---------- keyboard ----------

  document.addEventListener('keydown', async (e) => {
    if (!shell || document.querySelector('.modal-back')) return;
    const typing = /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName);
    const mod = e.ctrlKey || e.metaKey;
    const it = S.items.find((i) => i.id === S.selected);
    if (mod && e.key.toLowerCase() === 'l') {
      e.preventDefault();
      await call('lock');
      return full();
    }
    if (mod && e.key.toLowerCase() === 's' && (S.mode === 'edit' || S.mode === 'new')) {
      e.preventDefault();
      return shell.detail.querySelector('form.editor')?.requestSubmit();
    }
    if (mod && !e.shiftKey && e.key.toLowerCase() === 'n') {
      e.preventDefault();
      return startNew();
    }
    if (mod && e.key.toLowerCase() === 'f') {
      e.preventDefault();
      return searchInput?.focus();
    }
    if (mod && e.shiftKey && it && S.mode === 'view') {
      const k = e.key.toLowerCase();
      if (k === 'c' && it.password) { e.preventDefault(); return copy(it.password, 'Password copied'); }
      if (k === 'u' && it.username) { e.preventDefault(); return copy(it.username, 'Username copied', false); }
      if (k === 'o' && it.totp) { e.preventDefault(); return copy((await totpCode(it.totp)).code, 'Code copied'); }
    }
    if (e.key === 'Escape' && (S.mode === 'edit' || S.mode === 'new')) return cancelEdit();
    if (typing) return;
    if (e.key === '/') {
      e.preventDefault();
      searchInput?.focus();
      searchInput?.select();
    } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      if (TOOL_VIEWS.includes(S.view)) return;
      e.preventDefault();
      moveSelection(e.key === 'ArrowDown' ? 1 : -1);
    } else if (e.key.toLowerCase() === 'e' && it && S.mode === 'view' && !it.deletedAt) {
      e.preventDefault();
      startEdit(it);
    }
  });

  window.addEventListener('beforeunload', (e) => {
    if ((S.mode === 'edit' || S.mode === 'new') && S.dirty) e.preventDefault();
  });

  // periodic sync while open
  const syncNow = async () => {
    if (!S.status?.unlocked || S.mode !== 'view') return;
    try {
      await call('sync');
    } catch {
      /* status shows offline */
    }
  };
  window.addEventListener('focus', syncNow);
  setInterval(syncNow, 120000);

  full();
}
