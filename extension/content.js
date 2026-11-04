// Keyhaven content script: login-form detection, inline autofill menu, filling and
// save/update prompts. All UI lives in a closed shadow root and only reacts to trusted
// (real user) events, so page scripts can't read it or click it programmatically.

(() => {
  if (globalThis.__keyhaven) return;
  globalThis.__keyhaven = true;
  // Don't decorate Keyhaven's own web vault (checked lazily: this runs at document_start).
  const ownVault = () => !!document.querySelector('meta[name="keyhaven"]');

  // ---------- messaging ----------

  let dead = false;
  function send(type, data = {}) {
    if (dead) return Promise.resolve(null);
    return new Promise((resolve) => {
      try {
        chrome.runtime.sendMessage({ type, ...data }, (r) => {
          if (chrome.runtime.lastError) return resolve(null);
          resolve(r && r.ok ? r.result : null);
        });
      } catch {
        dead = true; // extension reloaded; this script is orphaned
        teardown();
        resolve(null);
      }
    });
  }

  // ---------- field detection ----------

  const everPassword = new WeakSet();
  const USER_RE = /user|e-?mail|login|account|identifier|member|phone|handle|nick|signin|benutzer|usuario|utilisateur/i;
  const OTP_RE = /\b(otp|totp|2fa|mfa|one[-_ ]?time|verification[-_ ]?code|security[-_ ]?code|auth(entication)?[-_ ]?code|two[-_ ]?factor|passcode|token)\b/i;
  const NEWPW_RE = /new|confirm|create|repeat|retype|again|signup|sign-up|register|neu|nouveau|nuevo/i;
  const SKIP_RE = /search|query|captcha|coupon|promo|zip|postal|address|city|card|cvv|cvc|amount/i;

  function describe(el) {
    let label = '';
    if (el.id) {
      try {
        label = document.querySelector(`label[for="${CSS.escape(el.id)}"]`)?.textContent || '';
      } catch { /* ignore */ }
    }
    if (!label) label = el.closest('label')?.textContent || '';
    return [el.name, el.id, el.getAttribute('autocomplete'), el.placeholder, el.getAttribute('aria-label'), label]
      .filter(Boolean).join(' ').slice(0, 300);
  }

  function visible(el) {
    if (!el.isConnected || el.disabled || el.readOnly) return false;
    const r = el.getBoundingClientRect();
    if (r.width < 24 || r.height < 12) return false;
    const cs = getComputedStyle(el);
    return cs.visibility !== 'hidden' && cs.display !== 'none' && Number(cs.opacity) > 0.05;
  }

  const isInput = (el) => el instanceof HTMLInputElement;

  function isPassword(el) {
    if (!isInput(el)) return false;
    if (el.type === 'password') {
      everPassword.add(el);
      return true;
    }
    return everPassword.has(el) && el.type === 'text';
  }

  function isOtp(el) {
    if (!isInput(el) || !['text', 'tel', 'number', ''].includes(el.type)) return false;
    if (el.autocomplete === 'one-time-code') return true;
    const d = describe(el);
    return OTP_RE.test(d) && !USER_RE.test(d.replace(/code/gi, ''));
  }

  function isUsernameLike(el) {
    if (!isInput(el) || !['text', 'email', 'tel', ''].includes(el.type) || isOtp(el)) return false;
    const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
    if (ac.includes('username') || ac === 'email') return true;
    const d = describe(el);
    return USER_RE.test(d) && !SKIP_RE.test(d);
  }

  function isNewPassword(el, ctxPasswords) {
    const ac = (el.getAttribute('autocomplete') || '').toLowerCase();
    if (ac === 'new-password') return true;
    if (ac === 'current-password') return false;
    return NEWPW_RE.test(describe(el)) || (ctxPasswords && ctxPasswords.length >= 2);
  }

  // ---------- payment card fields ----------

  const CARD_AC = { 'cc-number': 'number', 'cc-csc': 'cvc', 'cc-name': 'name', 'cc-exp': 'exp', 'cc-exp-month': 'month', 'cc-exp-year': 'year' };
  const CARD_RE = [
    ['number', /card.?num|cc.?num|cardnumber|ccnum|kartennummer|num(e|é)ro.?de.?(la.?)?carte|n(u|ú)mero.?de.?tarjeta/i],
    ['cvc', /\b(cvc|cvv|cvv2|csc|cvn|card.?code|security.?code)\b/i],
    ['name', /name.?on.?card|card.?holder|cardholder|cc.?name|nom.?du.?titulaire/i],
    ['month', /(exp|cc).*(month|mm\b)|month.*exp/i],
    ['year', /(exp|cc).*(year|yy)|year.*exp/i],
    ['exp', /exp(iry|iration)?.?(date)?|mm.?\/.?yy|valid.?thru/i],
  ];

  function cardRole(el) {
    const isSel = el instanceof HTMLSelectElement;
    if (!isSel && !(el instanceof HTMLInputElement)) return null;
    const ac = (el.getAttribute('autocomplete') || '').toLowerCase().split(/\s+/);
    for (const t of ac) if (CARD_AC[t]) return CARD_AC[t];
    if (!isSel && !['text', 'tel', 'number', ''].includes(el.type)) return null;
    const d = describe(el);
    for (const [role, re] of CARD_RE) if (re.test(d)) return role;
    return null;
  }

  function setSelect(sel, candidates) {
    const opt = [...sel.options].find((o) => candidates.includes(o.value.trim()) || candidates.includes(o.text.trim()));
    if (!opt) return;
    sel.value = opt.value;
    sel.dispatchEvent(new Event('input', { bubbles: true }));
    sel.dispatchEvent(new Event('change', { bubbles: true }));
  }

  function fillCard(c, anchor) {
    const scope = scopeOf(anchor);
    const fields = [...scope.querySelectorAll('input, select')].filter((e) => visible(e) && cardRole(e));
    const mm = String(c.expMonth || '').padStart(2, '0');
    const yyyy = c.expYear ? (String(c.expYear).length === 2 ? `20${c.expYear}` : String(c.expYear)) : '';
    const yy = yyyy.slice(-2);
    let n = 0;
    for (const f of fields) {
      const role = cardRole(f);
      const ph = `${f.placeholder || ''} ${f.getAttribute('aria-label') || ''}`;
      let v = '';
      if (role === 'number') v = c.number;
      else if (role === 'cvc') v = c.cvv;
      else if (role === 'name') v = c.cardholder;
      else if (role === 'month') v = mm;
      else if (role === 'year') v = f.maxLength === 2 || /\byy\b/i.test(ph) ? yy : yyyy;
      else if (role === 'exp') v = /yyyy|aaaa|jjjj/i.test(ph) ? `${mm}/${yyyy}` : / \/ /.test(ph) ? `${mm} / ${yy}` : `${mm}/${yy}`;
      if (!v || (role === 'month' && !c.expMonth) || ((role === 'exp' || role === 'year') && !yyyy)) continue;
      if (f instanceof HTMLSelectElement) {
        setSelect(f, role === 'month' ? [mm, String(+mm)] : role === 'year' ? [yyyy, yy] : [v]);
      } else setValue(f, v);
      n++;
    }
    return n;
  }

  function scopeOf(el) {
    return el.form || el.closest('form, [role="form"], dialog, [role="dialog"]') || document;
  }

  function inputsIn(scope) {
    return [...scope.querySelectorAll('input')].filter(visible);
  }

  /** Locate username / password / OTP fields related to an anchor (or the whole page). */
  function context(anchor) {
    const scope = anchor ? scopeOf(anchor) : document;
    let inputs = inputsIn(scope);
    if (scope !== document && !inputs.some(isPassword) && !inputs.some(isUsernameLike)) inputs = inputsIn(document);
    const passwords = inputs.filter(isPassword);
    const firstPw = passwords[0];
    let username = null;
    if (firstPw) {
      const before = inputs.slice(0, inputs.indexOf(firstPw)).filter((i) => ['text', 'email', 'tel', ''].includes(i.type) && !isOtp(i));
      username = before.filter(isUsernameLike).pop() || before.pop() || null;
    } else {
      username = anchor && isUsernameLike(anchor) ? anchor : inputs.find(isUsernameLike) || null;
    }
    const otp = inputs.find(isOtp) || null;
    return { scope, passwords, username, otp };
  }

  function isCandidate(el) {
    return isInput(el) && visible(el) && (cardRole(el) ||isPassword(el) || isOtp(el) || isUsernameLike(el) || (context(el).passwords.length > 0 && ['text', 'email', 'tel', ''].includes(el.type) && context(el).username === el));
  }

  // ---------- filling ----------

  const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;

  function setValue(el, value) {
    if (!el || value == null) return;
    el.focus({ preventScroll: true });
    valueSetter.call(el, value);
    el.dispatchEvent(new InputEvent('input', { bubbles: true, composed: true, inputType: 'insertReplacementText', data: value }));
    el.dispatchEvent(new Event('change', { bubbles: true }));
    
  }

  function fill(creds, anchor) {
    const a = anchor || (isInput(document.activeElement) ? document.activeElement : null);
    const ctx = context(a);
    let did = false;
    if (ctx.username && creds.username) {
      setValue(ctx.username, creds.username);
      did = true;
    }
    if (creds.password) {
      const target = ctx.passwords.find((p) => !isNewPassword(p, null)) || ctx.passwords[0];
      if (target) {
        setValue(target, creds.password);
        did = true;
      }
    }
    if (creds.totp && ctx.otp && !ctx.passwords.length) {
      setValue(ctx.otp, creds.totp);
      did = true;
    }
    if (did) if (creds.totp && !ctx.otp) toast('One-time code copied');
    return did;
  }

  function fillGenerated(password, anchor) {
    const a = anchor || (isInput(document.activeElement) ? document.activeElement : null);
    const ctx = context(a);
    const targets = ctx.passwords.filter((p) => isNewPassword(p, ctx.passwords));
    const list = targets.length ? targets : a && isPassword(a) ? [a] : ctx.passwords.slice(-1);
    if (!list.length && a && isInput(a)) list.push(a);
    list.forEach((p) => setValue(p, password));
    
    return list.length > 0;
  }

  // ---------- inline UI (closed shadow root) ----------

  let host = null;
  let shadow = null;
  let badge = null;
  let menu = null;
  let banner = null;
  let activeField = null;
  let rafPending = false;

  const CSS_TEXT = `
    :host { all: initial;
      --bg: #1a1a1d; --hover: #26262b; --line: #2c2c31; --text: #ededef; --text-2: #b4b4bb; --muted: #85858e;
      --tile: #26262b; --pri: #ededef; --pri-ink: #111113; --vt: #4c8dff; --shadow: 0 1px 2px rgba(0,0,0,.3), 0 14px 36px rgba(0,0,0,.4); }
    @media (prefers-color-scheme: light) { :host {
      --bg: #ffffff; --hover: #f3f3f5; --line: #e4e4e8; --text: #18181b; --text-2: #4a4a52; --muted: #74747c;
      --tile: #f3f3f5; --pri: #18181b; --pri-ink: #ffffff; --vt: #2563eb; --shadow: 0 1px 2px rgba(16,16,24,.06), 0 14px 36px rgba(16,16,24,.14); } }
    * { box-sizing: border-box; font-family: Inter, ui-sans-serif, system-ui, -apple-system, 'Segoe UI', Roboto, sans-serif; -webkit-font-smoothing: antialiased; }
    .badge { position: fixed; width: 20px; height: 20px; border-radius: 5px; display: grid; place-items: center; cursor: pointer;
      background: var(--pri); color: var(--pri-ink); border: 0; padding: 0; pointer-events: auto; opacity: .78; transition: opacity .12s; }
    .badge:hover { opacity: 1; }
    .menu { position: fixed; width: 296px; max-height: 340px; overflow: auto; background: var(--bg); color: var(--text); border: 1px solid var(--line);
      border-radius: 10px; box-shadow: var(--shadow); padding: 4px; pointer-events: auto; font-size: 13px; animation: in .12s ease; }
    @keyframes in { from { opacity: 0; transform: translateY(-3px); } }
    .head { padding: 8px 10px 4px; font-size: 11.5px; font-weight: 500; color: var(--muted); }
    .row { display: flex; align-items: center; gap: 10px; padding: 7px 8px; border-radius: 6px; cursor: pointer; border: 0; background: none; color: inherit; width: 100%; text-align: left; font-size: 13px; }
    .row:hover, .row.sel { background: var(--hover); }
    .av { width: 28px; height: 28px; border-radius: 7px; display: grid; place-items: center; background: var(--tile); color: var(--text-2); font-weight: 600; flex: none; font-size: 12px; }
    .t { font-weight: 500; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .s { color: var(--muted); font-size: 12px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; margin-top: 1px; }
    .g { flex: 1; min-width: 0; }
    .pw { font-family: ui-monospace, 'JetBrains Mono', monospace; font-size: 12px; color: var(--text-2); word-break: break-all; }
    .msg { padding: 8px 10px; color: var(--text-2); line-height: 1.45; }
    .btn { height: 28px; padding: 0 12px; border-radius: 6px; border: 1px solid var(--line); background: transparent; color: var(--text); cursor: pointer; font-size: 13px; font-weight: 500; }
    .btn:hover { background: var(--hover); }
    .btn.p { background: var(--pri); border-color: var(--pri); color: var(--pri-ink); }
    .btn.p:hover { opacity: .9; }
    .foot { border-top: 1px solid var(--line); margin-top: 4px; padding-top: 4px; }
    .banner, .dialog { position: fixed; top: 14px; width: 336px; background: var(--bg); color: var(--text); border: 1px solid var(--line); border-radius: 12px;
      box-shadow: var(--shadow); padding: 14px; pointer-events: auto; font-size: 13px; animation: in .16s ease; }
    .banner { right: 14px; }
    .dialog { left: 50%; transform: translateX(-50%); animation: inc .16s ease; }
    @keyframes inc { from { opacity: 0; transform: translate(-50%, -3px); } }
    .banner .top, .dialog .top { display: flex; gap: 10px; align-items: flex-start; margin-bottom: 12px; }
    .banner .av { display: none; }
    .banner h4, .dialog h4 { margin: 0 0 3px; font-size: 14px; font-weight: 600; letter-spacing: -0.01em; }
    .banner p, .dialog p { margin: 0; color: var(--muted); font-size: 12.5px; word-break: break-word; line-height: 1.45; }
    .banner .acts, .dialog .acts { display: flex; gap: 6px; justify-content: flex-end; flex-wrap: wrap; margin-top: 8px; }
    .dialog .row { margin: 0 -6px; width: calc(100% + 12px); }
    .vt { color: var(--vt); white-space: nowrap; font-weight: 500; }
    .x { margin-left: auto; background: none; border: 0; color: var(--muted); cursor: pointer; font-size: 17px; line-height: 1; padding: 0 2px; border-radius: 4px; }
    .x:hover { color: var(--text); }
    .toast { position: fixed; bottom: 18px; left: 50%; transform: translateX(-50%); background: var(--pri); color: var(--pri-ink); padding: 8px 14px;
      border-radius: 8px; font-size: 13px; font-weight: 500; pointer-events: none; box-shadow: var(--shadow); animation: inc .16s ease; }
    svg { display: block; }
  `;

  function el(tag, cls, text) {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
  }

  function keySvg(size = 14) {
    const ns = 'http://www.w3.org/2000/svg';
    const s = document.createElementNS(ns, 'svg');
    s.setAttribute('viewBox', '0 0 64 64');
    s.setAttribute('width', size);
    s.setAttribute('height', size);
    const p = document.createElementNS(ns, 'path');
    p.setAttribute('d', 'M32 20a7 7 0 0 0-3.5 13.06L26 44h12l-2.5-10.94A7 7 0 0 0 32 20z');
    p.setAttribute('fill', 'currentColor');
    const p2 = document.createElementNS(ns, 'path');
    p2.setAttribute('d', 'M32 4 8 13v17c0 15 10.4 25.6 24 30 13.6-4.4 24-15 24-30V13L32 4z');
    p2.setAttribute('fill', 'none');
    p2.setAttribute('stroke', 'currentColor');
    p2.setAttribute('stroke-width', '5');
    s.append(p2, p);
    return s;
  }

  function ensureHost() {
    if (host?.isConnected) return;
    host = document.createElement('keyhaven-ui');
    host.style.cssText = 'all:initial;position:fixed;top:0;left:0;width:0;height:0;z-index:2147483647;pointer-events:none;';
    shadow = host.attachShadow({ mode: 'closed' });
    const style = document.createElement('style');
    style.textContent = CSS_TEXT;
    shadow.append(style);
    document.documentElement.append(host);
  }

  function teardown() {
    host?.remove();
    host = shadow = badge = menu = banner = null;
  }

  function trusted(fn) {
    return (e) => {
      if (!e.isTrusted) return;
      e.preventDefault();
      e.stopPropagation();
      fn(e);
    };
  }

  function toast(text) {
    ensureHost();
    const t = el('div', 'toast', text);
    shadow.append(t);
    setTimeout(() => t.remove(), 2200);
  }

  function position() {
    rafPending = false;
    if (!activeField || !activeField.isConnected) return hideBadge();
    const r = activeField.getBoundingClientRect();
    if (badge) {
      const size = Math.min(22, Math.max(16, r.height - 10));
      badge.style.width = badge.style.height = `${size}px`;
      badge.style.left = `${r.right - size - 7}px`;
      badge.style.top = `${r.top + (r.height - size) / 2}px`;
      badge.style.display = r.bottom < 0 || r.top > innerHeight ? 'none' : 'grid';
    }
    if (menu) {
      const below = r.bottom + 6 + 300 < innerHeight || r.top < 320;
      menu.style.left = `${Math.max(8, Math.min(innerWidth - 308, r.left))}px`;
      menu.style.top = below ? `${r.bottom + 6}px` : '';
      menu.style.bottom = below ? '' : `${innerHeight - r.top + 6}px`;
    }
  }
  const schedule = () => {
    if (!rafPending && (badge || menu)) {
      rafPending = true;
      requestAnimationFrame(position);
    }
  };
  addEventListener('scroll', schedule, true);
  addEventListener('resize', schedule);

  function showBadge(field) {
    ensureHost();
    activeField = field;
    if (!badge) {
      badge = el('button', 'badge');
      badge.title = 'Keyhaven';
      badge.append(keySvg(13));
      badge.addEventListener('mousedown', (e) => e.isTrusted && e.preventDefault()); // keep focus in field
      badge.addEventListener('click', trusted(() => (menu ? closeMenu() : openMenu(activeField))));
      shadow.append(badge);
    }
    position();
  }

  function hideBadge() {
    badge?.remove();
    badge = null;
    closeMenu();
    activeField = null;
  }

  function closeMenu() {
    menu?.remove();
    menu = null;
  }

  let selIndex = -1;
  const rowActions = new WeakMap();

  async function openCardMenu(field) {
    const q = await send('cs:cards');
    if (!q || field !== activeField) return;
    closeMenu();
    ensureHost();
    menu = el('div', 'menu');
    menu.addEventListener('mousedown', (e) => e.isTrusted && e.preventDefault());
    const add = (title, sub, fn, avatarText) => {
      const row = el('button', 'row');
      const av = el('div', 'av');
      if (avatarText) av.textContent = avatarText;
      else av.append(keySvg(15));
      const g = el('div', 'g');
      g.append(el('div', 't', title));
      if (sub) g.append(el('div', 's', sub));
      row.append(av, g);
      row.addEventListener('click', trusted(fn));
      rowActions.set(row, fn);
      menu.append(row);
    };
    if (q.state !== 'unlocked') {
      menu.append(el('div', 'msg', q.state === 'locked' ? 'Keyhaven is locked.' : 'You are not signed in to Keyhaven.'));
      add(q.state === 'locked' ? 'Unlock' : 'Sign in', null, () => { closeMenu(); send('cs:openPopup'); });
    } else if (!q.cards.length) {
      menu.append(el('div', 'msg', 'No cards saved. Add one in the Keyhaven vault.'));
    } else {
      menu.append(el('div', 'head', 'Cards'));
      for (const c of q.cards) {
        add(c.title, `•••• ${c.last4}${c.holder ? ` · ${c.holder}` : ''}`, async () => {
          closeMenu();
          const data = await send('cs:fillCard', { id: c.id });
          if (data) fillCard(data, field);
        }, '▭');
      }
    }
    shadow.append(menu);
    selIndex = -1;
    position();
  }

  async function openMenu(field, auto = false) {
    if (cardRole(field)) return auto ? undefined : openCardMenu(field);
    const q = await send('cs:query');
    if (!q || field !== activeField) return;
    if (auto && (q.state !== 'unlocked' || !q.logins.length)) return;
    closeMenu();
    ensureHost();
    menu = el('div', 'menu');
    menu.addEventListener('mousedown', (e) => e.isTrusted && e.preventDefault());
    const ctx = context(field);
    const wantsNew = isPassword(field) && isNewPassword(field, ctx.passwords);
    const otpField = isOtp(field);

    const addRow = (title, sub, onPick, avatarText) => {
      const row = el('button', 'row');
      const av = el('div', 'av');
      if (avatarText) av.textContent = avatarText;
      else av.append(keySvg(15));
      const g = el('div', 'g');
      g.append(el('div', 't', title));
      if (sub) g.append(sub instanceof Node ? sub : el('div', 's', sub));
      row.append(av, g);
      row.addEventListener('click', trusted(onPick));
      rowActions.set(row, onPick);
      menu.append(row);
      return row;
    };

    if (q.state === 'signedOut' || q.state === 'locked') {
      menu.append(el('div', 'msg', q.state === 'locked' ? 'Keyhaven is locked.' : 'You are not signed in to Keyhaven.'));
      addRow(q.state === 'locked' ? 'Unlock' : 'Sign in', null, () => {
        closeMenu();
        send('cs:openPopup');
      });
    } else {
      if (wantsNew) {
        const pw = await send('cs:generate');
        if (pw) {
          
          addRow('Use generated password', el('div', 'pw', pw), () => {
            closeMenu();
            fillGenerated(pw, field);
          });
        }
      }
      if (conditional && !otpField && !wantsNew) {
        const req = conditional;
        menu.append(el('div', 'head', 'Passkeys'));
        for (const c of req.candidates) {
          addRow(c.userName || c.title, `Passkey · ${c.title}`, () => {
            closeMenu();
            conditional = null;
            usePasskey(req.id, req.options, c.credentialId);
          });
        }
      }
      const logins = otpField ? q.logins.filter((l) => l.hasTotp) : q.logins;
      if (logins.length) {
        menu.append(el('div', 'head', otpField ? 'One-time codes' : location.hostname.replace(/^www\./, '')));
        for (const l of logins) {
          addRow(l.title || l.host, l.username || l.host, async () => {
            closeMenu();
            if (otpField) {
              const code = await send('cs:totp', { id: l.id });
              if (code) setValue(field, code);
            } else {
              const creds = await send('cs:fill', { id: l.id });
              if (creds) fill(creds, field);
            }
          }, (l.title || l.host || '?').charAt(0).toUpperCase());
        }
      } else if (!wantsNew && !conditional) {
        menu.append(el('div', 'msg', 'Nothing saved for this site.'));
      }
    }
    const foot = el('div', 'foot');
    const open = el('button', 'row');
    open.append(el('div', 's', 'Open Keyhaven'));
    const openPopup = () => {
      closeMenu();
      send('cs:openPopup');
    };
    open.addEventListener('click', trusted(openPopup));
    rowActions.set(open, openPopup);
    foot.append(open);
    menu.append(foot);
    shadow.append(menu);
    selIndex = -1;
    position();
  }

  function menuRows() {
    return menu ? [...menu.querySelectorAll('.row')] : [];
  }

  document.addEventListener('keydown', (e) => {
    if (!e.isTrusted || e.target !== activeField) return;
    if (!menu) {
      if (e.key === 'ArrowDown' && e.altKey) openMenu(activeField);
      return;
    }
    const rows = menuRows();
    if (e.key === 'Escape') {
      closeMenu();
      e.preventDefault();
    } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      selIndex = (selIndex + (e.key === 'ArrowDown' ? 1 : -1) + rows.length) % rows.length;
      rows.forEach((r, i) => r.classList.toggle('sel', i === selIndex));
    } else if (e.key === 'Enter' && selIndex >= 0) {
      e.preventDefault();
      e.stopPropagation();
      rowActions.get(rows[selIndex])?.(); // the keydown itself was trusted
    }
  }, true);

  let lastQuery = { t: 0, r: null };
  async function cachedQuery() {
    if (Date.now() - lastQuery.t < 3000) return lastQuery.r;
    lastQuery = { t: Date.now(), r: await send('cs:query') };
    return lastQuery.r;
  }

  const autoOpened = new WeakSet();
  document.addEventListener('focusin', async (e) => {
    if (!e.isTrusted) return;
    const f = e.composedPath()[0];
    if (!isInput(f) || ownVault() || !isCandidate(f)) return;
    const q = await cachedQuery();
    if (!q || !q.inline) return;
    showBadge(f);
    const ctxF = context(f);
    const signup = ctxF.passwords.length >= 2 || ctxF.passwords.some((p) => isNewPassword(p, null));
    if (!f.value && !autoOpened.has(f) && q.state === 'unlocked' && (q.logins.length || conditional) && !isOtp(f) && !signup && !cardRole(f)) {
      autoOpened.add(f);
      openMenu(f, true);
    }
  }, true);

  document.addEventListener('focusout', (e) => {
    if (e.composedPath()[0] !== activeField) return;
    setTimeout(() => {
      if (document.activeElement !== activeField) hideBadge();
    }, 150);
  }, true);

  document.addEventListener('mousedown', (e) => {
    if (menu && !e.composedPath().includes(host) && e.composedPath()[0] !== activeField) closeMenu();
  }, true);

  // ---------- capture on submit ----------

  const capturedValues = new Set();

  function capture(scopeHint) {
    const ctx = context(scopeHint);
    const pws = ctx.passwords.map((p) => p.value).filter(Boolean);
    let password = '';
    if (pws.length === 1) password = pws[0];
    else if (pws.length >= 2) {
      // change-password / signup: the repeated value is the new password
      const last = pws[pws.length - 1];
      password = pws.filter((v) => v === last).length >= 2 ? last : pws[pws.length - 1];
    }
    const username = ctx.username?.value?.trim() || '';
    if (!password && !username) return;
    const key = `${username}\u0000${password}`;
    if (capturedValues.has(key)) return;
    capturedValues.add(key);
    send('cs:captured', { username, password }).then(() => {
      if (password) setTimeout(checkSave, 1800);
    });
  }

  document.addEventListener('submit', (e) => e.target instanceof HTMLFormElement && capture(e.target.querySelector('input') || null), true);
  document.addEventListener('click', (e) => {
    if (!e.isTrusted) return;
    const b = e.composedPath().find((n) => n instanceof Element && n.matches?.('button, input[type="submit"], input[type="button"], [role="button"], a'));
    if (!b) return;
    const scope = b.closest('form') || document;
    const hasLogin = [...scope.querySelectorAll('input')].some((i) => (isPassword(i) || isUsernameLike(i)) && i.value);
    const text = (b.textContent || b.value || '').toLowerCase();
    if (hasLogin && (b.type === 'submit' || /log ?in|sign ?in|sign ?up|continue|next|submit|register|create|save|weiter|anmelden|connexion|entrar/.test(text))) {
      capture(scope.querySelector('input'));
    }
  }, true);
  document.addEventListener('keydown', (e) => {
    if (e.isTrusted && e.key === 'Enter' && isInput(e.target) && (isPassword(e.target) || isUsernameLike(e.target)) && !menu) capture(e.target);
  }, true);

  // ---------- save banner ----------

  async function checkSave() {
    if (window !== window.top || ownVault()) return;
    const p = await send('cs:checkSave');
    if (!p || banner) return;
    ensureHost();
    banner = el('div', 'banner');
    const top = el('div', 'top');
    const av = el('div', 'av');
    av.append(keySvg(16));
    const g = el('div', 'g');
    const titles = { save: 'Save login?', update: 'Update password?', locked: 'Keyhaven is locked' };
    g.append(el('h4', null, titles[p.kind]));
    const line = el('p', null, p.kind === 'update' ? `${p.title} · ${p.username || p.host}` : `${p.username || '(no username)'} · ${p.host}`);
    if (p.verified) {
      const v = el('span', 'vt', ' ✓ verified');
      v.title = `${p.verified} is a well-known website`;
      line.append(v);
    }
    g.append(line);
    const x = el('button', 'x', '×');
    x.title = 'Not now';
    x.addEventListener('click', trusted(() => decide('dismiss')));
    top.append(av, g, x);
    const acts = el('div', 'acts');
    const mk = (label, action, primary) => {
      const b = el('button', primary ? 'btn p' : 'btn', label);
      b.addEventListener('click', trusted(() => decide(action)));
      acts.append(b);
    };
    if (p.kind === 'locked') {
      mk('Not now', 'dismiss');
      mk('Unlock', 'unlock', true);
    } else if (p.kind === 'update') {
      mk('Not now', 'dismiss');
      mk('Update', 'save', true);
    } else {
      mk('Never here', 'never');
      mk('Save', 'save', true);
    }
    banner.append(top, acts);
    shadow.append(banner);
  }

  async function decide(action) {
    if (action === 'unlock') {
      send('cs:openPopup');
      banner?.remove();
      banner = null;
      return;
    }
    const r = await send('cs:saveDecision', { action });
    banner?.remove();
    banner = null;
    if (r?.saved) toast(r.updated ? `Updated ${r.title}` : `Saved ${r.title} to Keyhaven`);
  }

  // ---------- passkeys (requests from webauthn.js in the page world) ----------

  let conditional = null; // pending conditional-mediation get(), offered in the inline menu
  let dialog = null;
  let dialogId = null;
  const reply = (id, data) => window.postMessage({ __keyhaven: 'res', id, ...data }, location.origin);
  const cancelled = (id) => reply(id, { error: { name: 'NotAllowedError', message: 'The operation either timed out or was not allowed.' } });

  function closeDialog(id) {
    if (id && dialogId !== id) return;
    dialog?.remove();
    dialog = null;
    dialogId = null;
  }

  function showDialog(id, { title, text, choices = [], actions = [], onClose }) {
    closeDialog();
    ensureHost();
    dialog = el('div', 'dialog');
    dialogId = id;
    const top = el('div', 'top');
    const g = el('div', 'g');
    g.append(el('h4', null, title));
    if (text) g.append(el('p', null, text));
    const x = el('button', 'x', '×');
    x.title = 'Cancel';
    x.addEventListener('click', trusted(() => {
      closeDialog();
      onClose?.();
    }));
    top.append(g, x);
    dialog.append(top);
    for (const [t, sub, fn] of choices) {
      const row = el('button', 'row');
      const av = el('div', 'av', (t || '?').charAt(0).toUpperCase());
      const gg = el('div', 'g');
      gg.append(el('div', 't', t));
      if (sub && sub !== t) gg.append(el('div', 's', sub));
      row.append(av, gg);
      row.addEventListener('click', trusted(() => {
        closeDialog();
        fn();
      }));
      dialog.append(row);
    }
    const acts = el('div', 'acts');
    for (const [label, fn, primary, keepOpen] of actions) {
      const b = el('button', primary ? 'btn p' : 'btn', label);
      b.addEventListener('click', trusted(() => {
        if (!keepOpen) closeDialog();
        fn();
      }));
      acts.append(b);
    }
    dialog.append(acts);
    shadow.append(dialog);
  }

  function lockedDialog(id, what, retry) {
    showDialog(id, {
      title: 'Keyhaven is locked',
      text: `Unlock Keyhaven to ${what}, then press Continue.`,
      actions: [
        ['Use another device', () => reply(id, { fallback: true })],
        ['Unlock', () => {
          send('cs:openPopup');
          showDialog(id, {
            title: 'Keyhaven is locked',
            text: `Unlock Keyhaven in the popup, then press Continue.`,
            actions: [['Use another device', () => reply(id, { fallback: true })], ['Continue', retry, true]],
            onClose: () => cancelled(id),
          });
        }, true, true],
      ],
      onClose: () => cancelled(id),
    });
  }

  async function usePasskey(id, options, credentialId) {
    const r = await send('cs:passkeyGet', { options, credentialId });
    reply(id, r || { error: { name: 'NotAllowedError', message: 'Keyhaven could not use this passkey.' } });
    if (r?.result) toast('Signed in with passkey');
  }

  async function passkeyCreateFlow(id, options) {
    const prep = await send('cs:passkeyCreatePrepare', { options });
    if (!prep || prep.fallback) return reply(id, { fallback: true });
    if (prep.locked) return lockedDialog(id, 'save a passkey', () => passkeyCreateFlow(id, options));
    if (prep.excluded) return reply(id, { error: { name: 'InvalidStateError', message: 'This account already has a passkey in Keyhaven.' } });
    showDialog(id, {
      title: 'Save passkey?',
      text: `${prep.userName || 'This account'} on ${prep.rpId}${prep.replaces ? '. This replaces the passkey already saved.' : ''}`,
      actions: [
        ['Use another device', () => reply(id, { fallback: true })],
        ['Save passkey', async () => {
          const r = await send('cs:passkeyCreate', { options });
          reply(id, r || { error: { name: 'NotAllowedError', message: 'Keyhaven could not save the passkey.' } });
          if (r?.result) toast('Passkey saved to Keyhaven');
        }, true],
      ],
      onClose: () => cancelled(id),
    });
  }

  async function passkeyGetFlow(id, options) {
    const prep = await send('cs:passkeyGetPrepare', { options });
    if (options.mediation === 'conditional') {
      if (!prep || prep.fallback || prep.locked) return reply(id, { fallback: true });
      conditional = { id, options, candidates: prep.candidates };
      lastQuery.t = 0;
      return;
    }
    if (!prep || prep.fallback) return reply(id, { fallback: true });
    if (prep.locked) return lockedDialog(id, 'sign in with a passkey', () => passkeyGetFlow(id, options));
    showDialog(id, {
      title: `Sign in to ${prep.rpId}`,
      text: 'Choose a passkey saved in Keyhaven.',
      choices: prep.candidates.map((c) => [c.userName || c.title, c.title, () => usePasskey(id, options, c.credentialId)]),
      actions: [['Use another device', () => reply(id, { fallback: true })]],
      onClose: () => cancelled(id),
    });
  }

  window.addEventListener('message', (e) => {
    if (e.source !== window || !e.data || e.data.__keyhaven !== 'req' || typeof e.data.id !== 'string') return;
    const { id, kind, options } = e.data;
    if (kind === 'cancel') {
      if (conditional?.id === id) conditional = null;
      closeDialog(id);
    } else if (kind === 'create' && options) passkeyCreateFlow(id, options);
    else if (kind === 'get' && options) passkeyGetFlow(id, options);
  });

  // ---------- background commands ----------

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type === 'bg:fill') {
      if (msg.origin !== location.origin) return sendResponse(false);
      sendResponse(fill(msg));
    } else if (msg.type === 'bg:autofill') {
      const ctx = context(isInput(document.activeElement) ? document.activeElement : null);
      if (!ctx.passwords.length && !ctx.username && !ctx.otp) return sendResponse(false);
      send('cs:fillBest').then((creds) => {
        if (creds) fill(creds);
        else if (window === window.top) toast('No matching login in Keyhaven');
      });
      sendResponse(true);
    } else if (msg.type === 'bg:fillGenerated') {
      sendResponse(fillGenerated(msg.password));
    }
  });

  if (window === window.top) {
    if (document.readyState === 'complete') setTimeout(checkSave, 400);
    else addEventListener('load', () => setTimeout(checkSave, 400), { once: true });
  }
})();
