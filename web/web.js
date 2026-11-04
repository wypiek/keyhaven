// Web vault entry: VaultClient runs in the page; the key lives only in memory.
import { VaultClient } from './shared/vault.js';
import { dispatch } from './shared/rpc.js';
import { deviceName } from './shared/device.js';
import { mountApp } from './ui/app.js';
import { h, logo } from './ui/dom.js';

const root = document.getElementById('app');

if (!window.isSecureContext || !crypto.subtle) {
  root.append(h('div.auth', h('div.auth-card', h('div.auth-brand', h('h1', 'HTTPS required')),
    h('p.muted', 'Browsers only allow the cryptography Keyhaven uses on https:// pages or localhost. Serve this server over HTTPS and reload.'))));
} else {
  const local = {
    get: async (k) => JSON.parse(localStorage.getItem(`kh.${k}`) ?? 'null'),
    set: async (k, v) => localStorage.setItem(`kh.${k}`, JSON.stringify(v)),
    remove: async (k) => localStorage.removeItem(`kh.${k}`),
  };
  const mem = new Map();
  const memory = { get: async (k) => mem.get(k), set: async (k, v) => void mem.set(k, v), remove: async (k) => void mem.delete(k) };
  const listeners = new Set();
  const vault = new VaultClient({
    storage: local,
    session: memory,
    deviceName: deviceName('web vault'),
    onChange: (e) => listeners.forEach((f) => f(e)),
  });
  setInterval(() => vault.checkAutoLock(), 15000);
  ['mousedown', 'keydown'].forEach((ev) => document.addEventListener(ev, () => vault.unlocked && vault.touch(), { passive: true }));

  let clipTimer;
  mountApp(root, {
    call: (m, p) => dispatch(vault, m, p),
    onEvent: (f) => listeners.add(f),
    async copy(text, sensitive) {
      await navigator.clipboard.writeText(text);
      clearTimeout(clipTimer);
      const secs = vault.settings.clipboardClearSeconds;
      if (sensitive && secs) {
        clipTimer = setTimeout(async () => {
          try {
            if ((await navigator.clipboard.readText()) === text) await navigator.clipboard.writeText('');
          } catch {
            navigator.clipboard.writeText('').catch(() => {});
          }
        }, secs * 1000);
      }
    },
    download(name, content, mime) {
      const url = URL.createObjectURL(new Blob([content], { type: mime }));
      const a = h('a', { href: url, download: name });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 5000);
    },
    openUrl: (url) => /^https?:/i.test(url) && window.open(url, '_blank', 'noopener,noreferrer'),
    isExtension: false,
    fixedServer: location.origin,
  });
}
