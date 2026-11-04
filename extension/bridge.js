// Messaging bridge from extension pages (popup, vault tab) to the service worker.
export async function rpc(type, data = {}) {
  let r;
  try {
    r = await chrome.runtime.sendMessage({ type, ...data });
  } catch (e) {
    throw new Error(`Keyhaven background is not responding (${e.message})`);
  }
  if (!r) throw new Error('Keyhaven background is not responding');
  if (!r.ok) throw new Error(r.error);
  return r.result;
}

const listeners = new Set();
chrome.runtime.onMessage.addListener((msg) => {
  if (msg?.type === 'kh:event') listeners.forEach((f) => f(msg.evt));
});

export const backend = {
  call: (method, params) => rpc('kh:rpc', { method, params }),
  onEvent: (f) => listeners.add(f),
  copy: (text, sensitive) => rpc('kh:copy', { text, sensitive }),
  download(name, content, mime) {
    const url = URL.createObjectURL(new Blob([content], { type: mime }));
    const a = document.createElement('a');
    a.href = url;
    a.download = name;
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
  },
  openUrl: (url) => /^https?:/i.test(url) && chrome.tabs.create({ url }),
  isExtension: true,
  lastServer: () => localStorage.getItem('keyhaven.server') || '',
  rememberServer: (u) => localStorage.setItem('keyhaven.server', u),
};
