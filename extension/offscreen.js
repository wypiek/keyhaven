// Offscreen document: the only place a MV3 service worker can write to the clipboard.
function write(text) {
  const onCopy = (e) => {
    e.clipboardData.setData('text/plain', text);
    e.preventDefault();
  };
  document.addEventListener('copy', onCopy);
  try {
    return document.execCommand('copy');
  } finally {
    document.removeEventListener('copy', onCopy);
  }
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg?.target !== 'offscreen') return false;
  if (msg.type === 'write') sendResponse(write(String(msg.text ?? '')));
  return false;
});
