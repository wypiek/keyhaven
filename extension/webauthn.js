// Runs in the page's MAIN world at document_start. Wraps navigator.credentials so
// Keyhaven can act as a passkey provider. Requests are forwarded to Keyhaven's
// isolated content script, which asks the user and talks to the extension. If
// Keyhaven can't or shouldn't handle a request, the browser's own WebAuthn runs instead.
(() => {
  if (!window.isSecureContext || !navigator.credentials || !window.PublicKeyCredential || window.__keyhavenWebAuthn) return;
  Object.defineProperty(window, '__keyhavenWebAuthn', { value: true });

  const native = {
    create: navigator.credentials.create.bind(navigator.credentials),
    get: navigator.credentials.get.bind(navigator.credentials),
  };

  const enc = (bytes) => {
    let s = '';
    for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  const dec = (str) => {
    const s = str.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(s + '='.repeat((4 - (s.length % 4)) % 4));
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  };
  const bytes = (src) => {
    if (src instanceof ArrayBuffer) return new Uint8Array(src);
    if (ArrayBuffer.isView(src)) return new Uint8Array(src.buffer, src.byteOffset, src.byteLength);
    throw new TypeError('expected BufferSource');
  };
  const b64u = (src) => enc(bytes(src));
  const descs = (list) => (list || []).map((d) => ({ type: d.type, id: b64u(d.id), transports: d.transports || [] }));

  function serializeCreate(pk) {
    return {
      rp: { id: pk.rp?.id, name: pk.rp?.name },
      user: { id: b64u(pk.user.id), name: pk.user.name, displayName: pk.user.displayName },
      challenge: b64u(pk.challenge),
      pubKeyCredParams: (pk.pubKeyCredParams || []).map((p) => ({ type: p.type, alg: p.alg })),
      excludeCredentials: descs(pk.excludeCredentials),
      authenticatorSelection: pk.authenticatorSelection || {},
      attestation: pk.attestation || 'none',
    };
  }

  function serializeGet(pk) {
    return {
      rpId: pk.rpId,
      challenge: b64u(pk.challenge),
      allowCredentials: descs(pk.allowCredentials),
      userVerification: pk.userVerification || 'preferred',
    };
  }

  const pending = new Map();
  window.addEventListener('message', (e) => {
    if (e.source !== window || !e.data || e.data.__keyhaven !== 'res') return;
    const done = pending.get(e.data.id);
    if (done) {
      pending.delete(e.data.id);
      done(e.data);
    }
  });

  function ask(kind, options, signal) {
    return new Promise((resolve, reject) => {
      const id = `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`;
      pending.set(id, resolve);
      if (signal) {
        if (signal.aborted) return reject(new DOMException('The operation was aborted.', 'AbortError'));
        signal.addEventListener('abort', () => {
          pending.delete(id);
          window.postMessage({ __keyhaven: 'req', id, kind: 'cancel' }, location.origin);
          reject(new DOMException('The operation was aborted.', 'AbortError'));
        }, { once: true });
      }
      window.postMessage({ __keyhaven: 'req', id, kind, options }, location.origin);
    });
  }

  const define = (obj, props) => {
    for (const [k, v] of Object.entries(props)) Object.defineProperty(obj, k, { value: v, enumerable: true });
    return obj;
  };

  function credential(r, kind) {
    const isCreate = kind === 'create';
    const response = Object.create((isCreate ? AuthenticatorAttestationResponse : AuthenticatorAssertionResponse).prototype);
    if (isCreate) {
      define(response, {
        clientDataJSON: dec(r.clientDataJSON),
        attestationObject: dec(r.attestationObject),
        getTransports: () => [...r.transports],
        getAuthenticatorData: () => dec(r.authenticatorData),
        getPublicKey: () => dec(r.publicKey),
        getPublicKeyAlgorithm: () => r.publicKeyAlgorithm,
      });
    } else {
      define(response, {
        clientDataJSON: dec(r.clientDataJSON),
        authenticatorData: dec(r.authenticatorData),
        signature: dec(r.signature),
        userHandle: r.userHandle ? dec(r.userHandle) : null,
      });
    }
    const json = () => ({
      id: r.id,
      rawId: r.rawId,
      type: 'public-key',
      authenticatorAttachment: 'platform',
      clientExtensionResults: isCreate ? { credProps: { rk: true } } : {},
      response: isCreate
        ? { clientDataJSON: r.clientDataJSON, attestationObject: r.attestationObject, authenticatorData: r.authenticatorData,
            transports: r.transports, publicKey: r.publicKey, publicKeyAlgorithm: r.publicKeyAlgorithm }
        : { clientDataJSON: r.clientDataJSON, authenticatorData: r.authenticatorData, signature: r.signature, userHandle: r.userHandle },
    });
    return define(Object.create(PublicKeyCredential.prototype), {
      id: r.id,
      rawId: dec(r.rawId),
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response,
      getClientExtensionResults: () => (isCreate ? { credProps: { rk: true } } : {}),
      toJSON: json,
    });
  }

  async function handle(kind, options) {
    let ser;
    try {
      ser = kind === 'create' ? serializeCreate(options.publicKey) : serializeGet(options.publicKey);
      if (kind === 'get') ser.mediation = options.mediation || 'optional';
    } catch {
      return native[kind](options);
    }
    const res = await ask(kind, ser, options.signal);
    if (res.fallback) return native[kind](options);
    if (res.error) throw new DOMException(res.error.message || 'The operation failed.', res.error.name || 'NotAllowedError');
    return credential(res.result, kind);
  }

  navigator.credentials.create = function create(options) {
    if (!options || !options.publicKey) return native.create(options);
    return handle('create', options);
  };
  navigator.credentials.get = function get(options) {
    if (!options || !options.publicKey) return native.get(options);
    return handle('get', options);
  };

  // Advertise a platform authenticator so sites offer passkeys.
  try {
    PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable = async () => true;
    PublicKeyCredential.isConditionalMediationAvailable = async () => true;
  } catch {
    /* read-only in some browsers */
  }
})();
