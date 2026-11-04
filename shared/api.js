// Thin HTTP client for keyhaven-server.

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const LOCAL_HOSTS = /^(localhost|127(\.\d+){3}|\[::1\])$/i;

/** Normalise a user-entered server URL. Plain HTTP is only accepted for localhost unless allowInsecure. */
export function normalizeServerUrl(input, allowInsecure = false) {
  let s = String(input || '').trim();
  if (!s) throw new Error('Enter your server URL');
  if (!/^[a-z]+:\/\//i.test(s)) s = (/^(localhost|127\.|\[::1\])/i.test(s) ? 'http://' : 'https://') + s;
  let u;
  try {
    u = new URL(s);
  } catch {
    throw new Error('That does not look like a valid URL');
  }
  if (u.protocol !== 'https:' && u.protocol !== 'http:') throw new Error('Server URL must start with https://');
  if (u.protocol === 'http:' && !LOCAL_HOSTS.test(u.hostname) && !allowInsecure) {
    throw new Error('Use https:// for remote servers (plain HTTP exposes your session to the network)');
  }
  return (u.origin + u.pathname).replace(/\/+$/, '');
}

export class Api {
  constructor(baseUrl, token = null) {
    this.baseUrl = baseUrl;
    this.token = token;
  }

  async request(method, path, body) {
    const headers = { Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    if (this.token) headers.Authorization = `Bearer ${this.token}`;
    let res;
    try {
      res = await fetch(this.baseUrl + path, {
        method,
        headers,
        body: body === undefined ? undefined : JSON.stringify(body),
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
      });
    } catch {
      throw new ApiError(0, `Can't reach server at ${this.baseUrl}`);
    }
    let json = null;
    try {
      json = await res.json();
    } catch {
      /* non-JSON */
    }
    if (!res.ok) throw new ApiError(res.status, (json && json.error) || `Server error (${res.status})`);
    if (!json) throw new ApiError(res.status, 'Unexpected response — is this a Keyhaven server?');
    return json;
  }

  config() { return this.request('GET', '/api/config'); }
  prelogin(email) { return this.request('POST', '/api/prelogin', { email }); }
  register(body) { return this.request('POST', '/api/register', body); }
  login(body) { return this.request('POST', '/api/login', body); }
  logout() { return this.request('POST', '/api/logout', {}); }
  account() { return this.request('GET', '/api/account'); }
  instance() { return this.request('GET', '/api/instance'); }
  changePassword(body) { return this.request('POST', '/api/account/password', body); }
  deleteAccount(authKey) { return this.request('POST', '/api/account/delete', { authKey }); }
  sync(since) { return this.request('GET', `/api/sync?since=${encodeURIComponent(since || 0)}`); }
  putItem(id, data) { return this.request('PUT', `/api/items/${encodeURIComponent(id)}`, { data }); }
  putItems(items) { return this.request('POST', '/api/items/batch', { items }); }
  deleteItem(id) { return this.request('DELETE', `/api/items/${encodeURIComponent(id)}`); }
  sessions() { return this.request('GET', '/api/sessions'); }
  revokeSession(id) { return this.request('DELETE', `/api/sessions/${encodeURIComponent(id)}`); }
}
