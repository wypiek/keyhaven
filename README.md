# Keyhaven

A free, self-hosted password manager. Run the server on your own VPS, then connect
the browser extension (or the built-in web vault) to it by URL.

- **`keyhaven-server`** is a single Rust binary with SQLite storage. It stores accounts and
  encrypted items, and it also serves the web vault.
- **Browser extension** (Chromium/Helium, MV3) is the main app. It has autofill, an inline
  menu in login fields, save/update prompts, a password generator, 2FA codes and a full vault tab.
  It is also a **passkey provider**: when a site creates or asks for a passkey, Keyhaven offers to handle it.
  The passkey's private key is stored encrypted on the login item. **Cards** fill into checkout forms
  from the key icon in the card-number field.
- **Web vault** is the same vault UI, served at your server's URL.

## Security model

Everything is encrypted on your device before it reaches the server.

```
masterKey = Argon2id(password, per-user salt, 64 MiB, t=3, p=4)
authKey   = HKDF-SHA256(masterKey, "keyhaven/auth")   -> sent to server, stored as Argon2id hash
kek       = HKDF-SHA256(masterKey, "keyhaven/enc")    -> never leaves the device
vaultKey  = random 256-bit key, stored on the server wrapped by kek (AES-256-GCM)
item      = AES-256-GCM(vaultKey, item JSON, AAD = "keyhaven/item:<id>")
```

- The server never sees your master password, the vault key or any item contents.
- The client refuses weak KDF parameters, so a malicious server can't downgrade them.
- Unknown emails get fake KDF parameters, so the login endpoint doesn't reveal which accounts exist.
  Failed logins are rate-limited per IP and per account.
- Changing the master password re-wraps the vault key and signs out all other devices.
- In the extension, the unlocked key lives in `chrome.storage.session`. That storage is memory-only,
  is cleared when the browser closes, and content scripts can't read it.
- Content scripts only receive credentials for the frame's real origin (as reported by the browser).
  An `https` login is never filled into an `http` page. Shared-hosting domains such as `github.io`
  or `vercel.app` are isolated per subdomain.
- Copied secrets are cleared from the clipboard after 30 s by default.
- There is no master password recovery. If you forget it, the data is gone.

## Build

Requirements: Rust (cargo), Node (only used for a syntax check), `rsvg-convert` (only if you change the icon).

```sh
./scripts/build.sh
```

Outputs:

- `dist/extension/`: load this folder as an unpacked extension
- `dist/keyhaven-extension.zip`: the same folder, zipped
- `dist/keyhaven-server`: the server binary, with the web vault embedded

## Run the server

```sh
KEYHAVEN_DATA=./data ./dist/keyhaven-server            # listens on 127.0.0.1:8743
```

| Variable               | Default          | Meaning                                                     |
| ---------------------- | ---------------- | ----------------------------------------------------------- |
| `KEYHAVEN_BIND`        | `127.0.0.1:8743` | Listen address                                              |
| `KEYHAVEN_DATA`        | `./data`         | Directory for `keyhaven.db`. **Back it up.**                |
| `KEYHAVEN_SIGNUPS`     | `invite`         | `open`, `invite` or `closed`. The first account is always allowed. |
| `KEYHAVEN_TRUST_PROXY` | off              | Set to `1` behind a reverse proxy so rate limiting sees real IPs |

Admin commands:

```sh
keyhaven-server invite --days 7      # one-time signup code for someone else
keyhaven-server users                # list accounts
keyhaven-server delete-user EMAIL    # remove an account and its data
```

### On this laptop (starts at boot)

```sh
./scripts/install-local.sh
```

This needs no root. It installs `keyhaven-server` and Caddy as systemd user services, enables lingering
so they start at boot, and serves `https://keyhaven.localhost:8443`. It listens on loopback only and uses a
Caddy local CA, which the script trusts in `~/.pki/nssdb`. Data lives in `~/.local/share/keyhaven`.
The unit files and Caddyfile are in `deploy/`.

```sh
systemctl --user status keyhaven-server keyhaven-caddy
journalctl --user -u keyhaven-server -f
```

### On a VPS

1. Copy `dist/keyhaven-server` to the VPS. The binary is self-contained.
2. Run it with `KEYHAVEN_DATA` pointing at a persistent directory. Use whatever process
   supervisor you prefer.
3. Put it behind HTTPS using any reverse proxy, and set `KEYHAVEN_TRUST_PROXY=1`.
   Browsers only allow the crypto APIs on `https://` (or localhost), and the extension
   refuses plain-HTTP remote servers unless you tick "allow insecure".
4. Open `https://your-domain`, create the first account, then sign in from the extension
   with the same URL.

## Install the extension (Helium / Chromium)

1. Open `helium://extensions` (or `chrome://extensions`).
2. Turn on **Developer mode**.
3. Click **Load unpacked** and choose `dist/extension`.
4. Click the Keyhaven toolbar icon. Enter your server URL, email and master password, or create an account.

The extension ID is fixed by the key in `manifest.json` (`bcmhgbcfgekmmbbhgmoaepnnlmlkndad`),
so reloading or reinstalling keeps its storage.

Shortcuts:

- `Ctrl+Shift+K`: open the popup
- `Ctrl+Shift+L`: autofill the best match
- In the vault: `/` to search, `Ctrl+N` for a new item, `Ctrl+Shift+C` to copy the password, `Ctrl+L` to lock

## Admin panel

The first account on a server is its **admin**. On servers created before roles existed, the oldest account is promoted.
Admins get an **Admin** section in the vault sidebar with these tabs:

- **Overview**: accounts, admins, stored items, database size, registration mode.
- **Users**: make or remove admins, sign someone out of every device, delete accounts.
  The last admin can't be demoted or deleted.
- **Invites**: create one-time sign-up codes (1–90 days), see which were used, revoke unused ones.
- **Branding**: name, tagline, accent colour (text contrast adjusts automatically), logo (resized to 128 px),
  and an announcement banner shown to every user.
- **Verified sites**: edit the domain list that earns the blue tick, or reset to the built-in list.
- **Server**: registration mode (overrides `KEYHAVEN_SIGNUPS`) and server-wide website icons.

Admins can't read anyone's vault: items stay end-to-end encrypted with each user's own key.
The same role changes are available from the command line with `keyhaven-server promote EMAIL` and `keyhaven-server demote EMAIL`.

## Website icons and verified sites

- Logins show the website's favicon. Your Keyhaven server fetches it straight from the site and caches it.
  No third-party icon service is used. The fetcher only connects to public addresses over https, follows
  redirects one hop at a time and re-checks each, and accepts only real image files.
  Clients keep icons in memory only. You can turn icons off in Settings → Appearance.
- Logins for well-known sites (about 300 domains in `shared/verified.js`, including major Polish sites)
  get a blue tick. Matching uses the registrable domain, so look-alikes such as `paypal.com.secure-login.net`
  never get the tick. The save prompt also shows "✓ verified" for these sites.

## Passkeys

- Sites that support passkeys show a Keyhaven dialog: **Save passkey** or **Use another device**.
  The second option hands the request to the browser's normal passkey flow (phone, security key and so on).
- Signing in shows the matching passkeys. Sites that use passkey autofill list them in the inline menu.
- Passkeys are ES256 keys with "none" attestation. They work only in the top-level page on `https://`
  (or localhost), and the requested RP ID must belong to the page's own domain.
- They sync to all your devices through your server, like any other item.

## Import

Settings → Import accepts exports from Bitwarden (JSON/CSV), 1Password (CSV), Chrome/Helium/Brave/Edge (CSV),
Firefox (CSV), LastPass (CSV), and Keyhaven's own JSON.

## Layout

```
server/     Rust server (axum + SQLite); web vault embedded from server/static at build time
shared/     client crypto, API client, vault/sync logic, TOTP, generator, importers (ES modules)
ui/         vault UI shared by the web vault and the extension vault page
web/        web vault entry point
extension/  MV3 extension: background worker, content script, popup, offscreen clipboard
vendor/     hash-wasm Argon2 build (MIT)
```

## Limitations

- Edits need a connection to the server. Offline, the vault is read-only from the encrypted cache.
- Concurrent edits to the same item on two devices are resolved last-write-wins.
- No attachments, sharing or organisations yet.
