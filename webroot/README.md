# CIPHER//NET

A self-hosted, single-page encrypted chat application. No accounts, no servers, no tracking — just cryptographic keypairs, signed messages, and end-to-end encryption.

Built to run on [OnionShare](https://onionshare.org/), but works on any static web host over HTTPS.

---

## Features

### Identity & Authentication
- **Keypair identity** — your account is a public/private keypair generated entirely in your browser. No passwords, no email, no server.
- **Private key shown once** — your signing private key is displayed at registration and immediately discarded from memory. It is never stored anywhere.
- **Lock screen gate** — the chat UI is completely hidden until you authenticate with a keypair. Nothing is accessible without a valid key.
- **Returning user detection** — if a fingerprint is found in localStorage, the import tab opens automatically with your handle pre-filled.

### Encryption
- **Channel encryption** — all channel messages are encrypted with AES-256-GCM. A shared passphrase is required to read or send in a channel. The key is derived via PBKDF2 (200,000 iterations, SHA-256) with a deterministic per-channel salt.
- **Direct message encryption** — DMs use ECDH P-256 key exchange. Both parties independently derive the same AES-256-GCM shared key from each other's public DH key — no key is ever transmitted.
- **Message signing** — every message is signed with your ECDSA or RSA-PSS private key and verified on receipt. Each message displays a ✓ SIGNED or ✗ INVALID badge.
- **Messages locked without key** — history without the channel passphrase shows `[encrypted — key required to read]`. Wrong passphrase shows `[decryption failed]`.

### Privacy Deterrents
- **No text selection** — chat content cannot be selected or copied via keyboard.
- **Right-click blocked** — context menu is suppressed on the entire page.
- **Screen blanking** — the entire screen goes black when the window loses focus or is hidden (alt-tab, switching apps). Returns immediately on refocus.
- **PrintScreen warning** — pressing Print Screen or Snapshot triggers a `// SCREENSHOT DETECTED` warning overlay. Note: OS-level screenshots cannot be blocked by a browser — this is a deterrent, not a guarantee.
- **Keyboard shortcuts suppressed** — Ctrl+S, Ctrl+U, Ctrl+P, and F12 are blocked.

### Identity Management
- **Export public identity** — share your handle, public signing key, and ECDH DM public key as a JSON file. Safe to distribute.
- **Export full backup** — exports all encrypted message history, public keys, and DM threads as JSON. Private key is never included.
- **Import / restore** — drag and drop a backup or identity file on the import tab, then paste your private key. Works across devices.
- **PGP / GPG / Kleopatra compatibility** — full OpenPGP integration via OpenPGP.js (bundled locally). Three capabilities:
  - **Export PGP keypair** — generate an RSA-4096 OpenPGP keypair tied to your handle. Export armored public and secret key files (`.asc`) importable directly into GPG or Kleopatra. Optional passphrase protection on the secret key.
  - **Import existing GPG key** — paste any armored GPG private key (RSA, ECC, protected or unprotected) to load it into the PGP tool for encrypt/decrypt operations.
  - **Encrypt & decrypt messages** — PGP-encrypt a message for any recipient (paste their public key), signed with your key. Decrypt any PGP-encrypted message sent to you, with signature verification.
- **ECDH DM key persistence** — your DM keypair is stored encrypted in localStorage (PBKDF2-wrapped AES-GCM) and automatically restored on import.
- **Password-protected key export** — optionally encrypt your private key before copying. Enter a password on the registration screen before hitting Copy — the key is encrypted with AES-256-GCM (PBKDF2, 300,000 iterations) and stored as a `CIPHER-ENC:v1:...` string. Useless without the password. On import, the password field appears automatically when an encrypted key is detected.

---

## Progressive Web App (PWA)

CIPHER//NET is installable as a native-feeling app on any device — no app store required.

### Installing on Android
1. Open the site in Chrome
2. Tap the three-dot menu → **Add to Home screen**
3. The app installs with a home screen icon and runs fullscreen

### Installing on iPhone / iPad
1. Open the site in **Safari** (Chrome on iOS cannot install PWAs)
2. Tap the Share button → **Add to Home Screen**

### Installing on Desktop
Chrome and Edge show an install icon (⊕) in the address bar when a PWA is detected. Click it to install.

### PWA capabilities
- **Offline** — the service worker caches all files on first load. The app works fully without a network connection after that.
- **Fullscreen** — runs without browser chrome in standalone display mode.
- **Home screen icon** — green lock icon on black, 192×512px.
- **Safe area support** — respects notch and gesture bar insets on iPhone X+ and modern Android.

---

## Files

```
index.html       — markup only, no inline scripts or styles
app.css          — all styles
app.js           — all application logic and crypto
sw.js            — service worker: caches assets for offline use
manifest.json    — PWA manifest: name, icons, display mode, theme
icon-192.png     — home screen icon (192×192)
icon-512.png     — high-res icon for splash screens (512×512)
embed-fonts.py   — optional: bakes fonts as base64 for fully offline use
openpgp.min.js   — OpenPGP.js v5 (must be downloaded separately, see GET_OPENPGP.md)
GET_OPENPGP.md   — instructions for downloading openpgp.min.js
README.md        — this file
```

---

## Hosting on OnionShare

1. Open OnionShare → **Publish website**
2. Add `index.html`, `app.css`, and `app.js`
3. Start — share the `.onion` address

No Python, no Node, no configuration. The app makes zero external requests and is fully compliant with OnionShare's strict Content Security Policy (`default-src 'self'`).

> **Note:** Use **Publish website** mode, not "Serve files" — the latter serves a directory listing rather than loading `index.html` as the app entry point.

---

## Hosting elsewhere

Any static file server works: GitHub Pages, Nginx, Caddy, Apache, `python3 -m http.server`.

> **Web Crypto API requires HTTPS, localhost, or a .onion address.** Plain HTTP on a public domain will not work — `crypto.subtle` is unavailable in insecure contexts.

---

## Embedding fonts (optional)

By default the app uses a system monospace font stack. To embed [Share Tech Mono](https://fonts.google.com/specimen/Share+Tech+Mono) and [VT323](https://fonts.google.com/specimen/VT323) as base64 data URIs for a consistent look everywhere including air-gapped machines:

```bash
python3 embed-fonts.py
```

This makes a one-time request from **your machine** to Google's font CDN, then splices the fonts into `app.css`. After that, the app makes zero network requests.

---

## Cryptographic architecture

### Signing keys (per-user identity)

Three algorithms available at registration — all generated via the browser's native Web Crypto API:

| Algorithm | Security | Notes |
|---|---|---|
| ECDSA P-256 | 128-bit | Recommended. Fast, universally supported. |
| ECDSA P-384 | 192-bit | Stronger. Slightly slower generation. |
| RSA-PSS 2048 | ~112-bit | Classical RSA. Large keys, slowest generation. |

- ECDSA P-256 signs with SHA-256; P-384 signs with SHA-384.
- Private keys are exported as PKCS#8 PEM and shown once. Re-import is supported for all three algorithm types on all major browsers.

### DM encryption (ECDH P-256)

A dedicated ECDH P-256 keypair is auto-generated alongside your signing key.

1. Your ECDH public key is included in your identity export.
2. When opening a DM, both parties derive the same AES-256-GCM key independently using `ECDH.deriveKey`.
3. No shared key is ever transmitted. Each DM message is signed with your ECDSA key and encrypted with the derived AES key.
4. Your ECDH private key is stored in localStorage wrapped with AES-GCM (key derived from your fingerprint via PBKDF2, 100,000 iterations).

### Channel encryption (PBKDF2 + AES-256-GCM)

1. Set a passphrase in the channel header.
2. The app derives an AES-256-GCM key via PBKDF2 (200,000 iterations, SHA-256) using a deterministic per-channel salt: `SHA-256("cipher-channel:<channel>")`.
3. Each message is encrypted with a fresh random 12-byte IV. The full signed envelope (text, signature, public key, metadata) is encrypted — only the author hint (first 6 hex chars of fingerprint) is stored in plaintext.
4. Users without the passphrase see the message locked. Users with the wrong passphrase see a decryption failure.

### Password-protected key export

Private keys can optionally be exported in an encrypted form safe to store in notes apps, cloud storage, or screenshots.

**Encryption:** AES-256-GCM with a key derived via PBKDF2 (300,000 iterations, SHA-256) from a user-supplied password and a random 16-byte salt.

**Format:** `CIPHER-ENC:v1:<base64(16-byte-salt + 12-byte-iv + ciphertext)>`

- The encrypted blob is self-describing — the app detects it automatically on paste.
- Without the correct password the blob is computationally infeasible to decrypt.
- The password field on the import tab appears automatically when an encrypted key is pasted.
- If no password is set, the plain PKCS#8 PEM is copied as before.

### Security model summary

| Property | Status |
|---|---|
| Channel message encryption | ✓ AES-256-GCM, PBKDF2-derived passphrase key |
| DM encryption | ✓ AES-256-GCM, ECDH P-256 shared key |
| Message authentication | ✓ ECDSA P-256/P-384 or RSA-PSS signatures |
| Private signing key storage | ✗ Never stored — shown once at registration |
| ECDH DM key storage | ✓ Stored encrypted (PBKDF2-wrapped AES-GCM) |
| Transport security | Depends on host (use HTTPS or .onion) |
| Anonymity | Depends on host — use OnionShare + Tor Browser |
| Screenshot prevention | ⚠ Deterrents only — OS capture cannot be blocked |
| Offline capability | ✓ Service worker caches all assets after first load |
| PGP encryption | ✓ OpenPGP.js v5, RSA-4096, armored export, GPG/Kleopatra compatible |
| Password-protected key export | ✓ AES-256-GCM, PBKDF2-SHA-256, 300k iterations |

---

## Recovering your identity

Your signing private key is never stored. To sign back in:

1. Go to the **Import Key** tab
2. Paste your signing private key (PKCS#8 PEM — the one shown during registration)
3. Your fingerprint, DM key, and message history are automatically restored from localStorage

To move to another device:

1. Export a **Full Backup** from the sidebar
2. On the new device, drop the backup JSON onto the Import tab
3. Paste your private signing key
4. All history, user keys, and DM threads are restored

---

## Browser support

Requires Web Crypto API: Firefox, Chrome, Brave, Safari, Tor Browser.

- **Tor Browser:** Security level must be **Standard** or **Safer**. The **Safest** level disables JavaScript entirely.
- **Firefox:** Key import uses a JWK round-trip path for full compatibility.
- **Extensions:** Some wallet extensions (e.g. MetaMask) run SES lockdown on page load. Disable them on the page if crypto operations fail.

---

## localStorage keys

| Key | Contents |
|---|---|
| `cipher_users` | Public key registry: handle, public key PEM, fingerprint, algo, DH public key |
| `cipher_msgs_<channel>` | Up to 200 encrypted messages per channel |
| `cipher_dm_<fpA>_<fpB>` | DM thread (fingerprints sorted, order-independent) |
| `cipher_dh_<fingerprint>` | ECDH private key (AES-GCM wrapped) |
| `cipher_my_fingerprint` | Last authenticated fingerprint (for returning user detection) |

All message content is stored as ciphertext. Public keys and fingerprints are stored in plaintext.

---

## PGP / GPG / Kleopatra

CIPHER//NET includes a full OpenPGP tool via [OpenPGP.js v5](https://openpgpjs.org/), bundled locally for offline and OnionShare use.

### Setup

Download `openpgp.min.js` and place it in the repo root alongside `index.html` (see `GET_OPENPGP.md`). The rest of the app works without it — the PGP buttons will show a warning if the file is missing.

### Export PGP Keypair (Option A)

Generates a fresh RSA-4096 OpenPGP keypair associated with your CIPHER//NET handle:

1. Click **PGP EXPORT KEYPAIR** in the sidebar
2. Optionally enter a PGP User ID (e.g. `Alice <alice@example.com>`) and an export passphrase
3. Click **GENERATE PGP KEYPAIR**
4. Download or copy `public.asc` and `secret.asc`

**Importing into Kleopatra:** File → Import → select `secret.asc` → enter passphrase if set.
**Importing into GPG:** `gpg --import secret.asc`

### Import Existing GPG Key (Option C)

Use your existing Kleopatra/GPG identity inside CIPHER//NET:

1. Export from GPG: `gpg --armor --export-secret-keys YOUR_KEY_ID > secret.asc`
2. Click **PGP IMPORT GPG KEY** in the sidebar
3. Paste the armored key and enter your passphrase if protected

### Encrypt & Decrypt Messages (Option B)

PGP messages encrypted here can be decrypted by any GPG/Kleopatra user and vice versa:

- **Encrypt:** paste recipient's public key, type your message, click **ENCRYPT & SIGN** — produces a standard `-----BEGIN PGP MESSAGE-----` block
- **Decrypt:** paste any PGP message encrypted to your key — optionally paste sender's public key for signature verification

---

## License

MIT License — see [LICENSE](LICENSE).

Free to use, modify, and distribute for any purpose. Attribution appreciated but not required.
