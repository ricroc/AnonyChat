# CIPHER//NET

A self-hosted, single-page encrypted chat application. No accounts, no servers, no tracking — just cryptographic keypairs and signed messages.

Built to run on [OnionShare](https://onionshare.org/), but works on any static web host.

---

## Features

- **Keypair identity** — accounts are a public/private key pair generated in your browser. No passwords, no email.
- **Cryptographically signed messages** — every message is signed with your private key and verified against your public key. Tampering is detectable.
- **Private key shown once** — your private key is displayed at registration and immediately discarded. It is never stored anywhere.
- **No server required** — runs entirely as static files. Message history and public keys are stored in browser `localStorage`.
- **Tor / OnionShare compatible** — no external requests, no CDN dependencies, no inline scripts. Fully compliant with OnionShare's strict Content Security Policy.
- **Identity export/import** — export your public identity or a full backup as JSON. Drag and drop to restore on another device.
- **Multiple channels** — `#general`, `#random`, `#tech`.
- **Offline-capable fonts** — ships with system font fallbacks. Run `embed-fonts.py` once to bake real fonts in as base64 for a consistent look everywhere.

---

## Files

```
index.html       — markup, no inline scripts or styles
app.css          — all styles
app.js           — all application logic
embed-fonts.py   — optional: embeds fonts as base64 for fully offline use
LICENSE          — GNU AGPLv3
```

---

## Hosting on OnionShare

1. Open OnionShare → **Publish website**
2. Add all four files (`index.html`, `app.css`, `app.js`, and optionally `embed-fonts.py` can be left out)
3. Start — share the `.onion` address

That's it. No Python, no Node, no configuration.

> **Note:** OnionShare's "Serve files" mode will not work — it serves files with a directory listing rather than as a website. Use **Publish website** mode.

---

## Hosting elsewhere

Any static file server works: GitHub Pages, Nginx, Caddy, Apache, `python3 -m http.server`.

> **Note:** Web Crypto API requires either **HTTPS**, **localhost**, or a **.onion** address. Plain HTTP on a public domain will not work.

---

## Embedding fonts (optional)

By default the app uses a system monospace font stack that looks clean on most systems. To embed [Share Tech Mono](https://fonts.google.com/specimen/Share+Tech+Mono) and [VT323](https://fonts.google.com/specimen/VT323) as base64 for a consistent look everywhere including air-gapped machines:

```bash
python3 embed-fonts.py
```

This makes a single outbound request from **your machine** to Google's font CDN, then splices the fonts into `app.css` as data URIs. After that, the app makes zero network requests.

---

## Security model

| Property | Status |
|---|---|
| Message authentication | ✓ ECDSA / RSA-PSS signatures |
| Private key storage | ✗ Never stored — shown once |
| Message encryption | ✗ Messages are signed, not encrypted |
| Transport security | Depends on host (HTTPS / .onion) |
| Anonymity | Depends on host — use OnionShare + Tor for anonymity |

**Messages are authenticated but not encrypted.** Anyone who can load the page can read all messages. Signatures prove who sent a message and that it hasn't been tampered with — they do not hide the content.

For encrypted direct messages, a future version could add ECDH key exchange. Contributions welcome.

---

## Key algorithms

Three options at registration:

| Algorithm | Notes |
|---|---|
| ECDSA P-256 | Default. Fast, widely supported, 128-bit security |
| ECDSA P-384 | Stronger, slightly slower, 192-bit security |
| RSA-PSS 2048 | Classical RSA, larger keys, slower generation |

All use the browser's native [Web Crypto API](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API). No crypto libraries are bundled.

---

## Reconnecting / recovering your identity

Your private key is **not stored** after registration. To sign in again:

1. Go to **Import Key** tab
2. Paste your private key (PKCS#8 PEM format)
3. Your identity is re-derived from it — no username or password needed

To move to another device, export a backup from the sidebar (**↓ Export Full Backup**) and drag it into the Import Key tab on the new device, then paste your private key.

---

## Browser support

Any modern browser with Web Crypto API support: Firefox, Chrome, Safari, Brave, Tor Browser.

Tor Browser's `about:config` security level must be set to **Standard** or **Safer** — the **Safest** level disables JavaScript entirely.

---

## License

MIT License — see [LICENSE](LICENSE).

Free to use, modify, and distribute for any purpose. Attribution appreciated but not required beyond keeping the copyright notice.
