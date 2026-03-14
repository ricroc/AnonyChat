'use strict';

// ═══════════════════════════════════════════════════════
// CRYPTO CONSTANTS — strongest settings throughout
//   Signing:   ECDSA P-256 + SHA-256
//   DM keys:   ECDH  P-256
//   Symmetric: AES-256-GCM, 96-bit random IV
//   KDF:       PBKDF2-SHA-256, 600 000 iterations (channels)
//              PBKDF2-SHA-256, 300 000 iterations (DH key wrap)
// ═══════════════════════════════════════════════════════
const SIGN_ALG  = { name: 'ECDSA',  namedCurve: 'P-256' };
const SIGN_USE  = { name: 'ECDSA',  hash: 'SHA-256' };
const DH_ALG    = { name: 'ECDH',   namedCurve: 'P-256' };
const AES_ALG   = { name: 'AES-GCM', length: 256 };
const KDF_CHAN  = { name: 'PBKDF2', hash: 'SHA-256', iterations: 600_000 };
const KDF_WRAP  = { name: 'PBKDF2', hash: 'SHA-256', iterations: 300_000 };

// ═══════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════
const state = {
  me: null,          // { handle, publicKeyPem, signingKey, fingerprint, dhPrivKey, dhPubKeyPem }
  view: 'channel',   // 'channel' | 'dm'
  channel: 'general',
  dmPeer: null,      // { handle, fingerprint, dhPubKeyPem }
  channelKeys: {},   // channel  -> AES-GCM CryptoKey
  dmKeys: {},        // fp       -> AES-GCM CryptoKey
  pendingDmFp: null,
  // transient keygen state
  generatedPrivPem:  null,
  generatedPubPem:   null,
  generatedCryptoKeys: null,
  generatedDHKeys:   null,
  generatedDHPubPem: null,
};

const CHANNEL_DESCS = {
  general: 'AES-256-GCM · PBKDF2-SHA384 · ECDSA-P256 signed',
  random:  'AES-256-GCM encrypted · shared passphrase',
  tech:    'AES-256-GCM encrypted · shared passphrase',
};

// ═══════════════════════════════════════════════════════
// PEM HELPERS
// ═══════════════════════════════════════════════════════

function toPem(buffer, label) {
  const b64 = btoa(String.fromCharCode(...new Uint8Array(buffer)));
  return `-----BEGIN ${label}-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END ${label}-----`;
}

function fromPem(pem) {
  // Strip PEM headers, all whitespace (including Windows \r\n and stray spaces)
  // then validate the result is pure base64 before calling atob.
  const b64 = pem
    .replace(/-----BEGIN[^-]*-----/, '')
    .replace(/-----END[^-]*-----/, '')
    .replace(/[\s\r\n]+/g, '');
  if (!/^[A-Za-z0-9+/]+=*$/.test(b64)) {
    throw new Error('PEM contains non-base64 characters — the key may have been corrupted during copy-paste.');
  }
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
}

async function exportPrivPem(key) { return toPem(await crypto.subtle.exportKey('pkcs8', key), 'PRIVATE KEY'); }
async function exportPubPem(key)  { return toPem(await crypto.subtle.exportKey('spki',  key), 'PUBLIC KEY'); }

// ═══════════════════════════════════════════════════════
// SIGNING — ECDSA P-256 / SHA-256
// ═══════════════════════════════════════════════════════

async function generateSigningKeypair() {
  return crypto.subtle.generateKey({ ...SIGN_ALG }, true, ['sign', 'verify']);
}

async function importSigningPrivKey(pem) {
  // Hard check — if crypto.subtle is unavailable the real error is the environment
  if (typeof crypto === 'undefined' || !crypto.subtle) {
    throw new Error('crypto.subtle is not available. The page must be served over HTTPS or localhost. (current origin: ' + location.origin + ')');
  }

  pem = pem.trim();

  // Detect wrong key type immediately
  if (pem.includes('-----BEGIN PUBLIC KEY-----')) {
    throw new Error('You pasted your PUBLIC key. You need to paste the PRIVATE key (labeled "Signing Private Key" during generation).');
  }
  if (pem.includes('-----BEGIN CERTIFICATE-----')) {
    throw new Error('This is a certificate, not a private key.');
  }
  if (!pem.includes('-----BEGIN') || !pem.includes('-----END')) {
    throw new Error('Missing PEM header/footer lines. Paste the full key including -----BEGIN PRIVATE KEY----- and -----END PRIVATE KEY-----.');
  }
  if (!pem.includes('PRIVATE KEY')) {
    throw new Error('This does not appear to be a private key PEM. Make sure you copied the "Signing Private Key" box, not the public key.');
  }

  let der;
  try {
    der = fromPem(pem);
  } catch (e) {
    throw new Error('Could not decode key — it may be corrupted or truncated during copy. (' + e.message + ')');
  }

  // Try every algorithm + usage combination this app has ever generated.
  // Firefox enforces that the usage passed to importKey matches the key's
  // intended usage — ECDH keys (deriveKey) cannot be imported with ['sign'].
  // So we try both usages and re-export via JWK to get the right CryptoKey.
  const ecCurves  = ['P-256'];
  const errors    = [];

  for (const curve of ecCurves) {
    const alg = { name: 'ECDSA', namedCurve: curve };
    // Try direct ECDSA import first (key was generated as signing key)
    try {
      const key = await crypto.subtle.importKey('pkcs8', der, alg, true, ['sign']);
      const pub = await deriveSigningPub(key, alg);
      return { privateKey: key, publicKey: pub, algorithm: alg };
    } catch (e) {
      errors.push('ECDSA ' + curve + ' [sign]: ' + (e.message || e));
    }
    // Try importing as ECDH (key may have been generated as DM/ECDH key),
    // then re-import the raw JWK bytes as ECDSA so it can sign.
    try {
      const dhAlg  = { name: 'ECDH', namedCurve: curve };
      const dhKey  = await crypto.subtle.importKey('pkcs8', der, dhAlg, true, ['deriveKey']);
      const jwk    = await crypto.subtle.exportKey('jwk', dhKey);
      // Flip the key_ops so we can import as ECDSA
      jwk.key_ops = ['sign'];
      const sigKey = await crypto.subtle.importKey('jwk', jwk, alg, true, ['sign']);
      const pub    = await deriveSigningPub(sigKey, alg);
      return { privateKey: sigKey, publicKey: pub, algorithm: alg };
    } catch (e) {
      errors.push('ECDH→ECDSA ' + curve + ': ' + (e.message || e));
    }
  }

  // RSA-PSS
  try {
    const alg = { name: 'RSA-PSS', hash: 'SHA-256' };
    const key = await crypto.subtle.importKey('pkcs8', der, alg, true, ['sign']);
    const pub = await deriveSigningPub(key, alg);
    return { privateKey: key, publicKey: pub, algorithm: alg };
  } catch (e) {
    errors.push('RSA-PSS: ' + (e.message || e));
  }

  throw new Error('Import failed. Errors: ' + errors.join(' | '));
}

async function deriveSigningPub(privateKey, alg) {
  alg = alg || SIGN_ALG;
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  // Strip all private key fields (handles both ECDSA and RSA-PSS)
  ['d','p','q','dp','dq','qi'].forEach(k => delete jwk[k]);
  const pubAlg = alg.name === 'ECDSA'
    ? { name: 'ECDSA', namedCurve: alg.namedCurve }
    : { name: 'RSA-PSS', hash: 'SHA-256' };
  return crypto.subtle.importKey('jwk', jwk, pubAlg, true, ['verify']);
}

async function fingerprint(pubKeyPem) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pubKeyPem));
  return Array.from(new Uint8Array(hash)).slice(0, 10).map(b => b.toString(16).padStart(2,'0')).join('');
}

async function signData(text, signingKey, alg) {
  alg = alg || SIGN_ALG;
  const sigAlg = alg.name === 'ECDSA'
    ? { name: 'ECDSA', hash: 'SHA-256' }
    : { name: 'RSA-PSS', saltLength: 32 };
  const sig = await crypto.subtle.sign(sigAlg, signingKey, new TextEncoder().encode(text));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

async function verifyData(text, sigB64, pubKeyPem, alg) {
  // alg is optional — defaults to P-256
  try {
    alg = alg || SIGN_ALG;
    const importAlg = alg.name === 'ECDSA'
      ? { name: 'ECDSA', namedCurve: alg.namedCurve || 'P-256' }
      : { name: 'RSA-PSS', hash: 'SHA-256' };
    const verAlg = alg.name === 'ECDSA'
      ? { name: 'ECDSA', hash: 'SHA-256' }
      : { name: 'RSA-PSS', saltLength: 32 };
    const key = await crypto.subtle.importKey('spki', fromPem(pubKeyPem), importAlg, false, ['verify']);
    return crypto.subtle.verify(verAlg, key,
      Uint8Array.from(atob(sigB64), c => c.charCodeAt(0)),
      new TextEncoder().encode(text));
  } catch { return false; }
}

// ═══════════════════════════════════════════════════════
// ECDH P-256 — DM key exchange
// ═══════════════════════════════════════════════════════

async function generateDHKeypair() {
  return crypto.subtle.generateKey({ ...DH_ALG }, true, ['deriveKey']);
}

// Both parties independently derive the same AES-256-GCM key.
async function deriveSharedDMKey(myDhPrivKey, theirDhPubKeyPem) {
  const theirPub = await crypto.subtle.importKey('spki', fromPem(theirDhPubKeyPem), DH_ALG, false, []);
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: theirPub },
    myDhPrivKey,
    AES_ALG, false, ['encrypt', 'decrypt']
  );
}

// Wrap the ECDH private key with AES-GCM so it can persist in localStorage
// without being stored in cleartext. The wrapping key is derived deterministically
// from the signing fingerprint using PBKDF2 — it is purely a local-at-rest
// protection, not a password.
async function persistDHPrivKey(dhPrivKey, fp) {
  const wrapKey  = await derivePersistKey(fp);
  const iv       = crypto.getRandomValues(new Uint8Array(12));
  const raw      = await crypto.subtle.exportKey('pkcs8', dhPrivKey);
  const wrapped  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, raw);
  const out      = new Uint8Array(12 + wrapped.byteLength);
  out.set(iv, 0); out.set(new Uint8Array(wrapped), 12);
  localStorage.setItem('cipher_dh_' + fp, btoa(String.fromCharCode(...out)));
}

async function loadDHPrivKey(fp) {
  const stored = localStorage.getItem('cipher_dh_' + fp);
  if (!stored) return null;
  const buf     = Uint8Array.from(atob(stored), c => c.charCodeAt(0));
  const wrapKey = await derivePersistKey(fp);
  try {
    const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, wrapKey, buf.slice(12));
    return crypto.subtle.importKey('pkcs8', raw, DH_ALG, true, ['deriveKey']);
  } catch { return null; }
}

async function derivePersistKey(fp) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(fp), 'PBKDF2', false, ['deriveKey']);
  const salt  = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('cipher-dh-wrap:' + fp));
  return crypto.subtle.deriveKey(
    { ...KDF_WRAP, salt },
    base, AES_ALG, false, ['encrypt', 'decrypt']
  );
}

async function deriveDHPubFromPriv(dhPrivKey) {
  const jwk = await crypto.subtle.exportKey('jwk', dhPrivKey);
  delete jwk.d;
  return crypto.subtle.importKey('jwk', jwk, DH_ALG, true, []);
}

// ═══════════════════════════════════════════════════════
// AES-256-GCM — symmetric encrypt / decrypt
// ═══════════════════════════════════════════════════════

async function aesEncrypt(plaintext, key) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0); out.set(new Uint8Array(ct), 12);
  return btoa(String.fromCharCode(...out));
}

async function aesDecrypt(b64, key) {
  const buf   = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, key, buf.slice(12));
  return new TextDecoder().decode(plain);
}

// ═══════════════════════════════════════════════════════
// PBKDF2 — channel passphrase → AES-256-GCM key
// ═══════════════════════════════════════════════════════

async function deriveChannelKey(passphrase, channel) {
  const enc  = new TextEncoder();
  const base = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const salt = await crypto.subtle.digest('SHA-256', enc.encode('cipher-channel:' + channel));
  return crypto.subtle.deriveKey({ ...KDF_CHAN, salt }, base, AES_ALG, false, ['encrypt', 'decrypt']);
}

// ═══════════════════════════════════════════════════════
// CHANNEL PASSPHRASE UI
// ═══════════════════════════════════════════════════════

async function setChannelPassphrase() {
  const pass = $('channel-passphrase').value;
  if (!pass) { toast('Enter a passphrase first'); return; }
  const btn = $('btn-set-passphrase');
  btn.textContent = '...'; btn.disabled = true;
  try {
    state.channelKeys[state.channel] = await deriveChannelKey(pass, state.channel);
    $('channel-passphrase').value = '';
    updateEncStatus(true);
    updateMsgInput();
    $('messages').innerHTML = '';
    await loadHistory();
    sysMsg('Channel key active — AES-256-GCM / PBKDF2-SHA384 / 600k iterations.');
    toast('Channel key set');
  } catch (e) { toast('Key derivation failed: ' + e.message); }
  btn.textContent = 'SET KEY'; btn.disabled = false;
}

function updateEncStatus(active) {
  const el = $('enc-status');
  el.textContent = active ? 'AES-256 ACTIVE' : 'NO KEY SET';
  el.classList.toggle('active', active);
}

// ═══════════════════════════════════════════════════════
// KEY GENERATION (lock screen)
// ═══════════════════════════════════════════════════════

async function generateKeys() {
  const username = $('reg-username').value.trim();
  if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) { toast('Handle: 3–32 chars, letters/numbers/underscores'); return; }

  const btn = $('btn-gen');
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>GENERATING...';
  $('key-gen-area').classList.remove('hidden');
  animateProgress(0, 30, 500);

  let sigKeys, dhKeys;
  try {
    sigKeys = await generateSigningKeypair();
    animateProgress(30, 60, 400);
    dhKeys  = await generateDHKeypair();
    animateProgress(60, 90, 300);
  } catch (e) {
    toast('Key generation failed: ' + e.message);
    btn.disabled = false; btn.innerHTML = 'GENERATE KEYPAIR'; return;
  }

  const privPem  = await exportPrivPem(sigKeys.privateKey);
  const pubPem   = await exportPubPem(sigKeys.publicKey);
  const dhPubPem = await exportPubPem(dhKeys.publicKey);
  animateProgress(90, 100, 200);

  state.generatedPrivPem    = privPem;
  state.generatedPubPem     = pubPem;
  state.generatedCryptoKeys = sigKeys;
  state.generatedDHKeys     = dhKeys;
  state.generatedDHPubPem   = dhPubPem;

  $('priv-key-display').textContent = privPem;
  $('pub-key-display').textContent  = pubPem;

  btn.classList.add('hidden');
  const act = $('btn-activate');
  act.classList.remove('hidden'); act.disabled = true;
  $('confirm-saved').addEventListener('change', function h() {
    act.disabled = !this.checked;
    if (this.checked) this.removeEventListener('change', h);
  });
}

function animateProgress(from, to, ms) {
  const fill = $('gen-progress'), start = Date.now();
  const tick = () => {
    const t = Math.min(1, (Date.now() - start) / ms);
    fill.style.width = (from + (to - from) * t) + '%';
    if (t < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

async function activateAccount() {
  const username = $('reg-username').value.trim();
  const fp       = await fingerprint(state.generatedPubPem);

  await persistDHPrivKey(state.generatedDHKeys.privateKey, fp);

  const users = getStoredUsers();
  users[fp]   = {
    handle: username, publicKeyPem: state.generatedPubPem,
    fingerprint: fp, dhPubKeyPem: state.generatedDHPubPem,
    registeredAt: Date.now(),
  };
  localStorage.setItem('cipher_users', JSON.stringify(users));
  localStorage.setItem('cipher_my_fingerprint', fp);

  state.me = {
    handle: username, publicKeyPem: state.generatedPubPem,
    signingKey: state.generatedCryptoKeys.privateKey,
    fingerprint: fp, algo: SIGN_ALG,
    dhPrivKey: state.generatedDHKeys.privateKey,
    dhPubKeyPem: state.generatedDHPubPem,
  };

  // Scrub transient keygen data
  state.generatedPrivPem    = null;
  state.generatedCryptoKeys = null;
  state.generatedDHKeys     = null;

  enterApp();
  sysMsg(username + ' joined the network.');
  toast('Authenticated as ' + username);
}

// ═══════════════════════════════════════════════════════
// IMPORT KEY (lock screen)
// ═══════════════════════════════════════════════════════

async function importKey() {
  const privPem       = $('login-privkey').value.trim();
  const handleOverride = $('login-username').value.trim();
  hideLoginError();
  if (!privPem) { showLoginError('Paste your private signing key (PKCS#8 PEM).'); return; }

  const btn = $('btn-import');
  btn.textContent = 'VERIFYING...'; btn.disabled = true;

  // Sanity-check crypto availability before attempting import
  if (!crypto || !crypto.subtle) {
    showLoginError('Web Crypto API not available. This page must be served over HTTPS or from localhost.');
    btn.textContent = 'IMPORT AND ENTER'; btn.disabled = false; return;
  }

  let sigKeys;
  try {
    sigKeys = await importSigningPrivKey(privPem);
  } catch (e) {
    showLoginError('Key parse error: ' + e.message);
    btn.textContent = 'IMPORT AND ENTER'; btn.disabled = false; return;
  }

  const pubPem = await exportPubPem(sigKeys.publicKey);
  const fp     = await fingerprint(pubPem);
  const users  = getStoredUsers();
  const handle = handleOverride || (users[fp] && users[fp].handle) || 'user_' + fp.slice(0, 6);

  // Load existing ECDH key from localStorage, or generate a fresh one
  let dhPrivKey, dhPubKeyPem;
  const stored = await loadDHPrivKey(fp);
  if (stored) {
    dhPrivKey   = stored;
    dhPubKeyPem = await exportPubPem(await deriveDHPubFromPriv(dhPrivKey));
  } else {
    const dhKeys = await generateDHKeypair();
    dhPrivKey    = dhKeys.privateKey;
    dhPubKeyPem  = await exportPubPem(dhKeys.publicKey);
    await persistDHPrivKey(dhPrivKey, fp);
  }

  // Preserve any existing dhPubKeyPem in user record if we already had one stored
  const existingUser = users[fp] || {};
  users[fp] = {
    ...existingUser,
    handle, publicKeyPem: pubPem, fingerprint: fp, dhPubKeyPem,
  };
  localStorage.setItem('cipher_users', JSON.stringify(users));
  localStorage.setItem('cipher_my_fingerprint', fp);

  state.me = { handle, publicKeyPem: pubPem, signingKey: sigKeys.privateKey, fingerprint: fp, algo: sigKeys.algorithm, dhPrivKey, dhPubKeyPem };

  btn.textContent = 'IMPORT AND ENTER'; btn.disabled = false;
  enterApp();
  sysMsg(handle + ' connected.');
  toast('Signed in as ' + handle);
}

function showLoginError(msg) {
  const el = $('login-error');
  el.textContent = msg;
  el.classList.remove('hidden');
}
function hideLoginError() { $('login-error').classList.add('hidden'); }

// ═══════════════════════════════════════════════════════
// LOCK SCREEN
// ═══════════════════════════════════════════════════════

function enterApp() {
  $('lock-screen').classList.add('hidden');
  $('app').classList.remove('hidden');
  onAuthenticated();
}

function switchLockTab(tab) {
  $('lock-tab-register').classList.toggle('active', tab === 'register');
  $('lock-tab-login').classList.toggle('active',    tab === 'login');
  $('lock-panel-register').classList.toggle('hidden', tab !== 'register');
  $('lock-panel-login').classList.toggle('hidden',    tab === 'register');
}

// ═══════════════════════════════════════════════════════
// DIRECT MESSAGES
// ═══════════════════════════════════════════════════════

async function openDM(fp) {
  if (fp === state.me.fingerprint) { toast('Cannot DM yourself'); return; }
  const users = getStoredUsers();
  const peer  = users[fp];
  if (!peer) { toast('User not found in local registry'); return; }

  // Already have a shared key for this peer
  if (state.dmKeys[fp]) { activateDMView(peer); return; }

  // Peer's DH public key is known — derive shared key silently
  if (peer.dhPubKeyPem) {
    try {
      state.dmKeys[fp] = await deriveSharedDMKey(state.me.dhPrivKey, peer.dhPubKeyPem);
      activateDMView(peer); return;
    } catch (e) { toast('DM key derivation failed: ' + e.message); return; }
  }

  // Need to ask for peer's DH public key
  state.pendingDmFp = fp;
  $('dm-modal-error').classList.add('hidden');
  $('dm-pubkey-input').value = '';
  $('dm-key-modal').classList.remove('hidden');
}

async function confirmDMKeyExchange() {
  const pem = $('dm-pubkey-input').value.trim();
  const fp  = state.pendingDmFp;
  if (!pem) { showDMModalError('Paste the recipient DM public key (SPKI PEM).'); return; }

  const btn = $('dm-modal-confirm');
  btn.textContent = 'DERIVING KEY...'; btn.disabled = true;

  try {
    state.dmKeys[fp] = await deriveSharedDMKey(state.me.dhPrivKey, pem);

    // Cache their DH pub key for future sessions
    const users = getStoredUsers();
    if (users[fp]) { users[fp].dhPubKeyPem = pem; localStorage.setItem('cipher_users', JSON.stringify(users)); }

    closeDMModal();
    const peer = getStoredUsers()[fp];
    if (peer) activateDMView(peer);
    toast('DM key established — ECDH P-256');
  } catch (e) {
    showDMModalError('Key derivation failed: ' + e.message);
  }

  btn.textContent = 'START ENCRYPTED DM'; btn.disabled = false;
}

function activateDMView(peer) {
  state.view    = 'dm';
  state.dmPeer  = peer;
  state.channel = 'dm:' + peer.fingerprint;

  document.querySelectorAll('.channel-item, .dm-item').forEach(el => el.classList.remove('active'));

  let dmItem = document.querySelector('.dm-item[data-fp="' + peer.fingerprint + '"]');
  if (!dmItem) dmItem = addDMSidebarItem(peer);
  dmItem.classList.add('active');

  $('channel-title').textContent = '@' + peer.handle;
  $('channel-desc').textContent  = 'ECDH P-256 end-to-end encrypted direct message';
  $('passphrase-wrap').classList.add('hidden');
  $('dm-header-info').classList.remove('hidden');
  $('dm-fp').textContent = 'fp:' + peer.fingerprint.slice(0, 12);

  $('messages').innerHTML = '';
  updateMsgInput();
  loadHistory();
}

function addDMSidebarItem(peer) {
  const list  = $('dm-list');
  const empty = list.querySelector('.dm-empty');
  if (empty) empty.remove();

  const div = document.createElement('div');
  div.className  = 'dm-item';
  div.dataset.fp = peer.fingerprint;
  div.innerHTML  = '<span class="dm-icon">@</span>' + escHtml(peer.handle) +
                   '<span class="user-fp">' + peer.fingerprint.slice(0,6) + '</span>';
  div.addEventListener('click', () => openDM(peer.fingerprint));
  list.appendChild(div);
  return div;
}

function showDMModalError(msg) { const el = $('dm-modal-error'); el.textContent = msg; el.classList.remove('hidden'); }
function closeDMModal() { $('dm-key-modal').classList.add('hidden'); state.pendingDmFp = null; }

// ═══════════════════════════════════════════════════════
// MESSAGING
// ═══════════════════════════════════════════════════════

async function sendMessage() {
  if (!state.me) return;
  const text = $('msg-input').value.trim();
  if (!text) return;
  $('msg-input').value = '';
  if (state.view === 'dm') await sendDM(text);
  else                     await sendChannelMessage(text);
}

async function sendChannelMessage(text) {
  const aesKey = state.channelKeys[state.channel];
  if (!aesKey) { toast('Set a channel passphrase first'); return; }

  const ts         = Date.now();
  const sigPayload = JSON.stringify({ text, channel: state.channel, author: state.me.fingerprint, ts });
  const sig        = await signData(sigPayload, state.me.signingKey, state.me.algo);
  const envelope   = JSON.stringify({
    text, sig, sigPayload, algo: state.me.algo,
    author: state.me.fingerprint, handle: state.me.handle,
    publicKeyPem: state.me.publicKeyPem, ts,
  });
  const ciphertext = await aesEncrypt(envelope, aesKey);

  persist('cipher_msgs_' + state.channel, { ciphertext, ts, authorHint: state.me.fingerprint.slice(0, 6) });
  renderMessage({ text, author: state.me.handle, fingerprint: state.me.fingerprint, ts, verified: true, enc: 'AES-256-GCM' });
  scrollToBottom();
}

async function sendDM(text) {
  const fp    = state.dmPeer.fingerprint;
  const dmKey = state.dmKeys[fp];
  if (!dmKey) { toast('DM key not established'); return; }

  const ts         = Date.now();
  const sigPayload = JSON.stringify({ text, dm: true, to: fp, from: state.me.fingerprint, ts });
  const sig        = await signData(sigPayload, state.me.signingKey, state.me.algo);
  const envelope   = JSON.stringify({
    text, sig, sigPayload, algo: state.me.algo,
    from: state.me.fingerprint, handle: state.me.handle,
    publicKeyPem: state.me.publicKeyPem, ts,
  });
  const ciphertext = await aesEncrypt(envelope, dmKey);

  persist(dmStorageKey(state.me.fingerprint, fp), { ciphertext, ts, authorHint: state.me.fingerprint.slice(0, 6) });
  renderMessage({ text, author: state.me.handle, fingerprint: state.me.fingerprint, ts, verified: true, enc: 'ECDH-P256+AES', dm: true });
  scrollToBottom();
}

function dmStorageKey(a, b) { return 'cipher_dm_' + [a, b].sort().join('_'); }

function persist(key, entry) {
  try {
    const arr = JSON.parse(localStorage.getItem(key) || '[]');
    arr.push(entry);
    if (arr.length > 200) arr.splice(0, arr.length - 200);
    localStorage.setItem(key, JSON.stringify(arr));
  } catch { /* storage full */ }
}

async function loadHistory() {
  if (state.view === 'dm') await loadDMHistory(state.dmPeer.fingerprint);
  else                     await loadChannelHistory(state.channel);
}

async function loadChannelHistory(channel) {
  const aesKey = state.channelKeys[channel];
  const stored = JSON.parse(localStorage.getItem('cipher_msgs_' + channel) || '[]');
  for (const entry of stored) {
    if (!aesKey) { renderLocked(entry.ts, entry.authorHint, false); continue; }
    try {
      const env      = JSON.parse(await aesDecrypt(entry.ciphertext, aesKey));
      const verified = await verifyData(env.sigPayload, env.sig, env.publicKeyPem, env.algo);
      renderMessage({ text: env.text, author: env.handle, fingerprint: env.author, ts: env.ts, verified, enc: 'AES-256-GCM' });
    } catch { renderLocked(entry.ts, entry.authorHint, true); }
  }
  scrollToBottom();
}

async function loadDMHistory(peerFp) {
  const dmKey  = state.dmKeys[peerFp];
  const stored = JSON.parse(localStorage.getItem(dmStorageKey(state.me.fingerprint, peerFp)) || '[]');
  for (const entry of stored) {
    if (!dmKey) { renderLocked(entry.ts, entry.authorHint, false); continue; }
    try {
      const env      = JSON.parse(await aesDecrypt(entry.ciphertext, dmKey));
      const verified = await verifyData(env.sigPayload, env.sig, env.publicKeyPem, env.algo);
      renderMessage({ text: env.text, author: env.handle, fingerprint: env.from, ts: env.ts, verified, enc: 'ECDH-P256+AES', dm: true });
    } catch { renderLocked(entry.ts, entry.authorHint, true); }
  }
  scrollToBottom();
}

// ═══════════════════════════════════════════════════════
// RENDER
// ═══════════════════════════════════════════════════════

function renderMessage(msg) {
  const isMe = state.me && msg.fingerprint === state.me.fingerprint;
  const div  = document.createElement('div'); div.className = 'msg';
  const meta = document.createElement('div'); meta.className = 'msg-meta';

  const author = document.createElement('span');
  author.className   = 'msg-author' + (isMe ? ' me' : '') + (msg.system ? ' system' : '');
  author.title       = msg.fingerprint ? 'fp: ' + msg.fingerprint : '';
  author.textContent = msg.author;
  meta.appendChild(author);

  const timeEl = document.createElement('span');
  timeEl.className   = 'msg-time';
  timeEl.textContent = new Date(msg.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  meta.appendChild(timeEl);

  if (!msg.system && msg.verified !== undefined) {
    const sigEl  = document.createElement('span'); sigEl.className = 'msg-sig';
    const icon   = document.createElement('span'); icon.className = 'verified-icon';
    icon.textContent = msg.verified ? '✓' : '✗';
    sigEl.appendChild(icon);
    sigEl.appendChild(document.createTextNode(msg.verified ? 'SIGNED' : 'INVALID'));
    meta.appendChild(sigEl);
  }

  if (msg.enc) {
    const encEl = document.createElement('div');
    encEl.className   = msg.dm ? 'msg-dm-badge' : 'msg-enc';
    encEl.textContent = msg.enc;
    meta.appendChild(encEl);
  }

  const body = document.createElement('div');
  body.className   = 'msg-body' + (msg.system ? ' system' : '');
  body.textContent = msg.text;

  div.appendChild(meta); div.appendChild(body);
  $('messages').appendChild(div);
}

function renderLocked(ts, hint, wrongKey) {
  const div  = document.createElement('div'); div.className = 'msg';
  const meta = document.createElement('div'); meta.className = 'msg-meta';
  const a    = document.createElement('span'); a.className = 'msg-author system';
  a.textContent = hint ? '...' + hint : '??????';
  const t = document.createElement('span'); t.className = 'msg-time';
  t.textContent = new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const e = document.createElement('div');
  e.className   = 'msg-enc' + (wrongKey ? ' failed' : '');
  e.textContent = wrongKey ? 'WRONG KEY' : 'LOCKED';
  meta.appendChild(a); meta.appendChild(t); meta.appendChild(e);
  const body = document.createElement('div'); body.className = 'msg-body system';
  body.textContent = wrongKey ? '[decryption failed — wrong passphrase or key]' : '[encrypted — key required to read]';
  div.appendChild(meta); div.appendChild(body);
  $('messages').appendChild(div);
}

function sysMsg(text) {
  renderMessage({ text, author: 'SYSTEM', fingerprint: '', ts: Date.now(), system: true });
  scrollToBottom();
}

function scrollToBottom() { const m = $('messages'); m.scrollTop = m.scrollHeight; }

// ═══════════════════════════════════════════════════════
// IDENTITY EXPORT / IMPORT
// ═══════════════════════════════════════════════════════

function exportIdentity() {
  if (!state.me) { toast('Sign in first'); return; }
  downloadJSON({
    cipher_version: 2, type: 'public_identity',
    handle: state.me.handle, fingerprint: state.me.fingerprint,
    publicKeyPem: state.me.publicKeyPem,
    dhPubKeyPem:  state.me.dhPubKeyPem,
    exportedAt: new Date().toISOString(),
    note: 'Public keys only. Safe to share. Includes ECDH P-256 DM key.',
  }, 'cipher-identity-' + state.me.handle + '.json');
  toast('Public identity exported');
}

function exportFullBackup() {
  if (!state.me) { toast('Sign in first'); return; }
  const users    = getStoredUsers();
  const channels = ['general', 'random', 'tech'].reduce((acc, ch) => {
    try { acc[ch] = JSON.parse(localStorage.getItem('cipher_msgs_' + ch) || '[]'); } catch {}
    return acc;
  }, {});
  const dms = {};
  Object.keys(users).forEach(fp => {
    if (fp === state.me.fingerprint) return;
    const raw = localStorage.getItem(dmStorageKey(state.me.fingerprint, fp));
    if (raw) dms[fp] = JSON.parse(raw);
  });
  downloadJSON({
    cipher_version: 2, type: 'full_backup',
    myFingerprint: state.me.fingerprint,
    exportedAt: new Date().toISOString(), users, channels, dms,
    note: 'Encrypted ciphertext + public keys only. Private signing key NOT included. Paste it on import.',
  }, 'cipher-backup-' + state.me.handle + '-' + Date.now() + '.json');
  toast('Full backup exported');
}

function downloadJSON(data, filename) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  const a   = Object.assign(document.createElement('a'), { href: url, download: filename });
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ── Drag/drop identity file ──

function handleDragOver(e)  { e.preventDefault(); $('drop-zone').classList.add('drag-over'); }
function handleDragLeave()  { $('drop-zone').classList.remove('drag-over'); }
function handleDrop(e) {
  e.preventDefault(); $('drop-zone').classList.remove('drag-over');
  if (e.dataTransfer.files[0]) readIdentityFile(e.dataTransfer.files[0]);
}

function readIdentityFile(file) {
  const r = new FileReader();
  r.onload = e => {
    try { applyIdentityFile(JSON.parse(e.target.result)); }
    catch { showLoginError('Invalid file — expected JSON.'); }
  };
  r.readAsText(file);
}

function applyIdentityFile(data) {
  if (!data.cipher_version) { showLoginError('Not a CIPHER//NET file.'); return; }

  // Always ensure the import tab is visible when loading a file
  switchLockTab('login');

  if (data.type === 'full_backup') {
    if (data.users)
      localStorage.setItem('cipher_users', JSON.stringify({ ...getStoredUsers(), ...data.users }));
    if (data.channels)
      for (const [ch, msgs] of Object.entries(data.channels))
        if (Array.isArray(msgs) && msgs.length)
          localStorage.setItem('cipher_msgs_' + ch, JSON.stringify(msgs));
    if (data.dms)
      for (const [fp, msgs] of Object.entries(data.dms)) {
        const key = dmStorageKey(data.myFingerprint, fp);
        if (Array.isArray(msgs) && msgs.length)
          localStorage.setItem(key, JSON.stringify(msgs));
      }

    const handle = data.myFingerprint && data.users?.[data.myFingerprint]?.handle;
    if (handle) $('login-username').value = handle;

    showIdentityPreview({ type: 'full_backup', userCount: Object.keys(data.users || {}).length });
    toast('Backup restored — paste your private signing key below');
    return;
  }

  // public_identity file
  if (data.handle) $('login-username').value = data.handle;
  if (data.fingerprint && data.publicKeyPem) {
    const users = getStoredUsers();
    users[data.fingerprint] = {
      handle: data.handle, publicKeyPem: data.publicKeyPem,
      fingerprint: data.fingerprint, dhPubKeyPem: data.dhPubKeyPem || null,
    };
    localStorage.setItem('cipher_users', JSON.stringify(users));
  }
  showIdentityPreview(data);
  toast('Identity loaded — paste your private key below');
}

function showIdentityPreview(data) {
  const el = $('identity-preview');
  el.classList.remove('hidden'); el.innerHTML = '';
  const lbl = document.createElement('div'); lbl.className = 'ip-label';
  lbl.textContent = data.type === 'full_backup' ? '// BACKUP RESTORED' : '// IDENTITY FILE LOADED';
  el.appendChild(lbl);
  const lines = data.type === 'full_backup'
    ? [data.userCount + ' user(s) restored. Paste your private signing key below to continue.']
    : [
        'Handle:      ' + (data.handle || '?'),
        'Fingerprint: ' + (data.fingerprint || '?'),
        'DM key:      ' + (data.dhPubKeyPem ? 'present' : 'not in file'),
        'Paste your private signing key below.',
      ];
  lines.forEach(t => { const d = document.createElement('div'); d.textContent = t; el.appendChild(d); });
}

function showStorageWarning() {
  if (sessionStorage.getItem('cipher_warn_dismissed')) return;
  $('storage-warning').classList.remove('hidden');
}
function dismissStorageWarning() {
  $('storage-warning').classList.add('hidden');
  sessionStorage.setItem('cipher_warn_dismissed', '1');
}

// ═══════════════════════════════════════════════════════
// CHANNEL SWITCHING
// ═══════════════════════════════════════════════════════

function switchChannel(ch) {
  state.view   = 'channel';
  state.channel = ch;
  state.dmPeer  = null;

  document.querySelectorAll('.channel-item, .dm-item').forEach(el => el.classList.remove('active'));
  document.querySelector('.channel-item[data-channel="' + ch + '"]').classList.add('active');

  $('channel-title').textContent = '# ' + ch;
  $('channel-desc').textContent  = CHANNEL_DESCS[ch] || '';
  $('passphrase-wrap').classList.remove('hidden');
  $('dm-header-info').classList.add('hidden');

  updateEncStatus(!!state.channelKeys[ch]);
  $('messages').innerHTML = '';
  updateMsgInput();
  loadChannelHistory(ch);
}

// ═══════════════════════════════════════════════════════
// AUTH / USER MANAGEMENT
// ═══════════════════════════════════════════════════════

function onAuthenticated() {
  updateMsgInput();
  updateUserBadge();
  updateUserList();
  $('auth-btn').textContent = '[ ' + state.me.handle.toUpperCase() + ' // ONLINE ]';
  $('identity-actions').classList.remove('hidden');
  $('identity-actions').classList.add('visible');
  loadChannelHistory(state.channel);
  showStorageWarning();
}

function updateMsgInput() {
  let enabled, hint, placeholder;
  if (state.view === 'dm') {
    const hasDmKey = state.dmPeer && !!state.dmKeys[state.dmPeer.fingerprint];
    enabled     = hasDmKey;
    placeholder = hasDmKey ? 'DM @' + state.dmPeer.handle + ' (ECDH P-256 encrypted)...' : 'Establishing DM key...';
    hint        = hasDmKey
      ? '> ECDH-P384 · AES-256-GCM · ECDSA-P256 SIGNED · to:' + state.dmPeer.handle
      : '> DM KEY NOT YET ESTABLISHED';
  } else {
    const hasKey = !!state.channelKeys[state.channel];
    enabled     = hasKey;
    placeholder = hasKey ? 'Message #' + state.channel + ' (AES-256-GCM encrypted)...' : 'Set a channel passphrase to send...';
    hint        = hasKey
      ? '> ' + state.me.handle.toUpperCase() + ' · AES-256-GCM · ECDSA-P256 SIGNED · fp:' + state.me.fingerprint
      : '> SET A CHANNEL PASSPHRASE — PBKDF2-SHA384 · 600k iterations · AES-256-GCM';
  }
  $('msg-input').disabled    = !enabled;
  $('btn-send').disabled     = !enabled;
  $('msg-input').placeholder = placeholder;
  $('input-hint').textContent = hint;
}

function updateUserBadge() {
  if (!state.me) return;
  const badge = $('user-badge');
  badge.classList.remove('hidden'); badge.classList.add('visible');
  badge.innerHTML = '';
  const dot = document.createElement('span'); dot.className = 'dot active';
  const fp  = document.createElement('span'); fp.className = 'badge-fp'; fp.textContent = state.me.fingerprint;
  badge.appendChild(dot);
  badge.appendChild(document.createTextNode(state.me.handle + ' '));
  badge.appendChild(fp);
}

function updateUserList() {
  const users   = getStoredUsers();
  const list    = $('user-list');
  list.innerHTML = '';
  const entries  = Object.values(users);
  if (!entries.length) {
    const e = document.createElement('div'); e.className = 'user-empty'; e.textContent = 'No users';
    list.appendChild(e); return;
  }
  entries.forEach(u => {
    const isMe = state.me && u.fingerprint === state.me.fingerprint;
    const div  = document.createElement('div');
    div.className = 'user-item' + (isMe ? ' me' : '');
    div.title     = 'fp: ' + u.fingerprint + (u.dhPubKeyPem ? ' · DM key present' : ' · No DM key');
    const dot = document.createElement('span'); dot.className = 'user-dot' + (isMe ? ' online' : '');
    const fp  = document.createElement('span'); fp.className = 'user-fp'; fp.textContent = u.fingerprint.slice(0, 6);
    div.appendChild(dot);
    div.appendChild(document.createTextNode(u.handle));
    div.appendChild(fp);
    if (!isMe) div.addEventListener('click', () => openDM(u.fingerprint));
    list.appendChild(div);
  });
  document.querySelectorAll('.online-count').forEach(el => el.textContent = entries.length);
}

function getStoredUsers() {
  try { return JSON.parse(localStorage.getItem('cipher_users') || '{}'); } catch { return {}; }
}

// ═══════════════════════════════════════════════════════
// COPY / TOAST / HELPERS
// ═══════════════════════════════════════════════════════

function copyKey(which) {
  const text = which === 'priv' ? state.generatedPrivPem : state.generatedPubPem;
  if (!text) return;
  navigator.clipboard.writeText(text)
    .then(() => toast('Copied'))
    .catch(() => {
      const ta = Object.assign(document.createElement('textarea'), { value: text });
      document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta);
      toast('Copied');
    });
}

let toastTimer;
function toast(msg) {
  const el = $('toast');
  el.textContent = '// ' + msg;
  el.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('show'), 3000);
}

function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function $(id) { return document.getElementById(id); }

// ═══════════════════════════════════════════════════════
// BOOT
// ═══════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {

  if (!window.crypto || !window.crypto.subtle) {
    document.body.innerHTML = '<div class="no-crypto">Web Crypto API unavailable. CIPHER//NET requires HTTPS, a .onion address, or localhost.</div>';
    return;
  }

  // ── Lock screen ──
  $('lock-tab-register').addEventListener('click', () => switchLockTab('register'));
  $('lock-tab-login').addEventListener('click',    () => switchLockTab('login'));
  $('btn-gen').addEventListener('click', generateKeys);
  $('btn-activate').addEventListener('click', activateAccount);
  $('copy-priv-btn').addEventListener('click', () => copyKey('priv'));
  $('copy-pub-btn').addEventListener('click',  () => copyKey('pub'));
  $('btn-import').addEventListener('click', importKey);

  const dz = $('drop-zone');
  dz.addEventListener('click',     () => $('identity-file-input').click());
  dz.addEventListener('dragover',  handleDragOver);
  dz.addEventListener('dragleave', handleDragLeave);
  dz.addEventListener('drop',      handleDrop);
  $('identity-file-input').addEventListener('change', e => {
    if (e.target.files[0]) readIdentityFile(e.target.files[0]);
  });

  // ── App ──
  $('auth-btn').addEventListener('click', () => {
    if (confirm('Sign out? You will need your private signing key to re-authenticate.')) location.reload();
  });
  $('warn-export-btn').addEventListener('click', exportIdentity);
  $('dismiss-warn-btn').addEventListener('click', dismissStorageWarning);
  $('btn-export-identity').addEventListener('click', exportIdentity);
  $('btn-export-backup').addEventListener('click', exportFullBackup);

  document.querySelectorAll('.channel-item').forEach(el =>
    el.addEventListener('click', () => switchChannel(el.dataset.channel))
  );

  $('msg-input').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });
  $('btn-send').addEventListener('click', sendMessage);

  $('btn-set-passphrase').addEventListener('click', setChannelPassphrase);
  $('channel-passphrase').addEventListener('keydown', e => {
    if (e.key === 'Enter') { e.preventDefault(); setChannelPassphrase(); }
  });

  // DM modal
  $('dm-modal-cancel').addEventListener('click', closeDMModal);
  $('dm-modal-confirm').addEventListener('click', confirmDMKeyExchange);

  // ── Returning user ──
  const myFp  = localStorage.getItem('cipher_my_fingerprint');
  const users = getStoredUsers();
  if (myFp && users[myFp]) {
    switchLockTab('login');
    $('login-username').value = users[myFp].handle;
    toast('Welcome back ' + users[myFp].handle + ' — paste your private key');
  }
});
