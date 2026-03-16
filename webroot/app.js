'use strict';

// Pure-JS base64 encode/decode — avoids atob/btoa which SES lockdown
// (MetaMask and similar extensions) may freeze or alter.
const B64CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/';
function b64Encode(bytes) {
  let out = '', i = 0;
  while (i < bytes.length) {
    const a = bytes[i++], b = bytes[i++], c = bytes[i++];
    out += B64CHARS[a >> 2]
        +  B64CHARS[((a & 3) << 4) | (b >> 4)]
        +  (b !== undefined ? B64CHARS[((b & 15) << 2) | (c >> 6)] : '=')
        +  (c !== undefined ? B64CHARS[c & 63] : '=');
  }
  return out;
}
function b64Decode(s) {
  s = s.replace(/[^A-Za-z0-9+/]/g, '');
  const lookup = new Uint8Array(256);
  for (let i = 0; i < B64CHARS.length; i++) lookup[B64CHARS.charCodeAt(i)] = i;
  const bytes = new Uint8Array(Math.floor(s.length * 3 / 4));
  let j = 0;
  for (let i = 0; i < s.length; i += 4) {
    const a = lookup[s.charCodeAt(i)], b = lookup[s.charCodeAt(i+1)],
          c = lookup[s.charCodeAt(i+2)], d = lookup[s.charCodeAt(i+3)];
    bytes[j++] = (a << 2) | (b >> 4);
    if (s[i+2] !== '=') bytes[j++] = ((b & 15) << 4) | (c >> 2);
    if (s[i+3] !== '=') bytes[j++] = ((c & 3)  << 6) | d;
  }
  return bytes.slice(0, j);
}


// ═══════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════
const state = {
  me: null,          // { handle, publicKeyPem, signingKey, fingerprint, algo, dhPrivKey, dhPubKeyPem }
  view: 'channel',
  channel: 'general',
  dmPeer: null,
  channelKeys: {},
  dmKeys: {},
  pendingDmFp: null,
  generatedPrivPem:    null,
  generatedPubPem:     null,
  generatedCryptoKeys: null,
  generatedDHKeys:     null,
  generatedDHPubPem:   null,
};

const CHANNEL_DESCS = {
  general: 'AES-256-GCM encrypted · shared passphrase · ECDSA signed',
  random:  'AES-256-GCM encrypted · shared passphrase',
  tech:    'AES-256-GCM encrypted · shared passphrase',
};

// ═══════════════════════════════════════════════════════
// PEM HELPERS
// ═══════════════════════════════════════════════════════

function toPem(buffer, label) {
  const b64 = b64Encode(new Uint8Array(buffer));
  return `-----BEGIN ${label}-----\n${b64.match(/.{1,64}/g).join('\n')}\n-----END ${label}-----`;
}

function fromPem(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s+/g, '');
  return b64Decode(b64).buffer;
}

async function exportPrivPem(key) { return toPem(await crypto.subtle.exportKey('pkcs8', key), 'PRIVATE KEY'); }
async function exportPubPem(key)  { return toPem(await crypto.subtle.exportKey('spki',  key), 'PUBLIC KEY'); }

// ═══════════════════════════════════════════════════════
// SIGNING — ECDSA P-256 / P-384 / RSA-PSS
// ═══════════════════════════════════════════════════════

async function generateECDSA(namedCurve) {
  return crypto.subtle.generateKey({ name: 'ECDSA', namedCurve }, true, ['sign', 'verify']);
}

async function generateRSAPSS() {
  return crypto.subtle.generateKey(
    { name: 'RSA-PSS', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
    true, ['sign', 'verify']
  );
}

// Import a private key — tries every algorithm this app has ever used.
async function importPrivateKey(pem) {
  pem = pem.trim();
  if (pem.includes('-----BEGIN PUBLIC KEY-----') || pem.includes('-----BEGIN EC PUBLIC KEY-----')) {
    throw new Error('You pasted your PUBLIC key. Paste the PRIVATE key instead (labeled "Signing Private Key").');
  }
  if (!pem.includes('-----BEGIN') || !pem.includes('PRIVATE KEY')) {
    throw new Error('This does not look like a private key. Copy the full PEM including -----BEGIN PRIVATE KEY----- and -----END PRIVATE KEY----- lines.');
  }

  const der = fromPem(pem);
  const errors = [];

  // For each EC curve, try both PKCS#8-direct and PKCS#8→JWK→re-import paths.
  // The JWK path is needed when the key was generated with ECDH usage (deriveKey)
  // instead of ECDSA usage (sign) — both produce identical PKCS#8 bytes but
  // browsers enforce the original key_ops on re-import via pkcs8.
  // Going via JWK and deleting key_ops bypasses this restriction on all browsers.
  for (const curve of ['P-256', 'P-384']) {
    const sigAlg = { name: 'ECDSA', namedCurve: curve };

    // Path A: direct pkcs8 → ECDSA (works when key was generated as ECDSA)
    try {
      const key = await crypto.subtle.importKey('pkcs8', der, sigAlg, true, ['sign']);
      const pub = await derivePublicFromPrivate(key, sigAlg);
      return { privateKey: key, publicKey: pub, algorithm: sigAlg };
    } catch (e) { errors.push('ECDSA-' + curve + '-direct: ' + (e.message || e)); }

    // Path B: pkcs8 → ECDH → export JWK (drop key_ops) → re-import as ECDSA
    // Works when key was generated as ECDH (e.g. old buggy build showed DM key)
    for (const importAs of ['ECDH', 'ECDSA']) {
      const importAlg = importAs === 'ECDH'
        ? { name: 'ECDH',  namedCurve: curve }
        : { name: 'ECDSA', namedCurve: curve };
      const importUsage = importAs === 'ECDH' ? ['deriveKey'] : ['sign', 'verify'];
      try {
        const tmp = await crypto.subtle.importKey('pkcs8', der, importAlg, true, importUsage);
        const jwk = await crypto.subtle.exportKey('jwk', tmp);
        delete jwk.key_ops;   // drop usage restriction — let algorithm govern
        delete jwk.ext;
        const key = await crypto.subtle.importKey('jwk', jwk, sigAlg, true, ['sign']);
        const pub = await derivePublicFromPrivate(key, sigAlg);
        return { privateKey: key, publicKey: pub, algorithm: sigAlg };
      } catch (e) { errors.push('ECDSA-' + curve + '-via-' + importAs + '-JWK: ' + (e.message || e)); }
    }
  }

  // RSA-PSS (pkcs8 only — no JWK fallback needed, RSA doesn't have the curve mismatch problem)
  try {
    const alg = { name: 'RSA-PSS', hash: 'SHA-256' };
    const key = await crypto.subtle.importKey('pkcs8', der, alg, true, ['sign']);
    const pub = await derivePublicFromPrivate(key, alg);
    return { privateKey: key, publicKey: pub, algorithm: alg };
  } catch (e) { errors.push('RSA-PSS: ' + (e.message || e)); }

  throw new Error('Could not import key. All attempts failed:\n' + errors.join('\n'));
}

async function derivePublicFromPrivate(privateKey, alg) {
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  ['d','p','q','dp','dq','qi','key_ops'].forEach(k => delete jwk[k]);
  const pubAlg = alg.name === 'ECDSA'
    ? { name: 'ECDSA', namedCurve: alg.namedCurve }
    : { name: 'RSA-PSS', hash: 'SHA-256' };
  return crypto.subtle.importKey('jwk', jwk, pubAlg, true, ['verify']);
}

async function fingerprint(pubKeyPem) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pubKeyPem));
  return Array.from(new Uint8Array(hash)).slice(0, 8).map(b => b.toString(16).padStart(2,'0')).join('');
}

function getSignAlg(algo) {
  if (!algo || algo.name === 'ECDSA') {
    const curve = algo && algo.namedCurve;
    return { name: 'ECDSA', hash: curve === 'P-384' ? 'SHA-384' : 'SHA-256' };
  }
  return { name: 'RSA-PSS', saltLength: 32 };
}

async function signData(text, privateKey, algo) {
  const sig = await crypto.subtle.sign(getSignAlg(algo), privateKey, new TextEncoder().encode(text));
  return b64Encode(new Uint8Array(sig));
}

async function verifyData(text, sigB64, pubKeyPem, algo) {
  try {
    algo = algo || { name: 'ECDSA', namedCurve: 'P-256' };
    const importAlg = algo.name === 'ECDSA'
      ? { name: 'ECDSA', namedCurve: algo.namedCurve || 'P-256' }
      : { name: 'RSA-PSS', hash: 'SHA-256' };
    const key = await crypto.subtle.importKey('spki', fromPem(pubKeyPem), importAlg, false, ['verify']);
    return crypto.subtle.verify(getSignAlg(algo), key,
      b64Decode(sigB64),
      new TextEncoder().encode(text));
  } catch { return false; }
}

// ═══════════════════════════════════════════════════════
// ECDH P-256 — DM key exchange
// ═══════════════════════════════════════════════════════

async function generateDHKeypair() {
  return crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
}

async function deriveSharedDMKey(myDhPrivKey, theirDhPubKeyPem) {
  const theirPub = await crypto.subtle.importKey(
    'spki', fromPem(theirDhPubKeyPem), { name: 'ECDH', namedCurve: 'P-256' }, false, []
  );
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: theirPub },
    myDhPrivKey,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function persistDHPrivKey(dhPrivKey, fp) {
  const wrapKey = await derivePersistKey(fp);
  const iv      = crypto.getRandomValues(new Uint8Array(12));
  const raw     = await crypto.subtle.exportKey('pkcs8', dhPrivKey);
  const wrapped = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, wrapKey, raw);
  const out     = new Uint8Array(12 + wrapped.byteLength);
  out.set(iv, 0); out.set(new Uint8Array(wrapped), 12);
  localStorage.setItem('cipher_dh_' + fp, b64Encode(out));
}

async function loadDHPrivKey(fp) {
  const stored = localStorage.getItem('cipher_dh_' + fp);
  if (!stored) return null;
  const buf     = b64Decode(stored);
  const wrapKey = await derivePersistKey(fp);
  try {
    const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0,12) }, wrapKey, buf.slice(12));
    return crypto.subtle.importKey('pkcs8', raw, { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey']);
  } catch { return null; }
}

async function derivePersistKey(fp) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(fp), 'PBKDF2', false, ['deriveKey']);
  const salt = await crypto.subtle.digest('SHA-256', new TextEncoder().encode('cipher-dh-wrap:' + fp));
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function deriveDHPubFromPriv(dhPrivKey) {
  const jwk = await crypto.subtle.exportKey('jwk', dhPrivKey);
  delete jwk.d;
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
}

// ═══════════════════════════════════════════════════════
// AES-256-GCM
// ═══════════════════════════════════════════════════════

async function aesEncrypt(plaintext, key) {
  const iv  = crypto.getRandomValues(new Uint8Array(12));
  const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(plaintext));
  const out = new Uint8Array(12 + ct.byteLength);
  out.set(iv, 0); out.set(new Uint8Array(ct), 12);
  return b64Encode(out);
}

async function aesDecrypt(b64, key) {
  const buf   = b64Decode(b64);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0,12) }, key, buf.slice(12));
  return new TextDecoder().decode(plain);
}

// ═══════════════════════════════════════════════════════
// PASSWORD-PROTECTED KEY EXPORT / IMPORT
// Format: CIPHER-ENC:v1:<base64(16-byte-salt + 12-byte-iv + ciphertext)>
// Key: PBKDF2-SHA-256, 300 000 iterations, 32-byte output → AES-256-GCM
// ═══════════════════════════════════════════════════════

const ENC_PREFIX  = 'CIPHER-ENC:v1:';
const ENC_ITERS   = 300_000;

async function encryptPrivateKey(pemStr, password) {
  const enc      = new TextEncoder();
  const salt     = crypto.getRandomValues(new Uint8Array(16));
  const iv       = crypto.getRandomValues(new Uint8Array(12));
  const baseKey  = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  const aesKey   = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ENC_ITERS, hash: 'SHA-256' },
    baseKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
  );
  const ct       = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aesKey, enc.encode(pemStr));
  const out      = new Uint8Array(16 + 12 + ct.byteLength);
  out.set(salt, 0); out.set(iv, 16); out.set(new Uint8Array(ct), 28);
  return ENC_PREFIX + btoa(String.fromCharCode(...out));
}

async function decryptPrivateKey(encStr, password) {
  if (!encStr.startsWith(ENC_PREFIX))
    throw new Error('Not an encrypted key — paste your password-protected CIPHER-ENC export.');
  const enc     = new TextEncoder();
  const buf     = Uint8Array.from(atob(encStr.slice(ENC_PREFIX.length)), c => c.charCodeAt(0));
  const salt    = buf.slice(0, 16);
  const iv      = buf.slice(16, 28);
  const ct      = buf.slice(28);
  const baseKey = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  const aesKey  = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: ENC_ITERS, hash: 'SHA-256' },
    baseKey, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
  );
  try {
    const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, aesKey, ct);
    return new TextDecoder().decode(plain);
  } catch {
    throw new Error('Wrong password — decryption failed.');
  }
}

function isEncryptedKey(str) {
  return str.trim().startsWith(ENC_PREFIX);
}

// ═══════════════════════════════════════════════════════
// PBKDF2 channel key
// ═══════════════════════════════════════════════════════

async function deriveChannelKey(passphrase, channel) {
  const enc  = new TextEncoder();
  const base = await crypto.subtle.importKey('raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']);
  const salt = await crypto.subtle.digest('SHA-256', enc.encode('cipher-channel:' + channel));
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
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
    sysMsg('Channel key active. AES-256-GCM encryption enabled.');
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
  if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) { toast('Handle: 3-32 chars, letters/numbers/underscores'); return; }

  const algo = $('reg-algo').value;
  const btn  = $('btn-gen');
  btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>GENERATING...';
  $('key-gen-area').classList.remove('hidden');
  animateProgress(0, 35, 500);

  let keys;
  try {
    if      (algo === 'ECDSA-P256') keys = await generateECDSA('P-256');
    else if (algo === 'ECDSA-P384') keys = await generateECDSA('P-384');
    else                            keys = await generateRSAPSS();
  } catch (e) {
    toast('Key generation failed: ' + e.message);
    btn.disabled = false; btn.innerHTML = 'GENERATE KEYPAIR'; return;
  }

  animateProgress(35, 65, 400);
  const dhKeys = await generateDHKeypair();
  animateProgress(65, 90, 300);

  const privPem  = await exportPrivPem(keys.privateKey);
  const pubPem   = await exportPubPem(keys.publicKey);
  const dhPubPem = await exportPubPem(dhKeys.publicKey);
  animateProgress(90, 100, 200);

  state.generatedPrivPem    = privPem;
  state.generatedPubPem     = pubPem;
  state.generatedCryptoKeys = keys;
  state.generatedDHKeys     = dhKeys;
  state.generatedDHPubPem   = dhPubPem;
  state.generatedAlgo = algo === 'ECDSA-P256' ? { name: 'ECDSA', namedCurve: 'P-256' }
                      : algo === 'ECDSA-P384' ? { name: 'ECDSA', namedCurve: 'P-384' }
                      : { name: 'RSA-PSS', hash: 'SHA-256' };

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
  users[fp] = {
    handle: username, publicKeyPem: state.generatedPubPem,
    fingerprint: fp, algo: state.generatedAlgo,
    dhPubKeyPem: state.generatedDHPubPem,
    registeredAt: Date.now(),
  };
  localStorage.setItem('cipher_users', JSON.stringify(users));
  localStorage.setItem('cipher_my_fingerprint', fp);

  state.me = {
    handle: username, publicKeyPem: state.generatedPubPem,
    signingKey: state.generatedCryptoKeys.privateKey,
    fingerprint: fp, algo: state.generatedAlgo,
    dhPrivKey: state.generatedDHKeys.privateKey,
    dhPubKeyPem: state.generatedDHPubPem,
  };

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
  const privPem        = $('login-privkey').value.trim();
  const handleOverride = $('login-username').value.trim();
  hideLoginError();
  if (!privPem) { showLoginError('Paste your private key.'); return; }

  const btn = $('btn-import');
  btn.textContent = 'VERIFYING...'; btn.disabled = true;

  // If the pasted value is a CIPHER-ENC encrypted key, decrypt it first
  let pemToImport = privPem;
  if (isEncryptedKey(privPem)) {
    const pw = $('import-password') && $('import-password').value.trim();
    if (!pw) {
      showLoginError('This key is password-protected. Enter the password in the field above.');
      // Show the password field if hidden
      const pg = $('import-password-group');
      if (pg) { pg.style.display = ''; pg.classList.remove('hidden'); }
      $('import-password') && $('import-password').focus();
      btn.textContent = 'IMPORT AND ENTER'; btn.disabled = false; return;
    }
    btn.textContent = 'DECRYPTING...';
    try {
      pemToImport = await decryptPrivateKey(privPem, pw);
    } catch (e) {
      showLoginError(e.message);
      btn.textContent = 'IMPORT AND ENTER'; btn.disabled = false; return;
    }
  }

  let keyData;
  try {
    keyData = await importPrivateKey(pemToImport);
  } catch (e) {
    showLoginError(e.message);
    btn.textContent = 'IMPORT AND ENTER'; btn.disabled = false; return;
  }

  const pubPem = await exportPubPem(keyData.publicKey);
  const fp     = await fingerprint(pubPem);
  const users  = getStoredUsers();
  const handle = handleOverride || (users[fp] && users[fp].handle) || 'user_' + fp.slice(0,6);

  let dhPrivKey, dhPubKeyPem;
  const storedDH = await loadDHPrivKey(fp);
  if (storedDH) {
    dhPrivKey   = storedDH;
    dhPubKeyPem = await exportPubPem(await deriveDHPubFromPriv(dhPrivKey));
  } else {
    const dhKeys = await generateDHKeypair();
    dhPrivKey    = dhKeys.privateKey;
    dhPubKeyPem  = await exportPubPem(dhKeys.publicKey);
    await persistDHPrivKey(dhPrivKey, fp);
  }

  const existingUser = users[fp] || {};
  users[fp] = { ...existingUser, handle, publicKeyPem: pubPem, fingerprint: fp, algo: keyData.algorithm, dhPubKeyPem };
  localStorage.setItem('cipher_users', JSON.stringify(users));
  localStorage.setItem('cipher_my_fingerprint', fp);

  state.me = { handle, publicKeyPem: pubPem, signingKey: keyData.privateKey, fingerprint: fp, algo: keyData.algorithm, dhPrivKey, dhPubKeyPem };

  // Clear sensitive fields before entering app
  $('login-privkey').value   = '';
  $('login-username').value  = '';
  $('import-password').value = '';
  hideLoginError();

  btn.textContent = 'IMPORT AND ENTER'; btn.disabled = false;
  enterApp();
  sysMsg(handle + ' connected.');
  toast('Signed in as ' + handle);
}

function showLoginError(msg) { const el = $('login-error'); el.textContent = msg; el.classList.remove('hidden'); }
function hideLoginError()    { $('login-error').classList.add('hidden'); }

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
  if (!peer) { toast('User not found'); return; }
  if (state.dmKeys[fp]) { activateDMView(peer); return; }
  if (peer.dhPubKeyPem) {
    try {
      state.dmKeys[fp] = await deriveSharedDMKey(state.me.dhPrivKey, peer.dhPubKeyPem);
      activateDMView(peer); return;
    } catch (e) { toast('DM key derivation failed: ' + e.message); return; }
  }
  state.pendingDmFp = fp;
  $('dm-modal-error').classList.add('hidden');
  $('dm-pubkey-input').value = '';
  $('dm-key-modal').classList.remove('hidden');
}

async function confirmDMKeyExchange() {
  const pem = $('dm-pubkey-input').value.trim();
  const fp  = state.pendingDmFp;
  if (!pem) { showDMModalError('Paste the recipient DM public key.'); return; }
  const btn = $('dm-modal-confirm');
  btn.textContent = 'DERIVING KEY...'; btn.disabled = true;
  try {
    state.dmKeys[fp] = await deriveSharedDMKey(state.me.dhPrivKey, pem);
    const users = getStoredUsers();
    if (users[fp]) { users[fp].dhPubKeyPem = pem; localStorage.setItem('cipher_users', JSON.stringify(users)); }
    closeDMModal();
    const peer = getStoredUsers()[fp];
    if (peer) activateDMView(peer);
    toast('DM key established — ECDH P-256');
  } catch (e) { showDMModalError('Key derivation failed: ' + e.message); }
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
  $('dm-fp').textContent = 'fp:' + peer.fingerprint.slice(0,12);
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
function closeDMModal()        { $('dm-key-modal').classList.add('hidden'); state.pendingDmFp = null; }

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
  persist('cipher_msgs_' + state.channel, { ciphertext, ts, authorHint: state.me.fingerprint.slice(0,6) });
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
  persist(dmStorageKey(state.me.fingerprint, fp), { ciphertext, ts, authorHint: state.me.fingerprint.slice(0,6) });
  renderMessage({ text, author: state.me.handle, fingerprint: state.me.fingerprint, ts, verified: true, enc: 'ECDH+AES', dm: true });
  scrollToBottom();
}

function dmStorageKey(a, b) { return 'cipher_dm_' + [a,b].sort().join('_'); }

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
      renderMessage({ text: env.text, author: env.handle, fingerprint: env.from, ts: env.ts, verified, enc: 'ECDH+AES', dm: true });
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
  timeEl.className = 'msg-time';
  timeEl.textContent = new Date(msg.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  meta.appendChild(timeEl);
  if (!msg.system && msg.verified !== undefined) {
    const sigEl = document.createElement('span'); sigEl.className = 'msg-sig';
    const icon  = document.createElement('span'); icon.className = 'verified-icon';
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
  const t   = document.createElement('span'); t.className = 'msg-time';
  t.textContent = new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const e   = document.createElement('div');
  e.className   = 'msg-enc' + (wrongKey ? ' failed' : '');
  e.textContent = wrongKey ? 'WRONG KEY' : 'LOCKED';
  meta.appendChild(a); meta.appendChild(t); meta.appendChild(e);
  const body = document.createElement('div'); body.className = 'msg-body system';
  body.textContent = wrongKey ? '[decryption failed - wrong passphrase or key]' : '[encrypted - key required to read]';
  div.appendChild(meta); div.appendChild(body);
  $('messages').appendChild(div);
}

function sysMsg(text) {
  renderMessage({ text, author: 'SYSTEM', fingerprint: '', ts: Date.now(), system: true });
  scrollToBottom();
}

function scrollToBottom() { const m = $('messages'); m.scrollTop = m.scrollHeight; }

// ═══════════════════════════════════════════════════════
// IDENTITY EXPORT / BACKUP
// ═══════════════════════════════════════════════════════

function exportIdentity() {
  if (!state.me) { toast('Sign in first'); return; }
  downloadJSON({
    cipher_version: 1, type: 'public_identity',
    handle: state.me.handle, fingerprint: state.me.fingerprint,
    publicKeyPem: state.me.publicKeyPem, algo: state.me.algo,
    dhPubKeyPem: state.me.dhPubKeyPem,
    exportedAt: new Date().toISOString(),
    note: 'Public keys only — safe to share. Includes DM public key for ECDH key exchange.',
  }, 'cipher-identity-' + state.me.handle + '.json');
  toast('Public identity exported');
}

function exportFullBackup() {
  if (!state.me) { toast('Sign in first'); return; }
  const users    = getStoredUsers();
  const channels = ['general','random','tech'].reduce((acc, ch) => {
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
    cipher_version: 1, type: 'full_backup',
    myFingerprint: state.me.fingerprint,
    exportedAt: new Date().toISOString(), users, channels, dms,
    note: 'Encrypted ciphertext + public keys. Private signing key NOT included — paste it on import.',
  }, 'cipher-backup-' + state.me.handle + '-' + Date.now() + '.json');
  toast('Full backup exported');
}

function downloadJSON(data, filename) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' }));
  const a   = Object.assign(document.createElement('a'), { href: url, download: filename });
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

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
    catch { showLoginError('Invalid JSON file.'); }
  };
  r.readAsText(file);
}

function applyIdentityFile(data) {
  if (!data.cipher_version) { showLoginError('Not a CIPHER//NET file.'); return; }

  // Always switch to the import tab so the user can paste their private key
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
    toast('Backup restored — paste your private key below');
    return;
  }

  if (data.handle) $('login-username').value = data.handle;
  if (data.fingerprint && data.publicKeyPem) {
    const users = getStoredUsers();
    users[data.fingerprint] = {
      handle: data.handle, publicKeyPem: data.publicKeyPem,
      fingerprint: data.fingerprint, algo: data.algo,
      dhPubKeyPem: data.dhPubKeyPem || null,
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
    ? [data.userCount + ' user(s) restored. Paste your private key below.']
    : ['Handle: ' + (data.handle||'?'), 'Fingerprint: ' + (data.fingerprint||'?'),
       'DM key: ' + (data.dhPubKeyPem ? 'present' : 'not in file'),
       'Paste your private key below.'];
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
  state.view    = 'channel';
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
  let enabled, placeholder, hint;
  if (state.view === 'dm') {
    const hasDmKey = state.dmPeer && !!state.dmKeys[state.dmPeer.fingerprint];
    enabled     = hasDmKey;
    placeholder = hasDmKey ? 'DM @' + state.dmPeer.handle + ' (ECDH encrypted)...' : 'Establishing DM key...';
    hint        = hasDmKey
      ? '> ECDH END-TO-END ENCRYPTED DM · ECDSA SIGNED · to:' + state.dmPeer.handle
      : '> DM KEY NOT ESTABLISHED';
  } else {
    const hasKey = !!state.channelKeys[state.channel];
    enabled     = hasKey;
    placeholder = hasKey ? 'Message #' + state.channel + ' (AES-256-GCM encrypted)...' : 'Set a channel passphrase to send messages...';
    hint        = state.me
      ? (hasKey
          ? '> ' + state.me.handle.toUpperCase() + ' · AES-256-GCM · ECDSA SIGNED · fp:' + state.me.fingerprint
          : '> SET A CHANNEL PASSPHRASE TO ENABLE ENCRYPTION')
      : '';
  }
  $('msg-input').disabled     = !enabled;
  $('btn-send').disabled      = !enabled;
  $('msg-input').placeholder  = placeholder;
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
    const fp  = document.createElement('span'); fp.className = 'user-fp'; fp.textContent = u.fingerprint.slice(0,6);
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

async function copyKey(which) {
  let text = which === 'priv' ? state.generatedPrivPem : state.generatedPubPem;
  if (!text) return;

  // If copying the private key and a password is set, encrypt it first
  if (which === 'priv') {
    const pw = $('export-password') && $('export-password').value;
    if (pw && pw.trim()) {
      const btn = $('copy-priv-btn');
      const orig = btn.textContent;
      btn.textContent = 'ENCRYPTING...'; btn.disabled = true;
      try {
        text = await encryptPrivateKey(text, pw.trim());
        $('export-hint').textContent = '✓ Encrypted key copied — you will need this password to import.';
        $('export-hint').style.color = 'var(--green3)';
      } catch (e) {
        toast('Encryption failed: ' + e.message);
        btn.textContent = orig; btn.disabled = false; return;
      }
      btn.textContent = orig; btn.disabled = false;
    } else {
      const hint = $('export-hint');
      if (hint) {
        hint.textContent = 'Plain key copied — no password set.';
        hint.style.color = 'var(--amber)';
      }
    }
  }

  navigator.clipboard.writeText(text)
    .then(() => toast(which === 'priv' ? 'Private key copied' : 'Public key copied'))
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
  toastTimer = setTimeout(() => el.classList.remove('show'), 2800);
}

function escHtml(s) { return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function $(id)      { return document.getElementById(id); }

// ═══════════════════════════════════════════════════════
// BOOT
// ═══════════════════════════════════════════════════════

// ═══════════════════════════════════════════════════════
// SERVICE WORKER REGISTRATION (PWA)
// ═══════════════════════════════════════════════════════
if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('./sw.js')
      .catch(err => console.warn('SW registration failed:', err));
  });
}

document.addEventListener('DOMContentLoaded', () => {

  if (!window.crypto || !window.crypto.subtle) {
    document.body.innerHTML = '<div class="no-crypto">Web Crypto API unavailable. Use HTTPS, .onion, or localhost.</div>';
    return;
  }

  $('lock-tab-register').addEventListener('click', () => switchLockTab('register'));
  $('lock-tab-login').addEventListener('click',    () => switchLockTab('login'));
  $('btn-gen').addEventListener('click', generateKeys);
  $('btn-activate').addEventListener('click', activateAccount);
  $('copy-priv-btn').addEventListener('click', () => copyKey('priv'));
  $('copy-pub-btn').addEventListener('click',  () => copyKey('pub'));
  $('btn-import').addEventListener('click', importKey);

  // Show password field automatically when an encrypted key is pasted
  $('login-privkey').addEventListener('input', function() {
    const pg = $('import-password-group');
    if (!pg) return;
    if (isEncryptedKey(this.value)) {
      pg.style.display = '';
      pg.classList.remove('hidden');
      $('import-password-hint').textContent = '— encrypted key detected, password required';
      $('import-password-hint').style.color = 'var(--amber)';
    } else {
      pg.style.display = 'none';
    }
  });

  const dz = $('drop-zone');
  dz.addEventListener('click',     () => $('identity-file-input').click());
  dz.addEventListener('dragover',  handleDragOver);
  dz.addEventListener('dragleave', handleDragLeave);
  dz.addEventListener('drop',      handleDrop);
  $('identity-file-input').addEventListener('change', e => {
    if (e.target.files[0]) readIdentityFile(e.target.files[0]);
  });

  $('auth-btn').addEventListener('click', () => {
    if (confirm('Sign out? You will need your private key to sign back in.')) location.reload();
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

  $('dm-modal-cancel').addEventListener('click', closeDMModal);
  $('dm-modal-confirm').addEventListener('click', confirmDMKeyExchange);

  // Returning user detection
  const myFp  = localStorage.getItem('cipher_my_fingerprint');
  const users = getStoredUsers();
  if (myFp && users[myFp]) {
    switchLockTab('login');
    $('login-username').value = users[myFp].handle;
    toast('Welcome back ' + users[myFp].handle + ' - paste your private key');
  }
});

// ═══════════════════════════════════════════════════════
// SCREENSHOT DETERRENTS
// ═══════════════════════════════════════════════════════

(function initScreenProtection() {

  // ── 1. Block right-click context menu ──
  document.addEventListener('contextmenu', e => {
    e.preventDefault();
    return false;
  });

  // ── 2. Block common keyboard shortcuts for saving/copying ──
  document.addEventListener('keydown', e => {
    const ctrl = e.ctrlKey || e.metaKey;

    // PrintScreen / Snapshot key — warn user (cannot block OS capture)
    if (e.key === 'PrintScreen' || e.key === 'Snapshot') {
      e.preventDefault();
      showScreenshotWarning();
      return false;
    }

    // Block Ctrl+S (save), Ctrl+U (view source), Ctrl+P (print)
    if (ctrl && (e.key === 's' || e.key === 'S' ||
                 e.key === 'u' || e.key === 'U' ||
                 e.key === 'p' || e.key === 'P')) {
      e.preventDefault();
      return false;
    }

    // Block F12 devtools, F5 hard reload with selection
    if (e.key === 'F12') {
      e.preventDefault();
      return false;
    }
  });

  // ── 3. Visibility change — blank screen when window loses focus ──
  const blank = document.getElementById('screen-blank');

  function hideContent() {
    if (blank) blank.classList.add('active');
  }
  function showContent() {
    if (blank) blank.classList.remove('active');
  }

  document.addEventListener('visibilitychange', () => {
    if (document.hidden) hideContent();
    else showContent();
  });

  // Also blank on window blur (switching apps, alt-tab)
  window.addEventListener('blur', hideContent);
  window.addEventListener('focus', showContent);

  // ── 4. PrintScreen warning overlay ──
  let warnTimer;
  function showScreenshotWarning() {
    const el = document.getElementById('screenshot-warn');
    if (!el) return;
    el.classList.add('show');
    clearTimeout(warnTimer);
    warnTimer = setTimeout(() => el.classList.remove('show'), 3000);
  }

  // Also try to detect screenshot via clipboard (Chrome only, requires permission)
  // When PrintScreen is pressed Chrome sometimes writes to clipboard
  document.addEventListener('copy', e => {
    // If the copy didn't come from a user text selection in an input,
    // it may be a screenshot copy — show warning
    const sel = window.getSelection && window.getSelection();
    if (!sel || sel.toString().length === 0) {
      showScreenshotWarning();
    }
  });

})();

// ═══════════════════════════════════════════════════════
// PGP / GPG / KLEOPATRA INTEGRATION  (requires openpgp.min.js)
// ═══════════════════════════════════════════════════════

// Holds the active OpenPGP key derived from the current CIPHER//NET identity
const pgpState = {
  privateKey: null,   // openpgp.PrivateKey
  publicKey:  null,   // openpgp.PublicKey
};

// ── Helpers ──────────────────────────────────────────

function pgpAvailable() {
  if (typeof openpgp === 'undefined') {
    toast('openpgp.min.js not loaded — see GET_OPENPGP.md');
    return false;
  }
  return true;
}

function pgpShowPanel(name) {
  ['export','import','encrypt','decrypt'].forEach(p => {
    const el = $('pgp-panel-' + p);
    if (el) el.classList.toggle('hidden', p !== name);
  });
}

function pgpShowModal(panel, title) {
  $('pgp-modal-title').textContent = '// PGP — ' + title;
  pgpShowPanel(panel);
  $('pgp-modal').classList.remove('hidden');
}

function pgpCloseModal() {
  $('pgp-modal').classList.add('hidden');
}

function pgpErr(id, msg) {
  const el = $(id);
  if (!el) return;
  el.textContent = msg;
  el.classList.remove('hidden');
}

function pgpClearErr(id) {
  const el = $(id);
  if (el) { el.textContent = ''; el.classList.add('hidden'); }
}

function pgpDownload(content, filename) {
  const url = URL.createObjectURL(new Blob([content], { type: 'application/pgp-keys' }));
  const a   = Object.assign(document.createElement('a'), { href: url, download: filename });
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ── A: Export PGP keypair derived from CIPHER//NET identity ──────────────

async function pgpExportKeypair() {
  if (!pgpAvailable() || !state.me) { toast('Sign in first'); return; }
  pgpClearErr('pgp-export-error');

  const btn = $('pgp-export-btn');
  btn.textContent = 'GENERATING...'; btn.disabled = true;

  try {
    const uid        = $('pgp-uid').value.trim() || state.me.handle + ' <' + state.me.handle + '@ciphernet>';
    const passphrase = $('pgp-export-pass').value || undefined;

    // Generate a fresh OpenPGP keypair (RSA-4096 for maximum Kleopatra compat)
    // We generate a new PGP key rather than converting the ECDSA key because
    // OpenPGP uses a different key format and Ed25519/ECDSA conversion is lossy.
    // The PGP key is a companion key — it shares your handle/UID identity.
    const { privateKey, publicKey } = await openpgp.generateKey({
      type: 'rsa',
      rsaBits: 4096,
      userIDs: [{ name: uid }],
      passphrase,
      format: 'armored',
    });

    $('pgp-pub-out').value = publicKey;
    $('pgp-sec-out').value = privateKey;
    $('pgp-export-output').classList.remove('hidden');
    toast('PGP keypair generated');

    // Cache for encrypt/decrypt operations this session
    const parsed = await openpgp.readPrivateKey({ armoredKey: privateKey });
    pgpState.publicKey  = await openpgp.readKey({ armoredKey: publicKey });
    pgpState.privateKey = passphrase
      ? await openpgp.decryptKey({ privateKey: parsed, passphrase })
      : parsed;

  } catch (e) {
    pgpErr('pgp-export-error', 'Export failed: ' + e.message);
  }
  btn.textContent = 'GENERATE PGP KEYPAIR'; btn.disabled = false;
}

// ── B / C: Import an existing GPG / Kleopatra private key ────────────────

async function pgpImportKey() {
  if (!pgpAvailable()) return;
  pgpClearErr('pgp-import-error');

  const armoredKey = $('pgp-import-key').value.trim();
  const passphrase = $('pgp-import-pass').value || undefined;
  if (!armoredKey) { pgpErr('pgp-import-error', 'Paste your armored private key.'); return; }

  const btn = $('pgp-import-btn');
  btn.textContent = 'IMPORTING...'; btn.disabled = true;

  try {
    const privateKey = await openpgp.readPrivateKey({ armoredKey });
    const decrypted  = passphrase
      ? await openpgp.decryptKey({ privateKey, passphrase })
      : privateKey;

    pgpState.privateKey = decrypted;
    pgpState.publicKey  = decrypted.toPublic();

    const uid = decrypted.getUserIDs()[0] || 'unknown';
    const fp  = decrypted.getFingerprint().toUpperCase();

    toast('GPG key imported: ' + uid);
    pgpErr('pgp-import-error', ''); // clear
    const el = $('pgp-import-error');
    if (el) {
      el.textContent = '✓ Imported: ' + uid + '\n  fp: ' + fp;
      el.style.color = 'var(--green3)';
      el.classList.remove('hidden');
    }
  } catch (e) {
    pgpErr('pgp-import-error', 'Import failed: ' + e.message);
  }
  btn.textContent = 'IMPORT GPG KEY'; btn.disabled = false;
}

// ── B: Encrypt a message with PGP (signed + encrypted) ───────────────────

async function pgpEncryptMessage() {
  if (!pgpAvailable()) return;
  pgpClearErr('pgp-encrypt-error');

  if (!pgpState.privateKey) {
    pgpErr('pgp-encrypt-error', 'No PGP key loaded. Export a keypair or import a GPG key first.');
    return;
  }

  const recipientArmored = $('pgp-enc-pubkey').value.trim();
  const plaintext        = $('pgp-enc-plain').value;
  if (!recipientArmored) { pgpErr('pgp-encrypt-error', 'Paste the recipient\'s PGP public key.'); return; }
  if (!plaintext)        { pgpErr('pgp-encrypt-error', 'Enter a message to encrypt.'); return; }

  const btn = $('pgp-enc-btn');
  btn.textContent = 'ENCRYPTING...'; btn.disabled = true;

  try {
    const recipientKey = await openpgp.readKey({ armoredKey: recipientArmored });
    const encrypted    = await openpgp.encrypt({
      message:            await openpgp.createMessage({ text: plaintext }),
      encryptionKeys:     recipientKey,
      signingKeys:        pgpState.privateKey,
      format:             'armored',
    });
    $('pgp-enc-out').value = encrypted;
    $('pgp-enc-out-group').classList.remove('hidden');
    toast('Message encrypted & signed');
  } catch (e) {
    pgpErr('pgp-encrypt-error', 'Encryption failed: ' + e.message);
  }
  btn.textContent = 'ENCRYPT & SIGN'; btn.disabled = false;
}

// ── B: Decrypt a PGP message ─────────────────────────────────────────────

async function pgpDecryptMessage() {
  if (!pgpAvailable()) return;
  pgpClearErr('pgp-decrypt-error');

  if (!pgpState.privateKey) {
    pgpErr('pgp-decrypt-error', 'No PGP key loaded. Export a keypair or import a GPG key first.');
    return;
  }

  const armoredMsg    = $('pgp-dec-cipher').value.trim();
  const senderArmored = $('pgp-dec-pubkey').value.trim();
  if (!armoredMsg) { pgpErr('pgp-decrypt-error', 'Paste the encrypted PGP message.'); return; }

  const btn = $('pgp-dec-btn');
  btn.textContent = 'DECRYPTING...'; btn.disabled = true;

  try {
    const message = await openpgp.readMessage({ armoredMessage: armoredMsg });

    const decryptOpts = {
      message,
      decryptionKeys: pgpState.privateKey,
      format: 'utf8',
    };

    if (senderArmored) {
      decryptOpts.verificationKeys = await openpgp.readKey({ armoredKey: senderArmored });
    }

    const { data, signatures } = await openpgp.decrypt(decryptOpts);
    $('pgp-dec-out').value = data;
    $('pgp-dec-out-group').classList.remove('hidden');

    // Signature status
    const sigEl = $('pgp-dec-sig-status');
    if (sigEl) {
      if (!senderArmored) {
        sigEl.textContent = '⚠ No sender key provided — signature not verified';
        sigEl.className   = 'pgp-sig-status warn';
      } else {
        try {
          await signatures[0].verified;
          sigEl.textContent = '✓ SIGNATURE VALID';
          sigEl.className   = 'pgp-sig-status ok';
        } catch {
          sigEl.textContent = '✗ SIGNATURE INVALID';
          sigEl.className   = 'pgp-sig-status fail';
        }
      }
    }
    toast('Message decrypted');
  } catch (e) {
    pgpErr('pgp-decrypt-error', 'Decryption failed: ' + e.message);
  }
  btn.textContent = 'DECRYPT'; btn.disabled = false;
}

// ── Wire up PGP UI ────────────────────────────────────────────────────────

function initPGP() {
  // Open modals
  $('btn-pgp-export').addEventListener('click', () => pgpShowModal('export', 'EXPORT KEYPAIR'));
  $('btn-pgp-import').addEventListener('click', () => pgpShowModal('import', 'IMPORT GPG KEY'));
  $('btn-pgp-encrypt').addEventListener('click', () => {
    if (!pgpState.privateKey) { toast('Load a PGP key first — export or import'); pgpShowModal('export', 'EXPORT KEYPAIR'); return; }
    pgpShowModal('encrypt', 'ENCRYPT MESSAGE');
  });
  $('btn-pgp-decrypt').addEventListener('click', () => {
    if (!pgpState.privateKey) { toast('Load a PGP key first — export or import'); pgpShowModal('import', 'IMPORT GPG KEY'); return; }
    pgpShowModal('decrypt', 'DECRYPT MESSAGE');
  });

  // Close buttons
  $('pgp-export-cancel').addEventListener('click', pgpCloseModal);
  $('pgp-import-cancel').addEventListener('click', pgpCloseModal);
  $('pgp-enc-cancel').addEventListener('click',    pgpCloseModal);
  $('pgp-dec-cancel').addEventListener('click',    pgpCloseModal);

  // Close on backdrop click
  $('pgp-modal').addEventListener('click', e => {
    if (e.target === $('pgp-modal')) pgpCloseModal();
  });

  // Actions
  $('pgp-export-btn').addEventListener('click', pgpExportKeypair);
  $('pgp-import-btn').addEventListener('click', pgpImportKey);
  $('pgp-enc-btn').addEventListener('click',    pgpEncryptMessage);
  $('pgp-dec-btn').addEventListener('click',    pgpDecryptMessage);

  // Copy / download buttons
  $('pgp-copy-pub').addEventListener('click', () => {
    navigator.clipboard.writeText($('pgp-pub-out').value).then(() => toast('Public key copied'));
  });
  $('pgp-copy-sec').addEventListener('click', () => {
    navigator.clipboard.writeText($('pgp-sec-out').value).then(() => toast('Secret key copied'));
  });
  $('pgp-copy-enc').addEventListener('click', () => {
    navigator.clipboard.writeText($('pgp-enc-out').value).then(() => toast('Encrypted message copied'));
  });
  $('pgp-dl-pub').addEventListener('click', () => pgpDownload($('pgp-pub-out').value, 'ciphernet-public.asc'));
  $('pgp-dl-sec').addEventListener('click', () => pgpDownload($('pgp-sec-out').value, 'ciphernet-secret.asc'));
}

// Call initPGP after DOMContentLoaded (appended to existing boot)
document.addEventListener('DOMContentLoaded', initPGP);
