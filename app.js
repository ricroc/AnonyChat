'use strict';

// ═══════════════════════════════════════════════════════
// STATE
// ═══════════════════════════════════════════════════════
const state = {
  me: null,            // { handle, publicKeyPem, signingKey, fingerprint, algo }
  channel: 'general',
  channelKeys: {},     // channel -> CryptoKey (AES-GCM, derived from passphrase)
  generatedPrivPem:    null,
  generatedPubPem:     null,
  generatedCryptoKeys: null,
  generatedAlgo:       null,
};

const CHANNEL_DESCS = {
  general: 'AES-GCM encrypted · ECDSA signed · passphrase required to read',
  random:  'AES-GCM encrypted · off-topic discussion',
  tech:    'AES-GCM encrypted · technical talk',
};

// ═══════════════════════════════════════════════════════
// CRYPTO — SIGNING (ECDSA / RSA-PSS)
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

async function exportPrivPem(key) { return toPem(await crypto.subtle.exportKey('pkcs8', key), 'PRIVATE KEY'); }
async function exportPubPem(key)  { return toPem(await crypto.subtle.exportKey('spki',  key), 'PUBLIC KEY'); }

function toPem(buffer, label) {
  const b64   = btoa(String.fromCharCode(...new Uint8Array(buffer)));
  const lines = b64.match(/.{1,64}/g).join('\n');
  return `-----BEGIN ${label}-----\n${lines}\n-----END ${label}-----`;
}

function fromPem(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
  return Uint8Array.from(atob(b64), c => c.charCodeAt(0)).buffer;
}

async function importPrivateKey(pem) {
  const der   = fromPem(pem);
  const algos = [
    { name: 'ECDSA', namedCurve: 'P-256' },
    { name: 'ECDSA', namedCurve: 'P-384' },
    { name: 'RSA-PSS', hash: 'SHA-256' },
  ];
  for (const alg of algos) {
    try {
      const key = await crypto.subtle.importKey('pkcs8', der, alg, true, ['sign']);
      const pub = await derivePublicFromPrivate(key, alg);
      return { privateKey: key, publicKey: pub, algorithm: alg };
    } catch { /* try next */ }
  }
  throw new Error('Unrecognised key format');
}

async function derivePublicFromPrivate(privateKey, alg) {
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  delete jwk.d;
  const pubAlg = alg.name === 'ECDSA'
    ? { name: 'ECDSA', namedCurve: alg.namedCurve }
    : { name: 'RSA-PSS', hash: 'SHA-256' };
  return crypto.subtle.importKey('jwk', jwk, pubAlg, true, ['verify']);
}

async function fingerprint(pubKeyPem) {
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(pubKeyPem));
  return Array.from(new Uint8Array(hash)).slice(0, 8).map(b => b.toString(16).padStart(2,'0')).join('');
}

async function signMessage(text, privateKey, alg) {
  const enc    = new TextEncoder().encode(text);
  const sigAlg = alg.name === 'ECDSA' ? { name: 'ECDSA', hash: 'SHA-256' } : { name: 'RSA-PSS', saltLength: 32 };
  const sig    = await crypto.subtle.sign(sigAlg, privateKey, enc);
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}

async function verifyMessage(text, sigB64, pubKeyPem, alg) {
  try {
    const enc    = new TextEncoder().encode(text);
    const sig    = Uint8Array.from(atob(sigB64), c => c.charCodeAt(0));
    const pubAlg = alg.name === 'ECDSA' ? { name: 'ECDSA', namedCurve: alg.namedCurve } : { name: 'RSA-PSS', hash: 'SHA-256' };
    const key    = await crypto.subtle.importKey('spki', fromPem(pubKeyPem), pubAlg, false, ['verify']);
    const verAlg = alg.name === 'ECDSA' ? { name: 'ECDSA', hash: 'SHA-256' } : { name: 'RSA-PSS', saltLength: 32 };
    return crypto.subtle.verify(verAlg, key, sig, enc);
  } catch { return false; }
}

// ═══════════════════════════════════════════════════════
// CRYPTO — ENCRYPTION (AES-256-GCM via PBKDF2)
// ═══════════════════════════════════════════════════════

// Derive an AES-GCM key from a passphrase.
// Salt is deterministic per channel so all users with the same passphrase
// derive the same key without needing a key exchange step.
async function deriveChannelKey(passphrase, channel) {
  const enc     = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw', enc.encode(passphrase), 'PBKDF2', false, ['deriveKey']
  );
  // Public, deterministic per-channel salt
  const saltBuf = await crypto.subtle.digest('SHA-256', enc.encode('cipher-channel:' + channel));
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: saltBuf, iterations: 200000, hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Encrypt plaintext -> base64(iv || ciphertext)
async function encryptText(plaintext, aesKey) {
  const iv         = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, aesKey, new TextEncoder().encode(plaintext)
  );
  const combined = new Uint8Array(12 + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), 12);
  return btoa(String.fromCharCode(...combined));
}

// Decrypt base64(iv || ciphertext) -> plaintext string
async function decryptText(b64, aesKey) {
  const combined   = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const plain      = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: combined.slice(0, 12) }, aesKey, combined.slice(12)
  );
  return new TextDecoder().decode(plain);
}

// ═══════════════════════════════════════════════════════
// PASSPHRASE / CHANNEL KEY MANAGEMENT
// ═══════════════════════════════════════════════════════

async function setChannelPassphrase() {
  const pass = $('channel-passphrase').value;
  if (!pass) { toast('Enter a passphrase first'); return; }

  const btn = $('btn-set-passphrase');
  btn.textContent = '...';
  btn.disabled    = true;

  try {
    const key = await deriveChannelKey(pass, state.channel);
    state.channelKeys[state.channel] = key;
    $('channel-passphrase').value = '';
    updateEncStatus(true);
    updateMsgInput();
    $('messages').innerHTML = '';
    await loadChannelHistory(state.channel);
    sysMsg('Channel key set. Messages encrypted with AES-256-GCM.');
    toast('Channel key active');
  } catch (e) {
    toast('Key derivation failed: ' + e.message);
  }

  btn.textContent = 'SET KEY';
  btn.disabled    = false;
}

function updateEncStatus(active) {
  const el = $('enc-status');
  if (active) {
    el.textContent = 'AES-256 ACTIVE';
    el.classList.add('active');
  } else {
    el.textContent = 'NO KEY SET';
    el.classList.remove('active');
  }
}

// ═══════════════════════════════════════════════════════
// KEY GENERATION (lock screen)
// ═══════════════════════════════════════════════════════

async function generateKeys() {
  const username = $('reg-username').value.trim();
  if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) {
    toast('Handle must be 3-32 chars: letters, numbers, underscores');
    return;
  }

  const algo = $('reg-algo').value;
  const btn  = $('btn-gen');
  btn.disabled  = true;
  btn.innerHTML = '<span class="spinner"></span>GENERATING...';

  $('key-gen-area').classList.remove('hidden');
  animateProgress(0, 40, 600);

  let keys;
  try {
    if      (algo === 'ECDSA-P256') keys = await generateECDSA('P-256');
    else if (algo === 'ECDSA-P384') keys = await generateECDSA('P-384');
    else                            keys = await generateRSAPSS();
  } catch (e) {
    toast('Key generation failed: ' + e.message);
    btn.disabled  = false;
    btn.innerHTML = 'GENERATE KEYPAIR';
    return;
  }

  animateProgress(40, 80, 400);
  const privPem = await exportPrivPem(keys.privateKey);
  const pubPem  = await exportPubPem(keys.publicKey);
  animateProgress(80, 100, 300);

  state.generatedPrivPem    = privPem;
  state.generatedPubPem     = pubPem;
  state.generatedCryptoKeys = keys;
  state.generatedAlgo = algo.startsWith('ECDSA')
    ? { name: 'ECDSA', namedCurve: algo === 'ECDSA-P256' ? 'P-256' : 'P-384' }
    : { name: 'RSA-PSS', hash: 'SHA-256' };

  $('priv-key-display').textContent = privPem;
  $('pub-key-display').textContent  = pubPem;

  btn.classList.add('hidden');
  const activateBtn = $('btn-activate');
  activateBtn.classList.remove('hidden');
  activateBtn.disabled = true;

  $('confirm-saved').addEventListener('change', function handler() {
    activateBtn.disabled = !this.checked;
    if (this.checked) this.removeEventListener('change', handler);
  });
}

function animateProgress(from, to, ms) {
  const fill  = $('gen-progress');
  const start = Date.now();
  const tick  = () => {
    const t = Math.min(1, (Date.now() - start) / ms);
    fill.style.width = (from + (to - from) * t) + '%';
    if (t < 1) requestAnimationFrame(tick);
  };
  requestAnimationFrame(tick);
}

async function activateAccount() {
  const username = $('reg-username').value.trim();
  const fp       = await fingerprint(state.generatedPubPem);

  const users = getStoredUsers();
  users[fp]   = {
    handle: username, publicKeyPem: state.generatedPubPem,
    fingerprint: fp, algo: state.generatedAlgo, registeredAt: Date.now(),
  };
  localStorage.setItem('cipher_users', JSON.stringify(users));
  localStorage.setItem('cipher_my_fingerprint', fp);

  state.me = {
    handle: username, publicKeyPem: state.generatedPubPem,
    signingKey: state.generatedCryptoKeys.privateKey,
    fingerprint: fp, algo: state.generatedAlgo,
  };

  state.generatedPrivPem    = null;
  state.generatedCryptoKeys = null;

  enterApp();
  sysMsg(username + ' joined the network.');
  toast('Authenticated as ' + username);
}

// ═══════════════════════════════════════════════════════
// IMPORT KEY (lock screen)
// ═══════════════════════════════════════════════════════

async function importKey() {
  const privPem          = $('login-privkey').value.trim();
  const usernameOverride = $('login-username').value.trim();
  hideLoginError();

  if (!privPem) { showLoginError('Paste your private key.'); return; }

  const btn = $('btn-import');
  btn.textContent = 'VERIFYING...';
  btn.disabled    = true;

  let keyData;
  try {
    keyData = await importPrivateKey(privPem);
  } catch (e) {
    showLoginError('Could not parse key: ' + e.message);
    btn.textContent = 'IMPORT AND ENTER';
    btn.disabled    = false;
    return;
  }

  const pubPem = await exportPubPem(keyData.publicKey);
  const fp     = await fingerprint(pubPem);
  const users  = getStoredUsers();
  const handle = usernameOverride || (users[fp] && users[fp].handle) || 'user_' + fp.slice(0, 6);

  users[fp] = { handle, publicKeyPem: pubPem, fingerprint: fp, algo: keyData.algorithm };
  localStorage.setItem('cipher_users', JSON.stringify(users));
  localStorage.setItem('cipher_my_fingerprint', fp);

  state.me = { handle, publicKeyPem: pubPem, signingKey: keyData.privateKey, fingerprint: fp, algo: keyData.algorithm };

  btn.textContent = 'IMPORT AND ENTER';
  btn.disabled    = false;

  enterApp();
  sysMsg(handle + ' connected.');
  toast('Signed in as ' + handle);
}

function showLoginError(msg) {
  const el = $('login-error');
  el.textContent = '// ERROR: ' + msg;
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
// MESSAGING
// ═══════════════════════════════════════════════════════

async function sendMessage() {
  if (!state.me) return;
  const aesKey = state.channelKeys[state.channel];
  if (!aesKey) { toast('Set a channel passphrase first'); return; }

  const input = $('msg-input');
  const text  = input.value.trim();
  if (!text) return;
  input.value = '';

  const ts = Date.now();

  // Sign the plaintext so recipients can verify authorship after decryption
  const sigPayload = JSON.stringify({ text, channel: state.channel, author: state.me.fingerprint, ts });
  const sig        = await signMessage(sigPayload, state.me.signingKey, state.me.algo);

  // Build plaintext envelope with all metadata, then encrypt it entirely
  const plainEnvelope = JSON.stringify({
    text, sig, sigPayload,
    author: state.me.fingerprint,
    handle: state.me.handle,
    publicKeyPem: state.me.publicKeyPem,
    algo: state.me.algo,
    ts,
  });
  const ciphertext = await encryptText(plainEnvelope, aesKey);

  // Only the author hint (first 6 chars of fingerprint) is stored in plaintext
  // so the UI can show a placeholder for locked messages without revealing content
  persistMessage({ ciphertext, channel: state.channel, ts, authorHint: state.me.fingerprint.slice(0, 6) });

  renderMessage({
    text, author: state.me.handle, fingerprint: state.me.fingerprint,
    ts, verified: true, encrypted: true, decrypted: true,
  });
  scrollToBottom();
}

function persistMessage(stored) {
  try {
    const key = 'cipher_msgs_' + stored.channel;
    const arr = JSON.parse(localStorage.getItem(key) || '[]');
    arr.push(stored);
    if (arr.length > 200) arr.splice(0, arr.length - 200);
    localStorage.setItem(key, JSON.stringify(arr));
  } catch { /* storage full */ }
}

async function loadChannelHistory(channel) {
  const aesKey = state.channelKeys[channel];
  const stored = JSON.parse(localStorage.getItem('cipher_msgs_' + channel) || '[]');

  for (const entry of stored) {
    if (!aesKey) {
      renderLockedMessage(entry.ts, entry.authorHint, false);
      continue;
    }
    try {
      const plain    = await decryptText(entry.ciphertext, aesKey);
      const env      = JSON.parse(plain);
      const verified = await verifyMessage(env.sigPayload, env.sig, env.publicKeyPem, env.algo);
      renderMessage({
        text: env.text, author: env.handle, fingerprint: env.fingerprint,
        ts: env.ts, verified, encrypted: true, decrypted: true,
      });
    } catch {
      renderLockedMessage(entry.ts, entry.authorHint, true);
    }
  }
  scrollToBottom();
}

function renderMessage(msg) {
  const isMe = state.me && msg.fingerprint === state.me.fingerprint;
  const time = new Date(msg.ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

  const div  = document.createElement('div');
  div.className = 'msg';

  const meta = document.createElement('div');
  meta.className = 'msg-meta';

  const author = document.createElement('span');
  author.className   = 'msg-author' + (isMe ? ' me' : '') + (msg.system ? ' system' : '');
  author.title       = msg.fingerprint ? 'Fingerprint: ' + msg.fingerprint : '';
  author.textContent = msg.author;
  meta.appendChild(author);

  const timeEl = document.createElement('span');
  timeEl.className   = 'msg-time';
  timeEl.textContent = time;
  meta.appendChild(timeEl);

  if (!msg.system && msg.verified !== undefined) {
    const sigEl = document.createElement('span');
    sigEl.className = 'msg-sig';
    const icon = document.createElement('span');
    icon.className   = 'verified-icon';
    icon.textContent = msg.verified ? '✓' : '✗';
    sigEl.appendChild(icon);
    sigEl.appendChild(document.createTextNode(msg.verified ? 'SIGNED' : 'INVALID'));
    meta.appendChild(sigEl);
  }

  if (msg.encrypted) {
    const encEl = document.createElement('div');
    encEl.className   = 'msg-enc';
    encEl.textContent = 'AES-256-GCM';
    meta.appendChild(encEl);
  }

  const body = document.createElement('div');
  body.className   = 'msg-body' + (msg.system ? ' system' : '');
  body.textContent = msg.text;

  div.appendChild(meta);
  div.appendChild(body);
  $('messages').appendChild(div);
}

function renderLockedMessage(ts, authorHint, wrongKey) {
  const time = new Date(ts).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
  const div  = document.createElement('div');
  div.className = 'msg';

  const meta = document.createElement('div');
  meta.className = 'msg-meta';

  const author = document.createElement('span');
  author.className   = 'msg-author system';
  author.textContent = authorHint ? '...' + authorHint : '??????';
  meta.appendChild(author);

  const timeEl = document.createElement('span');
  timeEl.className = 'msg-time';
  timeEl.textContent = time;
  meta.appendChild(timeEl);

  const encEl = document.createElement('div');
  encEl.className   = 'msg-enc' + (wrongKey ? ' failed' : '');
  encEl.textContent = wrongKey ? 'WRONG KEY' : 'LOCKED';
  meta.appendChild(encEl);

  const body = document.createElement('div');
  body.className   = 'msg-body system';
  body.textContent = wrongKey
    ? '[decryption failed - wrong passphrase]'
    : '[encrypted - set channel passphrase to read]';

  div.appendChild(meta);
  div.appendChild(body);
  $('messages').appendChild(div);
}

function sysMsg(text) {
  renderMessage({ text, author: 'SYSTEM', fingerprint: '', ts: Date.now(), system: true });
  scrollToBottom();
}

function scrollToBottom() {
  const m = $('messages');
  m.scrollTop = m.scrollHeight;
}

// ═══════════════════════════════════════════════════════
// IDENTITY EXPORT / IMPORT
// ═══════════════════════════════════════════════════════

function exportIdentity() {
  if (!state.me) { toast('Sign in first'); return; }
  downloadJSON({
    cipher_version: 1, type: 'public_identity',
    handle: state.me.handle, fingerprint: state.me.fingerprint,
    publicKeyPem: state.me.publicKeyPem, algo: state.me.algo,
    exportedAt: new Date().toISOString(),
    note: 'Public key only. Safe to share. Keep your private key secret.',
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
  downloadJSON({
    cipher_version: 1, type: 'full_backup',
    myFingerprint: state.me.fingerprint,
    exportedAt: new Date().toISOString(), users, channels,
    note: 'Encrypted ciphertext + public keys only. Private key NOT included.',
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
  e.preventDefault();
  $('drop-zone').classList.remove('drag-over');
  if (e.dataTransfer.files[0]) readIdentityFile(e.dataTransfer.files[0]);
}

function readIdentityFile(file) {
  const reader = new FileReader();
  reader.onload = e => {
    try   { applyIdentityFile(JSON.parse(e.target.result)); }
    catch { showLoginError('Could not parse file - expected JSON.'); }
  };
  reader.readAsText(file);
}

function applyIdentityFile(data) {
  if (!data.cipher_version) { showLoginError('Not a CIPHER//NET identity file.'); return; }
  if (data.type === 'full_backup') {
    if (data.users)
      localStorage.setItem('cipher_users', JSON.stringify({ ...getStoredUsers(), ...data.users }));
    if (data.channels) {
      for (const [ch, msgs] of Object.entries(data.channels))
        if (Array.isArray(msgs) && msgs.length)
          localStorage.setItem('cipher_msgs_' + ch, JSON.stringify(msgs));
    }
    toast('Backup restored - paste your private key to sign in');
    if (data.myFingerprint && data.users && data.users[data.myFingerprint])
      $('login-username').value = data.users[data.myFingerprint].handle;
    showIdentityPreview({ type: 'full_backup', userCount: Object.keys(data.users || {}).length });
    return;
  }
  if (data.handle) $('login-username').value = data.handle;
  if (data.fingerprint && data.publicKeyPem) {
    const users = getStoredUsers();
    users[data.fingerprint] = {
      handle: data.handle, publicKeyPem: data.publicKeyPem,
      fingerprint: data.fingerprint, algo: data.algo,
    };
    localStorage.setItem('cipher_users', JSON.stringify(users));
  }
  showIdentityPreview(data);
  toast('Identity file loaded - paste your private key to sign in');
}

function showIdentityPreview(data) {
  const el = $('identity-preview');
  el.classList.remove('hidden');
  el.innerHTML = '';
  const label = document.createElement('div');
  label.className   = 'ip-label';
  label.textContent = data.type === 'full_backup' ? '// FULL BACKUP LOADED' : '// IDENTITY FILE LOADED';
  el.appendChild(label);
  const lines = data.type === 'full_backup'
    ? [data.userCount + ' user(s) restored. Paste your private key below.']
    : ['Handle: ' + (data.handle || '?'), 'Fingerprint: ' + (data.fingerprint || '?'), 'Paste your private key below.'];
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
// CHANNEL & USER MANAGEMENT
// ═══════════════════════════════════════════════════════

function switchChannel(ch) {
  state.channel = ch;
  document.querySelectorAll('.channel-item').forEach(el =>
    el.classList.toggle('active', el.dataset.channel === ch)
  );
  $('channel-title').textContent = '# ' + ch;
  $('channel-desc').textContent  = CHANNEL_DESCS[ch] || '';
  $('messages').innerHTML = '';
  updateEncStatus(!!state.channelKeys[ch]);
  updateMsgInput();
  loadChannelHistory(ch);
}

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
  const hasKey = !!state.channelKeys[state.channel];
  $('msg-input').disabled    = !hasKey;
  $('btn-send').disabled     = !hasKey;
  $('msg-input').placeholder = hasKey
    ? 'Message #' + state.channel + ' (AES-256-GCM encrypted + ECDSA signed)'
    : 'Set a channel passphrase to send messages...';
  $('input-hint').textContent = hasKey
    ? '> ' + state.me.handle.toUpperCase() + ' · AES-256-GCM ENCRYPTED · ECDSA SIGNED · fp:' + state.me.fingerprint
    : '> SET A CHANNEL PASSPHRASE — all messages are encrypted at rest, only users with the passphrase can read them';
}

function updateUserBadge() {
  if (!state.me) return;
  const badge = $('user-badge');
  badge.classList.remove('hidden');
  badge.classList.add('visible');
  badge.innerHTML = '';
  const dot = document.createElement('span');
  dot.className = 'dot active';
  const fp = document.createElement('span');
  fp.className = 'badge-fp'; fp.textContent = state.me.fingerprint;
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
    const empty = document.createElement('div');
    empty.className = 'user-empty'; empty.textContent = 'No users';
    list.appendChild(empty); return;
  }
  entries.forEach(u => {
    const isMe = state.me && u.fingerprint === state.me.fingerprint;
    const div  = document.createElement('div');
    div.className = 'user-item' + (isMe ? ' me' : '');
    div.title     = 'Fingerprint: ' + u.fingerprint;
    const dot = document.createElement('span');
    dot.className = 'user-dot' + (isMe ? ' online' : '');
    const fp = document.createElement('span');
    fp.className = 'user-fp'; fp.textContent = u.fingerprint.slice(0, 6);
    div.appendChild(dot);
    div.appendChild(document.createTextNode(u.handle));
    div.appendChild(fp);
    list.appendChild(div);
  });
  document.querySelectorAll('.online-count').forEach(el => el.textContent = entries.length);
}

function getStoredUsers() {
  try { return JSON.parse(localStorage.getItem('cipher_users') || '{}'); }
  catch { return {}; }
}

// ═══════════════════════════════════════════════════════
// COPY / TOAST / HELPERS
// ═══════════════════════════════════════════════════════

function copyKey(which) {
  const text = which === 'priv' ? state.generatedPrivPem : state.generatedPubPem;
  if (!text) return;
  navigator.clipboard.writeText(text)
    .then(()  => toast('Copied to clipboard'))
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

function $(id) { return document.getElementById(id); }

// ═══════════════════════════════════════════════════════
// BOOT
// ═══════════════════════════════════════════════════════

document.addEventListener('DOMContentLoaded', () => {

  if (!window.crypto || !window.crypto.subtle) {
    document.body.innerHTML = '<div class="no-crypto">Web Crypto API not available.' +
      ' CIPHER//NET requires HTTPS, a .onion address, or localhost.</div>';
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

  // ── Check for returning user ──
  // If we recognise a previous fingerprint, pre-fill the import tab
  const myFp      = localStorage.getItem('cipher_my_fingerprint');
  const allUsers  = getStoredUsers();
  if (myFp && allUsers[myFp]) {
    switchLockTab('login');
    $('login-username').value = allUsers[myFp].handle;
    toast('Welcome back ' + allUsers[myFp].handle + ' - paste your private key to continue');
  }
});
