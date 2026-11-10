/* SecureShare Pro — client-side crypto, server-side lifecycle.
 * The browser does the encryption; the database enforces expiry, one-time reads,
 * and rate limits. The server only ever holds ciphertext. */
'use strict';

const API_URL = window.__SS_API_URL__ || 'https://drapuwslrdtinaobqrlp.supabase.co';
// Publishable key: safe to ship in client code. Every table is RLS-locked and
// every operation goes through a SECURITY DEFINER function. The service_role key
// is never used here and must never be committed.
const API_KEY = 'sb_publishable_It-jr_tDiFe6Ah64fokrrA_9NZtVre4';

const PBKDF2_ITERATIONS = 600000;
const QR_SAFE_LIMIT = 2000;

const te = new TextEncoder();
const td = new TextDecoder();
const subtle = window.crypto && window.crypto.subtle;

const state = {
  clipId: null,
  payload: null,      // decrypted payload once available
  cipher: null,       // {ciphertext, iv, salt, mode} kept in memory so a wrong password does not re-fetch
  rawText: '',
  busy: false
};

/* ---------- small helpers ---------- */

function toB64u(bytes) {
  const b = new Uint8Array(bytes);
  let s = '';
  for (let i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function fromB64u(str) {
  let s = String(str).replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function el(id) { return document.getElementById(id); }

function toast(msg, kind) {
  const host = el('toast');
  if (!host) return;
  const node = document.createElement('div');
  node.className = 'toast-item' + (kind ? ' toast-' + kind : '');
  node.textContent = msg;
  host.appendChild(node);
  setTimeout(() => node.classList.add('toast-out'), 2600);
  setTimeout(() => node.remove(), 3200);
}

/* ---------- api ---------- */

class ApiError extends Error {
  constructor(code) { super(code); this.code = code; }
}

const FRIENDLY = {
  rate_limited: 'Too many attempts from this connection in the last hour. Try again later.',
  at_capacity: 'The service is at capacity right now. Try again in a little while.',
  weak_pin: 'That PIN is too easy to guess. Try again.',
  invalid_pin: 'That PIN did not match anything. It may be wrong, expired, or already used.',
  pin_taken: 'That PIN is already in use. Try again.',
  pin_wrap_not_allowed: 'Could not set up the PIN. Please try again.',
  invalid_pin_wrapped: 'Could not set up the PIN. Please try again.',
  invalid_pin_salt: 'Could not set up the PIN. Please try again.',
  clip_not_found: 'This clip is gone. It has been opened the allowed number of times, expired, or was deleted by its sender.',
  clip_gone: 'This clip has expired.',
  invalid_expiry: 'That expiry time is not allowed.',
  invalid_max_views: 'That view limit is not allowed.',
  missing_salt: 'This link is incomplete.',
  invalid_payload: 'This link is incomplete.',
  invalid_iv: 'This link is incomplete.',
  network: 'Could not reach the server. Check your connection and try again.',
  offline: 'You appear to be offline.'
};

function friendly(code) {
  return FRIENDLY[code] || 'Something went wrong (' + code + '). Please try again.';
}

async function rpc(name, params) {
  let res;
  try {
    res = await fetch(API_URL + '/rest/v1/rpc/' + name, {
      method: 'POST',
      headers: {
        'apikey': API_KEY,
        'Authorization': 'Bearer ' + API_KEY,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(params || {})
    });
  } catch (e) {
    throw new ApiError('network');
  }
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch (e) { /* non-json error body */ }
  if (!res.ok) {
    const code = (data && (data.message || data.hint || data.code)) || ('http_' + res.status);
    throw new ApiError(String(code).trim());
  }
  return data;
}

/* ---------- crypto ---------- */

async function deriveKey(password, salt) {
  const base = await subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveKey']);
  return subtle.deriveKey(
    { name: 'PBKDF2', salt: salt, iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

/* ---------- pin ---------- */

// Uniform 5-digit code. Rejection sampling avoids the modulo bias that would
// make some PINs slightly likelier than others.
function randomPin() {
  const buf = new Uint32Array(1);
  const limit = 131072 - (131072 % 100000);
  for (;;) {
    crypto.getRandomValues(buf);
    const v = buf[0] % 131072;
    if (v < limit) return String(v % 100000).padStart(5, '0');
  }
}

// Wrap the content key under a key derived from the PIN. The server stores the
// blob but never sees the key, and cannot unwrap it without the PIN.
async function wrapKeyForPin(rawKey, pin) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(pin, salt);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, rawKey);
  const packed = new Uint8Array(iv.length + ct.byteLength);
  packed.set(iv, 0);
  packed.set(new Uint8Array(ct), iv.length);
  return { wrapped: toB64u(packed), salt: toB64u(salt) };
}

async function unwrapKeyFromPin(wrapped, salt, pin) {
  const packed = fromB64u(wrapped);
  const iv = packed.slice(0, 12);
  const ct = packed.slice(12);
  const key = await deriveKey(pin, fromB64u(salt));
  const raw = await subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct);
  return new Uint8Array(raw);
}

async function encryptPayload(payload, password) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = te.encode(JSON.stringify(payload));

  if (password) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await deriveKey(password, salt);
    const ct = await subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, plaintext);
    return { ciphertext: toB64u(ct), iv: toB64u(iv), salt: toB64u(salt), mode: 'p' };
  }

  const rawKey = crypto.getRandomValues(new Uint8Array(32));
  const key = await subtle.importKey('raw', rawKey, 'AES-GCM', false, ['encrypt']);
  const ct = await subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, plaintext);
  return { ciphertext: toB64u(ct), iv: toB64u(iv), salt: null, mode: 'k', rawKey: rawKey };
}

async function decryptPayload(cipher, secret, mode) {
  const iv = fromB64u(cipher.iv);
  const ct = fromB64u(cipher.ciphertext);
  let key;
  if (mode === 'password') {
    key = await deriveKey(secret, fromB64u(cipher.salt));
  } else {
    key = await subtle.importKey('raw', secret, 'AES-GCM', false, ['decrypt']);
  }
  const buf = await subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, ct);
  return JSON.parse(td.decode(buf));
}

/* ---------- markdown sanitiser ---------- */

const ALLOWED_TAGS = new Set([
  'P', 'BR', 'HR', 'STRONG', 'B', 'EM', 'I', 'DEL', 'S', 'CODE', 'PRE',
  'BLOCKQUOTE', 'UL', 'OL', 'LI', 'H1', 'H2', 'H3', 'H4', 'H5', 'H6',
  'A', 'TABLE', 'THEAD', 'TBODY', 'TR', 'TH', 'TD', 'SPAN', 'DIV'
]);
const DROP_TAGS = 'script,style,iframe,object,embed,link,meta,img,svg,math,form,input,button,textarea,select,base,video,audio,source,track,canvas';

function sanitizeHtml(html) {
  const doc = new DOMParser().parseFromString(String(html), 'text/html');
  const body = doc.body;

  body.querySelectorAll(DROP_TAGS).forEach(function (n) { n.remove(); });

  let guard = 0;
  for (;;) {
    const bad = Array.prototype.filter.call(body.querySelectorAll('*'), function (node) {
      return !ALLOWED_TAGS.has(node.tagName);
    });
    if (!bad.length || guard++ > 60) break;
    bad.forEach(function (node) {
      const parent = node.parentNode;
      if (!parent) return;
      while (node.firstChild) parent.insertBefore(node.firstChild, node);
      node.remove();
    });
  }

  body.querySelectorAll('*').forEach(function (node) {
    Array.prototype.slice.call(node.attributes).forEach(function (attr) {
      const name = attr.name.toLowerCase();
      const value = String(attr.value || '').trim();
      let keep = false;

      if (node.tagName === 'A' && name === 'href') {
        keep = /^https?:\/\//i.test(value) || /^mailto:/i.test(value) || /^#/.test(value);
      } else if (node.tagName === 'CODE' && name === 'class') {
        keep = /^language-[A-Za-z0-9_+-]+$/.test(value);
      } else if ((node.tagName === 'TH' || node.tagName === 'TD') && name === 'align') {
        keep = /^(left|right|center)$/i.test(value);
      }

      if (!keep) node.removeAttribute(attr.name);
    });

    if (node.tagName === 'A' && node.hasAttribute('href')) {
      node.setAttribute('rel', 'noopener noreferrer nofollow');
      node.setAttribute('target', '_blank');
    }
  });

  return body.innerHTML;
}

/* ---------- views ---------- */

const VIEWS = ['create-view', 'open-view', 'unlock-view', 'read-view', 'error-view'];

function showView(id) {
  VIEWS.forEach(function (v) {
    const node = el(v);
    if (node) node.classList.toggle('hidden', v !== id);
  });
  const focusTarget = el(id) && el(id).querySelector('h2, button, input');
  if (focusTarget && focusTarget.focus) {
    try { focusTarget.focus({ preventScroll: true }); } catch (e) {}
  }
}

function showError(code) {
  const msg = el('error-message');
  if (msg) msg.textContent = friendly(code);
  showView('error-view');
}

/* ---------- theme ---------- */

function applyTheme(mode) {
  const root = document.documentElement;
  if (mode === 'dark') root.setAttribute('data-theme', 'dark');
  else root.removeAttribute('data-theme');
}

function toggleTheme() {
  const next = document.documentElement.hasAttribute('data-theme') ? 'light' : 'dark';
  applyTheme(next);
  try { localStorage.setItem('theme', next); } catch (e) {}
}

/* ---------- create ---------- */

function updateLengthHint() {
  const ta = el('clip-text');
  const hint = el('length-hint');
  if (!ta || !hint) return;
  const n = ta.value.length;
  if (!n) { hint.textContent = ''; hint.className = 'length-hint'; return; }
  hint.textContent = n.toLocaleString() + ' characters \u00b7 links stay short now, the text lives on the server as ciphertext';
  hint.className = 'length-hint';
}

function setCreating(on) {
  state.busy = on;
  const btn = el('generate-btn');
  if (!btn) return;
  btn.disabled = on;
  btn.textContent = on ? 'Encrypting and uploading\u2026' : 'Create secure link';
}

async function generateLink() {
  if (state.busy) return;
  const text = el('clip-text').value;
  const password = el('password-input').value;
  const expiryMinutes = parseInt(el('expiry-select').value, 10);
  const views = parseInt(el('views-select').value, 10);

  if (!text.trim()) { toast('Type something to share first', 'bad'); return; }
  if (!subtle) { showError('webcrypto_missing'); return; }

  setCreating(true);
  try {
    const cipher = await encryptPayload({ v: 2, t: text }, password);
    const expiresAt = expiryMinutes > 0 ? new Date(Date.now() + expiryMinutes * 60000).toISOString() : null;

    // Every clip gets a PIN. With no password the PIN is also the credential, so
    // the content key is wrapped under it. With a password the PIN only locates
    // the clip: no wrapped key is stored, so a guessed PIN yields ciphertext.
    let created = null;
    let pin = null;
    for (let attempt = 0; attempt < 3 && !created; attempt++) {
      pin = randomPin();
      let wrapped = null;
      if (cipher.rawKey) {
        const w = await wrapKeyForPin(cipher.rawKey, pin);
        wrapped = w;
      }
      try {
        created = await rpc('create_clip', {
          p_ciphertext: cipher.ciphertext,
          p_iv: cipher.iv,
          p_salt: cipher.salt,
          p_mode: cipher.mode,
          p_expires_at: expiresAt,
          p_max_views: views > 0 ? views : null,
          p_pin: pin,
          p_pin_wrapped: wrapped ? wrapped.wrapped : null,
          p_pin_salt: wrapped ? wrapped.salt : null
        });
      } catch (err) {
        if (err instanceof ApiError && err.code === 'pin_taken' && attempt < 2) continue;
        throw err;
      }
    }

    const base = window.location.href.split('?')[0].split('#')[0];
    const clipUrl = base + '?c=' + created.id + (cipher.rawKey ? '#k=' + toB64u(cipher.rawKey) : '');

    el('share-link').innerText = clipUrl;

    el('pin-value').textContent = pin;
    const pinNote = el('pin-note');
    if (pinNote) {
      pinNote.textContent = cipher.rawKey
        ? 'Read this out over a call, or send it by another channel. Anyone with the PIN can open this clip without the link, and it dies when the clip does.'
        : 'This PIN finds the clip. Your password is still required to read it, so the PIN alone reveals nothing.';
    }
    el('pin-block').classList.remove('hidden');
    el('result-area').classList.remove('hidden');
    el('result-meta').textContent = describePolicy(views, expiryMinutes);
    renderQr(clipUrl);
    saveToHistory(created.id, clipUrl, text.length);
    toast('Link created');
  } catch (err) {
    toast(err instanceof ApiError ? friendly(err.code) : 'Could not create the link.', 'bad');
  } finally {
    setCreating(false);
  }
}

function describePolicy(views, expiryMinutes) {
  const viewText = views === 1 ? 'deleted after the first open' : (views > 0 ? 'deleted after ' + views + ' opens' : 'no view limit');
  const expiryText = expiryMinutes > 0 ? 'expires in ' + (expiryMinutes < 60 ? expiryMinutes + ' min' : expiryMinutes < 1440 ? Math.round(expiryMinutes / 60) + ' h' : Math.round(expiryMinutes / 1440) + ' d') : 'never expires';
  return viewText + ' \u00b7 ' + expiryText + ' \u00b7 enforced by the server';
}

function renderQr(url) {
  const host = el('qrcode');
  const err = el('qr-error');
  host.innerHTML = '';
  err.classList.add('hidden');
  if (typeof QRCode === 'undefined') {
    err.textContent = 'The QR library could not be loaded. Use Copy Link instead.';
    err.classList.remove('hidden');
    return;
  }
  if (url.length > QR_SAFE_LIMIT) {
    err.textContent = 'This link is too long for a QR code. Use Copy Link instead.';
    err.classList.remove('hidden');
    return;
  }
  try {
    new QRCode(host, { text: url, width: 148, height: 148, correctLevel: QRCode.CorrectLevel.L });
  } catch (e) {
    err.textContent = 'This link is too long for a QR code. Use Copy Link instead.';
    err.classList.remove('hidden');
  }
}

/* ---------- open / read ---------- */

async function openClip() {
  if (state.busy) return;
  const btn = el('open-btn');
  btn.disabled = true;
  btn.textContent = 'Fetching\u2026';
  try {
    const data = await rpc('read_clip', { p_id: state.clipId });
    state.cipher = { ciphertext: data.ciphertext, iv: data.iv, salt: data.salt, mode: data.mode };
    state.viewsLeft = data.views_left;

    if (data.mode === 'p') {
      el('unlock-note').textContent = data.views_left === 0
        ? 'This clip has now been fetched. Enter the password to read it.'
        : 'This clip can be opened ' + data.views_left + ' more time(s) after this one.';
      showView('unlock-view');
      el('unlock-password').focus();
      return;
    }

    const key = readKeyFromFragment();
    if (!key) { showError('missing_key'); return; }
    const payload = await decryptPayload(state.cipher, key, 'key');
    renderClip(payload, data);
  } catch (err) {
    showError(err instanceof ApiError ? err.code : 'decrypt_failed');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Open clip';
  }
}

function readKeyFromFragment() {
  const hash = window.location.hash || '';
  const m = hash.match(/[#&]k=([A-Za-z0-9_-]+)/);
  if (!m) return null;
  try {
    const raw = fromB64u(m[1]);
    return raw.length === 32 ? raw : null;
  } catch (e) {
    return null;
  }
}

async function attemptUnlock() {
  if (state.busy) return;
  const password = el('unlock-password').value;
  const errBox = el('unlock-error');
  errBox.classList.add('hidden');
  if (!password) { errBox.textContent = 'Enter the password first.'; errBox.classList.remove('hidden'); return; }

  const btn = el('unlock-btn');
  btn.disabled = true;
  btn.textContent = 'Unlocking\u2026';
  try {
    const payload = await decryptPayload(state.cipher, password, 'password');
    renderClip(payload, { views_left: state.viewsLeft, expires_at: state.expiresAt || null });
  } catch (e) {
    errBox.textContent = 'Wrong password. The clip is still in this tab \u2014 try again.';
    errBox.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Unlock';
  }
}

function renderClip(payload, meta) {
  el('content-display').innerHTML = sanitizeHtml(marked.parse(payload.t || ''));
  state.rawText = payload.t || '';

  const bits = [];
  if (meta && meta.expires_at) bits.push('expires ' + new Date(meta.expires_at).toLocaleString());
  if (meta && meta.views_left !== null && meta.views_left !== undefined) {
    bits.push(meta.views_left === 0 ? 'this was the last allowed open' : meta.views_left + ' more open(s) allowed');
  }
  el('read-meta').textContent = bits.join(' \u00b7 ');

  // Remove the key from the address bar so this device does not keep it.
  try { history.replaceState({}, document.title, window.location.pathname); } catch (e) {}

  showView('read-view');
}

/* ---------- redeem by PIN ---------- */

async function redeemPin() {
  if (state.busy) return;
  const input = el('pin-input');
  const pin = input.value.trim();
  const errBox = el('pin-error');
  errBox.classList.add('hidden');
  errBox.textContent = '';

  if (!/^[0-9]{4,5}$/.test(pin)) {
    errBox.textContent = 'Enter the 5-digit PIN.';
    errBox.classList.remove('hidden');
    return;
  }

  const btn = el('pin-btn');
  btn.disabled = true;
  btn.textContent = 'Checking\u2026';
  try {
    const res = await rpc('redeem_pin', { p_pin: pin });

    if (!res || !res.ok) {
      errBox.textContent = FRIENDLY[res && res.error ? res.error : 'invalid_pin'];
      errBox.classList.remove('hidden');
      return;
    }

    // A password clip is only located by its PIN. Keep the ciphertext in memory
    // and ask for the password, which is what actually unlocks it.
    if (res.mode === 'p') {
      state.cipher = { ciphertext: res.ciphertext, iv: res.iv, salt: res.salt, mode: 'p' };
      state.viewsLeft = res.views_left;
      state.expiresAt = res.expires_at;
      el('unlock-note').textContent = 'The PIN found your clip. It also has a password \u2014 enter it to read the contents.';
      showView('unlock-view');
      el('unlock-password').focus();
      return;
    }

    // No password: the server verified the PIN and handed back the wrapped key,
    // which is unwrapped here, in the browser, using the PIN the user typed.
    const rawKey = await unwrapKeyFromPin(res.pin_wrapped, res.pin_salt, pin);
    const payload = await decryptPayload(
      { ciphertext: res.ciphertext, iv: res.iv, salt: null, mode: 'k' },
      rawKey,
      'key'
    );
    input.value = '';
    renderClip(payload, res);
  } catch (err) {
    if (err instanceof ApiError) {
      errBox.textContent = friendly(err.code);
    } else {
      errBox.textContent = 'That PIN opened a clip, but its contents could not be decrypted.';
    }
    errBox.classList.remove('hidden');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Open';
  }
}

/* ---------- history ---------- */

function readHistory() {
  try { return JSON.parse(localStorage.getItem('clipHistory') || '[]'); } catch (e) { return []; }
}

function saveToHistory(id, url, len) {
  try {
    const hist = readHistory();
    hist.unshift({ id: id, url: url, len: len, date: new Date().toLocaleString() });
    localStorage.setItem('clipHistory', JSON.stringify(hist.slice(0, 10)));
  } catch (e) {}
}

function toggleHistory() {
  const panel = el('history-panel');
  const overlay = el('history-overlay');
  const open = panel.classList.toggle('open');
  overlay.style.display = open ? 'block' : 'none';
  el('history-toggle-btn').setAttribute('aria-expanded', open ? 'true' : 'false');
  if (open) renderHistory();
}

function renderHistory() {
  const list = el('history-list');
  const hist = readHistory();
  list.innerHTML = '';

  if (!hist.length) {
    const p = document.createElement('p');
    p.className = 'empty-note';
    p.textContent = 'No clips yet.';
    list.appendChild(p);
    return;
  }

  hist.forEach(function (item) {
    const row = document.createElement('div');
    row.className = 'history-item';

    const label = document.createElement('div');
    label.className = 'history-label';
    label.textContent = 'Clip \u00b7 ' + (item.len || 0) + ' chars';

    const date = document.createElement('div');
    date.className = 'history-date';
    date.textContent = item.date || '';

    const actions = document.createElement('div');
    actions.className = 'history-actions';

    const openBtn = document.createElement('button');
    openBtn.type = 'button';
    openBtn.className = 'mini';
    openBtn.textContent = 'Open';
    openBtn.addEventListener('click', function () { window.location.href = item.url; });

    actions.appendChild(openBtn);

    row.appendChild(label);
    row.appendChild(date);
    row.appendChild(actions);
    list.appendChild(row);
  });
}

function clearHistory() {
  try { localStorage.removeItem('clipHistory'); } catch (e) {}
  renderHistory();
  toast('Recents cleared');
}

/* ---------- misc ---------- */

async function copyText(text, okMessage) {
  if (!text) { toast('Nothing to copy yet', 'bad'); return; }
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      toast(okMessage || 'Copied');
      return;
    }
  } catch (e) {}
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.setAttribute('readonly', '');
  ta.style.position = 'fixed';
  ta.style.top = '-1000px';
  document.body.appendChild(ta);
  ta.select();
  let ok = false;
  try { ok = document.execCommand('copy'); } catch (e) { ok = false; }
  ta.remove();
  toast(ok ? (okMessage || 'Copied') : 'Copy failed \u2014 select and copy manually', ok ? '' : 'bad');
}

/* ---------- boot ---------- */

function bindUI() {
  const on = function (id, ev, fn) {
    const node = el(id);
    if (node) node.addEventListener(ev, fn);
  };

  on('theme-toggle-btn', 'click', toggleTheme);
  on('history-toggle-btn', 'click', toggleHistory);
  on('history-overlay', 'click', toggleHistory);
  on('clear-history-btn', 'click', clearHistory);
  on('generate-btn', 'click', generateLink);
  on('clip-text', 'input', updateLengthHint);
  on('open-btn', 'click', openClip);
  on('unlock-btn', 'click', attemptUnlock);
  on('unlock-password', 'keydown', function (e) {
    if (e.key === 'Enter') { e.preventDefault(); attemptUnlock(); }
  });
  on('copy-link-btn', 'click', function () { copyText(el('share-link').innerText, 'Link copied'); });
  on('copy-content-btn', 'click', function () { copyText(state.rawText, 'Content copied'); });
  on('new-clip-btn', 'click', function () { window.location.href = window.location.pathname; });
  on('new-clip-btn-2', 'click', function () { window.location.href = window.location.pathname; });
  on('pin-btn', 'click', redeemPin);
  on('pin-input', 'keydown', function (e) {
    if (e.key === 'Enter') { e.preventDefault(); redeemPin(); }
  });
  on('pin-input', 'input', function () {
    el('pin-input').value = el('pin-input').value.replace(/[^0-9]/g, '').slice(0, 5);
  });

  updateLengthHint();
}

function route() {
  const params = new URLSearchParams(window.location.search);
  const clip = params.get('c');

  if (clip) {
    state.clipId = clip;
    el('open-target').textContent = clip;
    showView('open-view');
    return;
  }

  showView('create-view');
}

document.addEventListener('DOMContentLoaded', function () {
  bindUI();
  route();
});
