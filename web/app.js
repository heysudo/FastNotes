// FastNotes app — local-first, zero-knowledge. All plaintext lives only in this tab's memory.
'use strict';

/* ================= IndexedDB ================= */
const idb = (() => {
  let dbp = null;
  function open() {
    if (dbp) return dbp;
    dbp = new Promise((res, rej) => {
      const rq = indexedDB.open('fastnotes', 1);
      rq.onupgradeneeded = () => {
        const d = rq.result;
        d.createObjectStore('notes', { keyPath: 'id' });   // encrypted note records
        d.createObjectStore('images');                     // encrypted image bytes
        d.createObjectStore('kv');                         // lastSync, session
        d.createObjectStore('pending', { autoIncrement: true }); // outbound op queue
      };
      rq.onsuccess = () => res(rq.result);
      rq.onerror = () => rej(rq.error);
    });
    return dbp;
  }
  async function tx(store, mode, fn) {
    const d = await open();
    return new Promise((res, rej) => {
      const t = d.transaction(store, mode);
      const s = t.objectStore(store);
      const out = fn(s);
      t.oncomplete = () => res(out instanceof IDBRequest ? out.result : out);
      t.onerror = () => rej(t.error);
    });
  }
  return {
    get: (st, k) => tx(st, 'readonly', s => s.get(k)),
    put: (st, v, k) => tx(st, 'readwrite', s => k !== undefined ? s.put(v, k) : s.put(v)),
    add: (st, v) => tx(st, 'readwrite', s => s.add(v)),
    del: (st, k) => tx(st, 'readwrite', s => s.delete(k)),
    all: (st) => tx(st, 'readonly', s => s.getAll()),
    keys: (st) => tx(st, 'readonly', s => s.getAllKeys()),
    clear: (st) => tx(st, 'readwrite', s => s.clear()),
  };
})();

/* ================= state ================= */
const notes = new Map();      // id -> {id, title, md, color, pinned, images:[], cover, created, updated}
const srvMeta = new Map();    // id -> {version, updated_at} last known from server
const CLIENT_ID = FNCrypto.newId(); // identifies this tab so we ignore our own SSE echoes
let es = null;                // EventSource for real-time push
const srvVersion = (id) => (srvMeta.get(id) || {}).version || 0;
const srvUpdated = (id) => (srvMeta.get(id) || {}).updated_at || 0;
const setSrvMeta = (id, version, updated_at) => srvMeta.set(id, { version, updated_at });
const imgURLs = new Map();    // imageId -> decrypted object URL
let currentId = null;         // note open in editor
let editMode = false;
let searchTerm = '';
let saveTimer = null;
let pendingFlushing = false;
let coverReplace = false; // next file-input pick replaces the cover instead of appending
let aiOn = false;         // server has AI cover keys configured
const aiTimers = new Map();

const $ = (id) => document.getElementById(id);
// Editor status line. gen=true shows the animated "…" loop (cover generation).
function setStatus(text, gen) {
  const el = $('ed-status');
  el.classList.toggle('gen', !!gen);
  el.textContent = text;
}
const isGenerating = () => $('ed-status').classList.contains('gen');
const toast = (msg) => {
  const t = $('toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove('show'), 2600);
};

/* ================= API ================= */
async function api(path, opts = {}) {
  opts.headers = Object.assign({ 'Authorization': 'Bearer ' + FNCrypto.token(), 'X-Client-Id': CLIENT_ID }, opts.headers || {});
  const r = await fetch(path, opts);
  if (r.status === 401) { hardLock('Wrong password or session expired.'); throw new Error('unauthorized'); }
  if (!r.ok && r.status !== 409) throw new Error('api ' + r.status);
  return r;
}

/* ================= markdown ================= */
marked.setOptions({ gfm: true, breaks: true });
function renderMD(md, interactive) {
  const html = DOMPurify.sanitize(marked.parse(md || ''));
  const div = document.createElement('div');
  div.innerHTML = html;
  let idx = 0;
  div.querySelectorAll('input[type=checkbox]').forEach(cb => {
    cb.dataset.ck = idx++;
    if (interactive) cb.removeAttribute('disabled');
    else { cb.setAttribute('disabled', ''); cb.style.pointerEvents = 'none'; }
  });
  return div;
}
// Toggle the nth task-list checkbox inside markdown source.
function toggleCheckboxInMD(md, n) {
  let i = -1;
  return md.replace(/(^[ \t]*[-*+] +)\[([ xX])\]/gm, (m, pre, state) => {
    i++;
    if (i !== n) return m;
    return pre + (state === ' ' ? '[x]' : '[ ]');
  });
}

/* ================= unlock ================= */
async function boot() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('/sw.js').catch(() => {});
  }
  // bootstrap: network first, IndexedDB fallback so unlock works fully offline
  let bs = null, offline = false;
  try {
    bs = await (await fetch('/api/bootstrap')).json();
    await idb.put('kv', bs, 'bootstrap');
  } catch (e) {
    bs = await idb.get('kv', 'bootstrap');
    offline = true;
    if (!bs || !bs.configured) {
      $('unlock-err').textContent = 'Offline and no local data on this device yet.';
      $('unlock-btn').disabled = true;
      return;
    }
  }
  const firstRun = !bs.configured && !offline;
  if (firstRun) {
    $('unlock-sub').textContent = 'First run — choose a master password. It encrypts everything and is NOT recoverable if forgotten.';
    $('pw2').style.display = '';
    $('unlock-btn').textContent = 'Create & unlock';
  }
  $('unlock-form').onsubmit = async (ev) => {
    ev.preventDefault();
    const pw = $('pw').value;
    const err = $('unlock-err');
    err.textContent = '';
    if (pw.length < (firstRun ? 8 : 1)) { err.textContent = firstRun ? 'Use at least 8 characters.' : 'Enter your password.'; return; }
    if (firstRun && pw !== $('pw2').value) { err.textContent = 'Passwords do not match.'; return; }
    $('unlock-btn').disabled = true;
    $('unlock-btn').textContent = 'Deriving key…';
    try {
      if (firstRun) {
        const salt = FNCrypto.newSalt();
        const token = await FNCrypto.unlock(pw, salt, FNCrypto.DEFAULT_ITERS);
        const r = await fetch('/api/setup', {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ salt, iters: FNCrypto.DEFAULT_ITERS, auth_token: token }),
        });
        if (!r.ok) throw new Error('setup failed');
        // refresh the offline-unlock cache with the real salt
        await idb.put('kv', { configured: true, salt, iters: FNCrypto.DEFAULT_ITERS, ai: bs.ai }, 'bootstrap');
      } else {
        await FNCrypto.unlock(pw, bs.salt, bs.iters);
        try {
          const probe = await fetch('/api/notes?since=99999999999999', { headers: { 'Authorization': 'Bearer ' + FNCrypto.token() } });
          if (probe.status === 401) { err.textContent = 'Wrong password.'; resetUnlockBtn(); return; }
          if (!probe.ok) throw new Error('server error ' + probe.status);
        } catch (netErr) {
          // offline: verify the password against a locally cached note instead
          const cached = (await idb.all('notes')).filter(rec => !rec.deleted && rec.blob);
          if (cached.length) {
            try { await FNCrypto.decryptJSON(cached[0].blob); }
            catch (bad) { err.textContent = 'Wrong password.'; resetUnlockBtn(); return; }
          } else if (!offline) {
            throw netErr;
          }
        }
      }
      await enterApp();
    } catch (e) {
      err.textContent = 'Could not unlock: ' + e.message;
      resetUnlockBtn();
    }
  };
  function resetUnlockBtn() {
    $('unlock-btn').disabled = false;
    $('unlock-btn').textContent = firstRun ? 'Create & unlock' : 'Unlock';
  }
}

function hardLock(msg) {
  FNCrypto.lock();
  if (es) { es.close(); es = null; }
  if (msg) sessionStorage.setItem('fn-msg', msg);
  location.reload();
}

/* ================= auto-lock =================
   Lock after the tab has been non-active for 2 minutes: wipes the in-memory
   keys and returns to the password screen. Background timers can be throttled
   by the browser, so we also check elapsed time when the tab becomes visible. */
const AUTO_LOCK_MS = window.__autolockMs || 120000;
let hiddenAt = null;
let lockTimer = null;

function watchAutoLock() {
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) {
      hiddenAt = Date.now();
      // flush any in-flight edit before we might lock
      if (currentId) { clearTimeout(saveTimer); saveNote(currentId); }
      clearTimeout(lockTimer);
      lockTimer = setTimeout(() => hardLock('Locked after inactivity.'), AUTO_LOCK_MS);
    } else {
      clearTimeout(lockTimer);
      if (hiddenAt && Date.now() - hiddenAt >= AUTO_LOCK_MS) {
        hardLock('Locked after inactivity.');
        return;
      }
      hiddenAt = null;
    }
  });
}

/* ================= app entry ================= */
async function enterApp() {
  // load local cache first — instant paint
  const cached = await idb.all('notes');
  for (const rec of cached) {
    if (rec.deleted) continue;
    try {
      const obj = await FNCrypto.decryptJSON(rec.blob);
      notes.set(rec.id, obj);
      setSrvMeta(rec.id, rec.version || 0, rec.updated_at || 0);
    } catch (e) { /* wrong-key record; skip */ }
  }
  // replay queued offline edits over the confirmed base so memory reflects them
  try {
    for (const op of await idb.all('pending')) {
      if (op.kind === 'put' && op.blob) {
        try { notes.set(op.id, await FNCrypto.decryptJSON(op.blob)); } catch (e) {}
      } else if (op.kind === 'del') {
        notes.delete(op.id);
      }
    }
  } catch (e) {}
  try {
    const bs = await (await fetch('/api/bootstrap')).json();
    aiOn = !!bs.ai;
  } catch (e) { /* offline is fine */ }
  $('unlock').style.display = 'none';
  $('app').style.display = '';
  $('ed-ai').style.display = aiOn ? '' : 'none';
  renderBoard();
  wireUI();
  watchAutoLock();
  await syncNow().catch(() => {});
  startEvents();                                       // real-time push
  setInterval(() => syncNow().catch(() => {}), 30000); // safety-net poll (SSE handles real-time)
  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) syncNow().catch(() => {});
  });
  const msg = sessionStorage.getItem('fn-msg');
  if (msg) { sessionStorage.removeItem('fn-msg'); toast(msg); }
}

/* ================= 3-way merge (no-data-loss conflicts) ================= */
function _matchMap(o, x) {
  const m = o.length, n = x.length;
  const dp = Array.from({ length: m + 1 }, () => new Int32Array(n + 1));
  for (let i = m - 1; i >= 0; i--)
    for (let j = n - 1; j >= 0; j--)
      dp[i][j] = o[i] === x[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const map = new Map();
  let i = 0, j = 0;
  while (i < m && j < n) {
    if (o[i] === x[j]) { map.set(i, j); i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) i++; else j++;
  }
  return map;
}
function _eqArr(p, q) {
  if (p.length !== q.length) return false;
  for (let i = 0; i < p.length; i++) if (p[i] !== q[i]) return false;
  return true;
}
// diff3 line merge; returns {ok:true,text} or {ok:false} on overlapping edits.
function diff3(oText, aText, bText) {
  const o = (oText || '').split('\n'), a = (aText || '').split('\n'), b = (bText || '').split('\n');
  const ma = _matchMap(o, a), mb = _matchMap(o, b);
  const anchors = [];
  let lastA = -1, lastB = -1;
  for (let i = 0; i < o.length; i++) {
    if (ma.has(i) && mb.has(i)) {
      const ai = ma.get(i), bi = mb.get(i);
      if (ai > lastA && bi > lastB) { anchors.push([i, ai, bi]); lastA = ai; lastB = bi; }
    }
  }
  anchors.push([o.length, a.length, b.length]);
  const out = [];
  let oi = 0, ai = 0, bi = 0;
  for (const [oe, ae, be] of anchors) {
    const oreg = o.slice(oi, oe), areg = a.slice(ai, ae), breg = b.slice(bi, be);
    const aCh = !_eqArr(oreg, areg), bCh = !_eqArr(oreg, breg);
    if (!aCh && !bCh) out.push(...oreg);
    else if (aCh && !bCh) out.push(...areg);
    else if (!aCh && bCh) out.push(...breg);
    else if (_eqArr(areg, breg)) out.push(...areg);
    else return { ok: false };
    if (oe < o.length) out.push(o[oe]);
    oi = oe + 1; ai = ae + 1; bi = be + 1;
  }
  return { ok: true, text: out.join('\n') };
}
function noteSig(n) {
  return JSON.stringify([n.title || '', n.md || '', n.color || 'default', !!n.pinned, n.cover || null, n.images || []]);
}
const sameNote = (x, y) => noteSig(x) === noteSig(y);
function fieldMerge(o, a, b) { // scalar three-way
  if (a === b) return { ok: true, v: a };
  if (a === o) return { ok: true, v: b };
  if (b === o) return { ok: true, v: a };
  return { ok: false };
}
// merge3: base/local/remote note objects -> merged note, or null on hard conflict.
function merge3(base, local, remote) {
  const title = fieldMerge(base.title || '', local.title || '', remote.title || '');
  if (!title.ok) return null; // divergent titles: keep both via conflict-copy
  let md;
  if (local.md === remote.md) md = local.md;
  else if (local.md === base.md) md = remote.md;
  else if (remote.md === base.md) md = local.md;
  else {
    const d = diff3(base.md, local.md, remote.md);
    if (!d.ok) return null;
    md = d.text;
  }
  const color = fieldMerge(base.color || 'default', local.color || 'default', remote.color || 'default');
  const pinned = fieldMerge(!!base.pinned, !!local.pinned, !!remote.pinned);
  const cover = fieldMerge(base.cover || null, local.cover || null, remote.cover || null);
  const images = [...new Set([...(local.images || []), ...(remote.images || [])])]; // union: never drop an image
  return {
    title: title.v,
    md,
    color: color.ok ? color.v : (local.color || 'default'),
    pinned: pinned.ok ? pinned.v : !!local.pinned,
    cover: cover.ok ? cover.v : (local.cover || remote.cover || null),
    images,
    created: base.created || local.created || Date.now(),
    updated: Date.now(),
  };
}

// reconcile a server record against local state without ever losing data.
async function reconcile(id, remote) {
  const local = notes.get(id);
  const cached = await idb.get('notes', id);
  let base = null;
  if (cached && cached.blob) { try { base = await FNCrypto.decryptJSON(cached.blob); } catch (e) {} }

  if (remote.deleted) {
    if (local && base && !sameNote(local, base)) {
      // deleted elsewhere but we have unsaved local edits — resurrect (local wins).
      setSrvMeta(id, remote.version, remote.updated_at);
      await saveNote(id);
    } else {
      notes.delete(id);
      setSrvMeta(id, remote.version, remote.updated_at);
      await idb.put('notes', { id, deleted: true, updated_at: remote.updated_at, version: remote.version });
      if (currentId === id) closeEditor();
    }
    renderBoard();
    return;
  }

  let remoteObj;
  try { remoteObj = await FNCrypto.decryptJSON(remote.blob); }
  catch (e) { return; } // can't decrypt (shouldn't happen) — leave local untouched

  const adopt = async () => {
    notes.set(id, remoteObj);
    setSrvMeta(id, remote.version, remote.updated_at);
    await idb.put('notes', { id, blob: remote.blob, updated_at: remote.updated_at, version: remote.version });
  };

  if (!local || (base && sameNote(local, base)) ) {
    await adopt();                       // no local changes → take server version
  } else if (sameNote(local, remoteObj)) {
    setSrvMeta(id, remote.version, remote.updated_at); // same content, just track version
    await idb.put('notes', { id, blob: remote.blob, updated_at: remote.updated_at, version: remote.version });
  } else {
    const merged = base ? merge3(base, local, remoteObj) : null;
    if (merged) {
      notes.set(id, merged);
      setSrvMeta(id, remote.version, remote.updated_at); // push merged onto the current server version
      await idb.put('notes', { id, blob: remote.blob, updated_at: remote.updated_at, version: remote.version });
      await saveNote(id); // re-encrypts merged and queues a versioned push
    } else {
      await adopt(); // server wins as the canonical note...
      const copyId = FNCrypto.newId();
      const copy = Object.assign({}, local, {
        title: (local.title ? local.title + ' ' : '') + '(conflict copy)',
        created: Date.now(), updated: Date.now(),
      });
      notes.set(copyId, copy);
      setSrvMeta(copyId, 0, 0);
      await saveNote(copyId); // ...and the local edits are preserved as a new note
      toast('Note edited on two devices — kept both (see "conflict copy")');
    }
  }
  if (currentId === id) openEditor(id, { keepMode: true });
  renderBoard();
}

/* ================= sync ================= */
function setSync(state) {
  const d = $('syncdot');
  d.className = state === 'busy' ? 'busy' : state === 'err' ? 'err' : '';
  d.title = state === 'busy' ? 'Syncing…' : state === 'err' ? 'Offline — changes queued' : 'Synced';
}

let syncDebounce = null;
function debouncedSync() {
  clearTimeout(syncDebounce);
  syncDebounce = setTimeout(() => syncNow().catch(() => {}), 400);
}

// EventSource: server pushes {id,version,origin} on any write; we ignore our
// own echoes and coalesce the rest into a delta pull. Falls back to the 30s
// poll if SSE is unavailable. EventSource can't send auth headers, so we mint
// a short-lived signed ticket first.
async function startEvents() {
  if (!window.EventSource || !FNCrypto.isUnlocked()) return;
  try {
    const t = await (await api('/api/events/ticket', { method: 'POST' })).json();
    if (es) es.close();
    es = new EventSource('/api/events?ticket=' + encodeURIComponent(t.ticket));
    es.onmessage = (ev) => {
      try { const d = JSON.parse(ev.data); if (d.origin === CLIENT_ID) return; } catch (e) {}
      debouncedSync();
    };
    es.onerror = () => {
      if (es) { es.close(); es = null; }
      setTimeout(() => { if (FNCrypto.isUnlocked()) startEvents(); }, 5000); // re-ticket & reconnect
    };
  } catch (e) { /* SSE unavailable — the poll keeps things in sync */ }
}

async function syncNow() {
  setSync('busy');
  try {
    await flushPending();
    const last = (await idb.get('kv', 'lastSync')) || 0;
    const r = await api('/api/notes?since=' + last);
    const { notes: incoming, now } = await r.json();
    for (const rec of incoming) {
      if (rec.updated_at <= srvUpdated(rec.id)) continue; // already have this (incl. our own echoes)
      await reconcile(rec.id, rec); // handles merge, conflict-copy, open-editor protection
    }
    await idb.put('kv', now, 'lastSync');
    setSync('ok');
  } catch (e) {
    if (e.message !== 'unauthorized') setSync('err');
    throw e;
  }
}

async function queueOp(op) { // op: {kind:'put'|'del'|'img'|'imgdel', id, blob?}
  await idb.add('pending', op); // own store + autoincrement key: no read-modify-write races
  flushPending().catch(() => setSync('err'));
}

async function flushPending() {
  if (pendingFlushing) return;
  pendingFlushing = true;
  try {
    for (;;) {
      const keys = await idb.keys('pending');
      if (!keys.length) break;
      const key = keys[0];
      const op = await idb.get('pending', key);
      if (!op) { await idb.del('pending', key); continue; }
      try {
        if (op.kind === 'put') {
          const r = await api('/api/notes/' + op.id, {
            method: 'PUT', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ blob: op.blob, base_version: srvVersion(op.id) }),
          });
          if (r.status === 409) {
            const { note } = await r.json(); // someone else wrote first
            await reconcile(op.id, note);    // merge or conflict-copy, then re-queue
          } else {
            const { version, updated_at } = await r.json();
            setSrvMeta(op.id, version, updated_at);
            if (notes.has(op.id)) await idb.put('notes', { id: op.id, blob: op.blob, updated_at, version });
          }
        } else if (op.kind === 'del') {
          await api('/api/notes/' + op.id, { method: 'DELETE' });
        } else if (op.kind === 'img') {
          const bytes = await idb.get('images', op.id);
          if (bytes) await api('/api/images/' + op.id, { method: 'PUT', body: bytes });
        } else if (op.kind === 'imgdel') {
          await api('/api/images/' + op.id, { method: 'DELETE' });
        }
      } catch (e) {
        // Permanent client errors: drop the op so the queue never wedges.
        if (/api 4\d\d/.test(e.message)) {
          console.warn('dropping bad op', op, e.message);
        } else {
          throw e; // network/server errors: keep op, retry later
        }
      }
      await idb.del('pending', key);
    }
  } finally {
    pendingFlushing = false;
  }
}

/* ================= images ================= */
async function imageURL(imgId) {
  if (imgURLs.has(imgId)) return imgURLs.get(imgId);
  let bytes = await idb.get('images', imgId);
  if (!bytes) {
    try {
      const r = await api('/api/images/' + imgId);
      bytes = new Uint8Array(await r.arrayBuffer());
      await idb.put('images', bytes, imgId);
    } catch (e) { return null; }
  }
  try {
    const pt = await FNCrypto.decryptBytes(bytes);
    const url = URL.createObjectURL(new Blob([pt]));
    imgURLs.set(imgId, url);
    return url;
  } catch (e) { return null; }
}

async function addImageToNote(noteId, file) {
  const buf = await file.arrayBuffer();
  if (buf.byteLength > 12 << 20) { toast('Image too large (12 MB max)'); return; }
  const enc = await FNCrypto.encryptBytes(buf);
  const imgId = FNCrypto.newId();
  await idb.put('images', enc, imgId);
  const n = notes.get(noteId);
  n.images = n.images || [];
  n.images.push(imgId);
  if (!n.cover) n.cover = imgId;
  await queueOp({ kind: 'img', id: imgId });
  await saveNote(noteId);
  if (currentId === noteId) openEditor(noteId, { keepMode: true });
}

async function replaceCover(noteId, file) {
  const n = notes.get(noteId);
  if (!n) return;
  const buf = await file.arrayBuffer();
  if (buf.byteLength > 12 << 20) { toast('Image too large (12 MB max)'); return; }
  const enc = await FNCrypto.encryptBytes(buf);
  const imgId = FNCrypto.newId();
  await idb.put('images', enc, imgId);
  await queueOp({ kind: 'img', id: imgId });
  const old = n.cover;
  if (old) {
    n.images = (n.images || []).filter(i => i !== old);
    await idb.del('images', old);
    imgURLs.delete(old);
    await queueOp({ kind: 'imgdel', id: old });
  }
  n.images = n.images || [];
  n.images.push(imgId);
  n.cover = imgId;
  await saveNote(noteId);
  if (currentId === noteId) openEditor(noteId, { keepMode: true });
}

/* ================= AI covers ================= */
// Auto-generate a minimal brand-logo style cover for notes with no image.
// Privacy: this sends THIS note's title/text (plaintext) to the server's
// /api/ai/cover, which forwards to Claude Haiku + Higgsfield. The returned
// image is encrypted client-side like any upload. Once per note (aiTried).
function maybeAutoCover(id) {
  if (!aiOn) return;
  const n = notes.get(id);
  if (!n || n.cover || (n.images && n.images.length) || n.aiTried) return;
  if (((n.title || '') + (n.md || '')).trim().length < 12) return;
  clearTimeout(aiTimers.get(id));
  aiTimers.set(id, setTimeout(() => generateCover(id, false), 4000));
}

async function generateCover(id, manual) {
  const n = notes.get(id);
  if (!n) return;
  if (!aiOn) { if (manual) toast('AI covers are not configured on the server'); return; }
  const text = (n.md || '').slice(0, 3000);
  if (((n.title || '') + text).trim().length < 8) { if (manual) toast('Note too short for a cover'); return; }
  if (n.aiBusy) return;
  n.aiBusy = true;
  n.aiTried = true;
  if (currentId === id) setStatus('Generating cover', true);
  try {
    const r = await api('/api/ai/cover', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ title: n.title || '', text }),
    });
    const j = await r.json();
    const bytes = FNCrypto.b64.dec(j.image);
    const enc = await FNCrypto.encryptBytes(bytes.buffer);
    const imgId = FNCrypto.newId();
    await idb.put('images', enc, imgId);
    await queueOp({ kind: 'img', id: imgId });
    const old = n.cover;
    if (old) {
      n.images = (n.images || []).filter(i => i !== old);
      await idb.del('images', old);
      imgURLs.delete(old);
      await queueOp({ kind: 'imgdel', id: old });
    }
    n.images = n.images || [];
    n.images.push(imgId);
    n.cover = imgId;
    delete n.aiBusy;
    await saveNote(id);
    if (currentId === id) { openEditor(id, { keepMode: true }); setStatus('Cover generated'); }
  } catch (e) {
    delete n.aiBusy;
    await saveNote(id); // persist aiTried so we don't loop on failures
    if (currentId === id) setStatus('');
    if (manual) toast('Cover generation failed');
  }
}

/* ================= Google Keep import ================= */
// Runs entirely in the browser: reads a Google Takeout .zip, decodes each Keep
// note, encrypts client-side, and uploads ciphertext. Your notes never leave
// this tab in plaintext.

// Minimal dependency-free ZIP reader using the built-in DecompressionStream.
async function inflateRaw(bytes) {
  const ds = new DecompressionStream('deflate-raw');
  const ab = await new Response(new Blob([bytes]).stream().pipeThrough(ds)).arrayBuffer();
  return new Uint8Array(ab);
}
async function unzip(arrayBuffer) {
  const dv = new DataView(arrayBuffer), u8 = new Uint8Array(arrayBuffer);
  let eocd = -1;
  for (let i = u8.length - 22; i >= 0 && i > u8.length - 22 - 65557; i--) {
    if (dv.getUint32(i, true) === 0x06054b50) { eocd = i; break; }
  }
  if (eocd < 0) throw new Error('Not a valid .zip file');
  const cdCount = dv.getUint16(eocd + 10, true);
  const cdOff = dv.getUint32(eocd + 16, true);
  if (cdOff === 0xffffffff || cdCount === 0xffff) throw new Error('ZIP64 archives are not supported');
  const files = new Map();
  let p = cdOff;
  for (let n = 0; n < cdCount; n++) {
    if (dv.getUint32(p, true) !== 0x02014b50) break;
    const method = dv.getUint16(p + 10, true);
    const compSize = dv.getUint32(p + 20, true);
    const nameLen = dv.getUint16(p + 28, true);
    const extraLen = dv.getUint16(p + 30, true);
    const commentLen = dv.getUint16(p + 32, true);
    const localOff = dv.getUint32(p + 42, true);
    const name = new TextDecoder().decode(u8.subarray(p + 46, p + 46 + nameLen));
    files.set(name, { method, compSize, localOff });
    p += 46 + nameLen + extraLen + commentLen;
  }
  return {
    names: [...files.keys()],
    async read(name) {
      const f = files.get(name);
      if (!f) return null;
      const lNameLen = dv.getUint16(f.localOff + 26, true);
      const lExtraLen = dv.getUint16(f.localOff + 28, true);
      const start = f.localOff + 30 + lNameLen + lExtraLen;
      const data = u8.subarray(start, start + f.compSize);
      if (f.method === 0) return data.slice();
      if (f.method === 8) return inflateRaw(data);
      throw new Error('Unsupported zip compression method ' + f.method);
    },
  };
}

const KEEP_COLORS = {
  DEFAULT: 'default', RED: 'coral', ORANGE: 'peach', YELLOW: 'sand', GREEN: 'mint',
  TEAL: 'sage', BLUE: 'fog', CERULEAN: 'storm', GRAY: 'chalk', PINK: 'blossom',
  PURPLE: 'dusk', BROWN: 'clay',
};
function b64url(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/[+/=]/g, c => ({ '+': '-', '/': '_', '=': '' }[c]));
}
// Deterministic id from Keep's create timestamp so re-importing is idempotent.
async function keepStableId(k, name) {
  const seed = (k.createdTimestampUsec || '') + '|' + (k.title || '') + '|' + name;
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(seed));
  return 'kp' + b64url(new Uint8Array(buf).slice(0, 12));
}
function keepToNote(k) {
  let md;
  if (Array.isArray(k.listContent) && k.listContent.length) {
    md = k.listContent.map(it => `- [${it.isChecked ? 'x' : ' '}] ${(it.text || '').trim()}`).join('\n');
  } else {
    md = k.textContent || '';
  }
  const labels = (k.labels || []).map(l => l.name).filter(Boolean);
  if (labels.length) md += (md ? '\n\n' : '') + labels.map(l => '#' + l.replace(/\s+/g, '-')).join(' ');
  const usToMs = u => (u ? Math.floor(Number(u) / 1000) : Date.now());
  return {
    title: k.title || '', md,
    color: KEEP_COLORS[k.color] || 'default',
    pinned: !!k.isPinned, images: [], cover: null,
    created: usToMs(k.createdTimestampUsec), updated: usToMs(k.userEditedTimestampUsec),
  };
}

async function importTakeout(file) {
  const ov = $('import-overlay');
  const setStat = (t, pct) => { $('import-stat').textContent = t; if (pct != null) $('import-fill').style.width = pct + '%'; };
  ov.classList.add('open'); setStat('Reading export…', 3);
  let zip;
  try { zip = await unzip(await file.arrayBuffer()); }
  catch (e) { setStat('Could not read file: ' + e.message, 0); setTimeout(() => ov.classList.remove('open'), 3000); return; }

  const jsonNames = zip.names.filter(n => /\.json$/i.test(n) && /(^|\/)keep\//i.test(n));
  const names = jsonNames.length ? jsonNames : zip.names.filter(n => /\.json$/i.test(n) && !/labels/i.test(n));
  const imgIndex = new Map();
  for (const n of zip.names) if (/\.(jpe?g|png|gif|webp|heic|bmp)$/i.test(n)) imgIndex.set(n.split('/').pop(), n);

  // content signatures of notes already present, so re-imports and cross-account
  // overlap (the same note owned by another account) are skipped, not duplicated.
  const sigOf = n => (n.title || '').trim() + ' ' + (n.md || '').trim();
  const existingSigs = new Set([...notes.values()].map(sigOf));

  let imported = 0, skipped = 0, images = 0;
  for (let i = 0; i < names.length; i++) {
    setStat(`Importing note ${i + 1} of ${names.length}…`, 5 + Math.round(90 * i / names.length));
    let k;
    try { k = JSON.parse(new TextDecoder().decode(await zip.read(names[i]))); }
    catch (e) { skipped++; continue; }
    if (!k || k.isTrashed || (k.textContent === undefined && !k.listContent && !k.title)) { skipped++; continue; }
    const id = await keepStableId(k, names[i]);
    if (notes.has(id)) { skipped++; continue; } // already imported previously
    const obj = keepToNote(k);
    if (existingSigs.has(sigOf(obj))) { skipped++; continue; } // identical content already present
    existingSigs.add(sigOf(obj));
    for (const att of k.attachments || []) {
      const base = (att.filePath || '').split('/').pop();
      const zn = imgIndex.get(base) || [...imgIndex.keys()].find(bn => base && bn.startsWith(base.replace(/\.[^.]+$/, '')));
      const bytes = zn ? await zip.read(imgIndex.get(zn) || zn) : null;
      if (bytes && bytes.length) {
        const enc = await FNCrypto.encryptBytes(bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength));
        const imgId = FNCrypto.newId();
        await idb.put('images', enc, imgId);
        await queueOp({ kind: 'img', id: imgId });
        obj.images.push(imgId); images++;
      }
    }
    obj.cover = obj.images[0] || null;
    notes.set(id, obj);
    setSrvMeta(id, 0, 0);
    await saveNote(id);
    imported++;
  }
  setStat('Uploading…', 96);
  await flushPending().catch(() => {});
  setStat(`Done — imported ${imported} note${imported === 1 ? '' : 's'}${images ? ', ' + images + ' image' + (images === 1 ? '' : 's') : ''}${skipped ? ' (' + skipped + ' skipped)' : ''}.`, 100);
  renderBoard();
  setTimeout(() => ov.classList.remove('open'), 3500);
  toast(`Imported ${imported} notes from Google Keep`);
}

/* ================= persistence ================= */
async function saveNote(id) {
  const n = notes.get(id);
  if (!n) return;
  n.updated = Date.now();
  const { aiBusy, ...persistable } = n; // transient flags never hit disk
  const blob = await FNCrypto.encryptJSON(persistable);
  // NOTE: we do NOT overwrite the cached `notes` record here — that record holds
  // the last server-CONFIRMED blob, which reconcile() needs as the 3-way merge
  // base. The optimistic local edit lives in the pending queue (and in memory)
  // and is replayed over the base on reload.
  await queueOp({ kind: 'put', id, blob });
  renderBoard();
}

let dirtySince = null; // max-wait guard: force a save at least every 5s while typing
function scheduleSave(id) {
  if (!isGenerating()) setStatus('Saving…');
  const now = Date.now();
  if (dirtySince === null) dirtySince = now;
  clearTimeout(saveTimer);
  const wait = now - dirtySince >= 5000 ? 0 : 300;
  saveTimer = setTimeout(async () => {
    dirtySince = null;
    await saveNote(id);
    if (!isGenerating()) setStatus('Saved');
    maybeAutoCover(id);
  }, wait);
}

async function deleteNote(id) {
  const n = notes.get(id);
  notes.delete(id);
  await idb.put('notes', { id, deleted: true, updated_at: srvUpdated(id), version: srvVersion(id) });
  await queueOp({ kind: 'del', id });
  for (const im of (n && n.images) || []) {
    await idb.del('images', im);
    await queueOp({ kind: 'imgdel', id: im });
  }
  closeEditor();
  renderBoard();
  toast('Note deleted');
}

function newNote(initial = {}) {
  const id = FNCrypto.newId();
  const n = Object.assign({
    title: '', md: '', color: 'default', pinned: false,
    images: [], cover: null, created: Date.now(), updated: Date.now(),
  }, initial);
  notes.set(id, n);
  return id;
}

/* ================= board rendering ================= */
const COL_W = 240, GAP = 12;

function cardFor(id, n) {
  const card = document.createElement('div');
  card.className = 'card c-' + (n.color || 'default');
  card.dataset.id = id;
  if (n.cover) {
    const img = document.createElement('img');
    img.className = 'cover';
    img.alt = '';
    imageURL(n.cover).then(u => { if (u) { img.src = u; } else { img.remove(); } });
    img.addEventListener('load', () => layoutAll());
    card.appendChild(img);
  }
  const inner = document.createElement('div');
  inner.className = 'inner';
  if (n.title) {
    const t = document.createElement('div');
    t.className = 'title';
    t.textContent = n.title;
    inner.appendChild(t);
  }
  if (n.md) {
    const p = renderMD(n.md.length > 1200 ? n.md.slice(0, 1200) + '…' : n.md, false);
    p.className = 'preview';
    inner.appendChild(p);
  }
  card.appendChild(inner);

  const pin = document.createElement('button');
  pin.className = 'pinbtn' + (n.pinned ? ' pinned' : '');
  pin.title = n.pinned ? 'Unpin' : 'Pin';
  pin.innerHTML = '<svg viewBox="0 0 24 24"><path d="M16 9V4h1c.55 0 1-.45 1-1s-.45-1-1-1H7c-.55 0-1 .45-1 1s.45 1 1 1h1v5c0 1.66-1.34 3-3 3v2h5.97v7l1 1 1-1v-7H19v-2c-1.66 0-3-1.34-3-3z"/></svg>';
  pin.onclick = (e) => {
    e.stopPropagation();
    n.pinned = !n.pinned;
    saveNote(id);
  };
  card.appendChild(pin);

  card.onclick = () => openEditor(id);
  return card;
}

function matchesSearch(n) {
  if (!searchTerm) return true;
  const q = searchTerm.toLowerCase();
  return (n.title || '').toLowerCase().includes(q) || (n.md || '').toLowerCase().includes(q);
}

function renderBoard() {
  const pinnedEl = $('masonry-pinned');
  const othersEl = $('masonry-others');
  pinnedEl.innerHTML = '';
  othersEl.innerHTML = '';
  const sorted = [...notes.entries()].sort((a, b) => (b[1].updated || 0) - (a[1].updated || 0));
  let pinnedCount = 0, othersCount = 0;
  for (const [id, n] of sorted) {
    if (!matchesSearch(n)) continue;
    const card = cardFor(id, n);
    if (n.pinned) { pinnedEl.appendChild(card); pinnedCount++; }
    else { othersEl.appendChild(card); othersCount++; }
  }
  $('pinned-wrap').style.display = pinnedCount ? '' : 'none';
  $('others-label').style.display = (pinnedCount && othersCount) ? '' : 'none';
  $('empty').style.display = (pinnedCount + othersCount) === 0 ? '' : 'none';
  layoutAll();
}

function layoutMasonry(el) {
  const cards = [...el.children];
  if (!cards.length) { el.style.height = '0px'; return; }
  const bw = el.clientWidth;
  // Mobile (like Keep): exactly 2 edge-to-edge columns with a slim gutter.
  // Desktop: as many fixed 240px columns as fit, centered.
  const mobile = window.innerWidth <= 600;
  const gap = mobile ? 8 : GAP;
  const cols = mobile ? 2 : Math.max(1, Math.floor((bw + gap) / (COL_W + gap)));
  const colW = mobile ? Math.floor((bw - gap * (cols - 1)) / cols) : COL_W;
  const width = cols * colW + (cols - 1) * gap;
  const offsetX = Math.max(0, (bw - width) / 2);
  const heights = new Array(cols).fill(0);
  for (const c of cards) {
    c.style.width = colW + 'px';
    const h = c.offsetHeight;
    let best = 0;
    for (let i = 1; i < cols; i++) if (heights[i] < heights[best]) best = i;
    c.style.left = (offsetX + best * (colW + gap)) + 'px';
    c.style.top = heights[best] + 'px';
    heights[best] += h + gap;
  }
  el.style.height = Math.max(...heights) + 'px';
}

let layoutTimer = null;
function layoutAll() {
  clearTimeout(layoutTimer);
  layoutTimer = setTimeout(() => {
    layoutMasonry($('masonry-pinned'));
    layoutMasonry($('masonry-others'));
  }, 16);
}
window.addEventListener('resize', layoutAll);

/* ================= editor ================= */
async function openEditor(id, opts = {}) {
  currentId = id;
  const n = notes.get(id);
  if (!n) return;
  const ed = $('editor');
  ed.className = 'open c-' + (n.color || 'default');
  $('ed-title').value = n.title || '';
  $('ed-pin').style.opacity = n.pinned ? 1 : 0.55;
  $('ed-status').textContent = '';
  if (!opts.keepMode) editMode = !n.md; // empty note opens in edit mode
  refreshEditorBody(n);
  // cover
  const cw = $('coverwrap');
  let coverShown = false;
  if (n.cover) {
    const u = await imageURL(n.cover);
    if (u) { $('cover-img').src = u; cw.style.display = 'block'; coverShown = true; }
    else cw.style.display = 'none';
  } else cw.style.display = 'none';
  ed.classList.toggle('has-cover', coverShown);
  document.querySelectorAll('.card').forEach(c => c.classList.toggle('selected', c.dataset.id === id));
  if (editMode) setTimeout(() => $(n.title ? 'ed-md' : 'ed-title').focus(), 240);
}

function refreshEditorBody(n) {
  const ta = $('ed-md');
  const rd = $('ed-rendered');
  if (editMode) {
    ta.style.display = '';
    rd.style.display = 'none';
    ta.value = n.md || '';
    autoGrow(ta);
  } else {
    ta.style.display = 'none';
    rd.style.display = '';
    rd.innerHTML = '';
    if (n.md) {
      const div = renderMD(n.md, true);
      // interactive checkboxes -> mutate markdown source
      div.addEventListener('change', (ev) => {
        const cb = ev.target;
        if (cb.matches('input[type=checkbox]')) {
          n.md = toggleCheckboxInMD(n.md, +cb.dataset.ck);
          scheduleSave(currentId);
        }
      });
      rd.appendChild(div);
    } else {
      rd.innerHTML = '<span class="empty-hint">Empty note — click to write (markdown supported)…</span>';
    }
  }
  $('ed-mode').classList.toggle('active', editMode);
}

function autoGrow(ta) {
  ta.style.height = 'auto';
  ta.style.height = Math.max(300, ta.scrollHeight) + 'px';
}

function closeEditor() {
  currentId = null;
  $('editor').className = '';
  $('palette').classList.remove('open');
  document.querySelectorAll('.card.selected').forEach(c => c.classList.remove('selected'));
}

/* ================= palette ================= */
const COLORS = ['default', 'coral', 'peach', 'sand', 'mint', 'sage', 'fog', 'storm', 'dusk', 'blossom', 'clay', 'chalk'];
function buildPalette() {
  const p = $('palette');
  for (const c of COLORS) {
    const sw = document.createElement('div');
    sw.className = 'swatch c-' + c;
    sw.title = c;
    if (c === 'default') sw.style.border = '2px solid #5f6368';
    sw.onclick = () => {
      const n = notes.get(currentId);
      if (!n) return;
      n.color = c;
      const ed = $('editor');
      ed.className = 'open c-' + c + (ed.classList.contains('has-cover') ? ' has-cover' : '');
      p.classList.remove('open');
      saveNote(currentId);
    };
    p.appendChild(sw);
  }
}

/* ================= UI wiring ================= */
function wireUI() {
  buildPalette();

  $('qa-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && $('qa-input').value.trim()) {
      const id = newNote({ md: $('qa-input').value.trim() });
      $('qa-input').value = '';
      saveNote(id).then(() => maybeAutoCover(id));
    }
  });
  $('quickadd-box').addEventListener('click', (e) => {
    if (e.target === $('qa-input')) return;
    if (e.target.closest('#qa-img')) return;
    const id = newNote({});
    saveNote(id).then(() => openEditor(id));
  });
  $('qa-img').onclick = () => {
    const id = newNote({});
    notes.get(id) && saveNote(id).then(() => {
      openEditor(id);
      $('file-input').click();
    });
  };

  $('q').addEventListener('input', () => {
    searchTerm = $('q').value.trim();
    renderBoard();
  });

  $('ed-title').addEventListener('input', () => {
    const n = notes.get(currentId);
    if (!n) return;
    n.title = $('ed-title').value;
    scheduleSave(currentId);
  });
  $('ed-md').addEventListener('input', () => {
    const n = notes.get(currentId);
    if (!n) return;
    n.md = $('ed-md').value;
    autoGrow($('ed-md'));
    scheduleSave(currentId);
  });
  $('ed-mode').onclick = () => {
    editMode = !editMode;
    refreshEditorBody(notes.get(currentId));
    if (editMode) $('ed-md').focus();
  };
  $('ed-rendered').addEventListener('click', (e) => {
    if (e.target.closest('a') || e.target.matches('input[type=checkbox]')) return;
    editMode = true;
    refreshEditorBody(notes.get(currentId));
    $('ed-md').focus();
  });
  $('ed-pin').onclick = () => {
    const n = notes.get(currentId);
    n.pinned = !n.pinned;
    $('ed-pin').style.opacity = n.pinned ? 1 : 0.55;
    saveNote(currentId);
  };
  $('ed-color').onclick = (e) => {
    const p = $('palette');
    const r = e.currentTarget.getBoundingClientRect();
    p.style.left = Math.max(8, r.left - 120) + 'px';
    p.style.top = (r.top - 110) + 'px';
    p.classList.toggle('open');
    p.querySelectorAll('.swatch').forEach(sw => {
      sw.classList.toggle('sel', sw.classList.contains('c-' + (notes.get(currentId).color || 'default')));
    });
  };
  $('ed-image').onclick = () => { coverReplace = false; $('file-input').click(); };
  $('file-input').addEventListener('change', async () => {
    const f = $('file-input').files[0];
    $('file-input').value = '';
    if (!f || !currentId) { coverReplace = false; return; }
    if (coverReplace) { coverReplace = false; await replaceCover(currentId, f); }
    else await addImageToNote(currentId, f);
  });
  $('ed-close-x').onclick = closeEditor;
  $('ed-back').onclick = closeEditor;
  $('fab').onclick = () => {
    const id = newNote({});
    saveNote(id).then(() => openEditor(id));
  };
  $('ed-ai').onclick = () => generateCover(currentId, true);
  $('cover-change').onclick = () => { coverReplace = true; $('file-input').click(); };
  $('cover-remove').onclick = async () => {
    const n = notes.get(currentId);
    if (!n || !n.cover) return;
    n.images = (n.images || []).filter(i => i !== n.cover);
    await idb.del('images', n.cover);
    await queueOp({ kind: 'imgdel', id: n.cover });
    n.cover = n.images[0] || null;
    await saveNote(currentId);
    openEditor(currentId, { keepMode: true });
  };
  $('ed-delete').onclick = () => {
    if (confirm('Delete this note permanently?')) deleteNote(currentId);
  };

  // paste image directly into open editor
  document.addEventListener('paste', async (e) => {
    if (!currentId) return;
    for (const item of e.clipboardData.items) {
      if (item.type.startsWith('image/')) {
        e.preventDefault();
        await addImageToNote(currentId, item.getAsFile());
        return;
      }
    }
  });

  $('import-btn').onclick = () => $('import-input').click();
  $('import-input').addEventListener('change', async () => {
    const f = $('import-input').files[0];
    $('import-input').value = '';
    if (f) await importTakeout(f);
  });
  $('lock-btn').onclick = () => hardLock('Locked.');
  $('export-btn').onclick = async () => {
    try {
      const r = await api('/api/export');
      const blob = await r.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = 'fastnotes-encrypted-backup.json';
      a.click();
      toast('Encrypted backup downloaded');
    } catch (e) { toast('Export failed'); }
  };

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if ($('palette').classList.contains('open')) $('palette').classList.remove('open');
      else if (currentId) closeEditor();
    }
    if ((e.ctrlKey || e.metaKey) && e.key === 'e' && currentId) {
      e.preventDefault();
      $('ed-mode').click();
    }
    if (e.key === '/' && !currentId && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
      e.preventDefault();
      $('q').focus();
    }
  });
  document.addEventListener('click', (e) => {
    if (!e.target.closest('#palette') && !e.target.closest('#ed-color')) {
      $('palette').classList.remove('open');
    }
  });
}

boot();
