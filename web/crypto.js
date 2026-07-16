// FastNotes client-side crypto. Master password never leaves this file's closure.
// Key derivation: PBKDF2-SHA256 (600k iters) -> 256-bit master key
//   -> HKDF "enc"  -> AES-256-GCM data key (encrypts notes & images)
//   -> HKDF "auth" -> API bearer token (server stores only its SHA-256 hash)
'use strict';

const FNCrypto = (() => {
  const te = new TextEncoder();
  const td = new TextDecoder();
  const DEFAULT_ITERS = 600000;

  let encKey = null;   // CryptoKey (AES-GCM), non-extractable
  let authToken = null; // base64 string

  const b64 = {
    enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))),
    dec: (str) => Uint8Array.from(atob(str), c => c.charCodeAt(0)),
  };

  async function deriveAll(password, saltB64, iters) {
    const salt = b64.dec(saltB64);
    const baseKey = await crypto.subtle.importKey('raw', te.encode(password), 'PBKDF2', false, ['deriveBits']);
    const masterBits = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iters }, baseKey, 256);
    const hkdfKey = await crypto.subtle.importKey('raw', masterBits, 'HKDF', false, ['deriveBits', 'deriveKey']);
    const enc = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: te.encode('fastnotes-enc-v1') },
      hkdfKey, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
    const authBits = await crypto.subtle.deriveBits(
      { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(32), info: te.encode('fastnotes-auth-v1') },
      hkdfKey, 256);
    return { enc, auth: b64.enc(authBits) };
  }

  return {
    DEFAULT_ITERS,
    newSalt: () => b64.enc(crypto.getRandomValues(new Uint8Array(16))),
    newId: () => b64.enc(crypto.getRandomValues(new Uint8Array(12))).replace(/[+/=]/g, c => ({'+':'-','/':'_','=':''}[c])),

    // Derive keys and hold them in memory. Returns the auth token for API calls.
    async unlock(password, saltB64, iters) {
      const k = await deriveAll(password, saltB64, iters || DEFAULT_ITERS);
      encKey = k.enc;
      authToken = k.auth;
      return authToken;
    },

    lock() { encKey = null; authToken = null; },
    isUnlocked: () => !!encKey,
    token: () => authToken,

    // Encrypt a JS object -> base64(iv || ciphertext)
    async encryptJSON(obj) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, encKey, te.encode(JSON.stringify(obj)));
      const out = new Uint8Array(12 + ct.byteLength);
      out.set(iv); out.set(new Uint8Array(ct), 12);
      return b64.enc(out);
    },

    // base64(iv || ciphertext) -> JS object (throws on wrong key/tamper)
    async decryptJSON(blobB64) {
      const buf = b64.dec(blobB64);
      const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, encKey, buf.slice(12));
      return JSON.parse(td.decode(pt));
    },

    // Encrypt raw bytes (images): returns Uint8Array(iv || ct)
    async encryptBytes(arrayBuffer) {
      const iv = crypto.getRandomValues(new Uint8Array(12));
      const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, encKey, arrayBuffer);
      const out = new Uint8Array(12 + ct.byteLength);
      out.set(iv); out.set(new Uint8Array(ct), 12);
      return out;
    },

    async decryptBytes(bytes) {
      const u8 = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
      return crypto.subtle.decrypt({ name: 'AES-GCM', iv: u8.slice(0, 12) }, encKey, u8.slice(12));
    },

    b64,
  };
})();
