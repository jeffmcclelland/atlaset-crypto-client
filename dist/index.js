import s from "libsodium-wrappers-sumo";
import { split as C, combine as R } from "shamir-secret-sharing";
async function D(r, e) {
  await s.ready;
  const t = s;
  return t.crypto_pwhash(
    32,
    // 256 bits
    t.from_string(r),
    e,
    t.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    t.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    t.crypto_pwhash_ALG_DEFAULT
  );
}
function f(r) {
  return new Uint8Array(r);
}
function h(r) {
  r?.fill(0);
}
class O {
  mek = null;
  oekCache = /* @__PURE__ */ new Map();
  setMEK(e) {
    h(this.mek), this.mek = f(e);
  }
  getMEK() {
    return this.mek ? f(this.mek) : null;
  }
  async generateOEK() {
    return await s.ready, s.crypto_secretbox_keygen();
  }
  async encryptBytesWithMEK(e) {
    if (!this.mek) throw new Error("MEK not set");
    await s.ready;
    const t = s, o = t.randombytes_buf(t.crypto_secretbox_NONCEBYTES), n = t.crypto_secretbox_easy(e, o, this.mek), a = new Uint8Array([...o, ...n]);
    return t.to_base64(a);
  }
  async decryptBytesWithMEK(e) {
    if (!this.mek) throw new Error("MEK not set");
    await s.ready;
    const t = s, o = t.from_base64(e), n = o.slice(0, t.crypto_secretbox_NONCEBYTES), a = o.slice(t.crypto_secretbox_NONCEBYTES), i = t.crypto_secretbox_open_easy(a, n, this.mek);
    if (!i) throw new Error("MEK decryption failed");
    return i;
  }
  async encryptOEKWithMEK(e) {
    return this.encryptBytesWithMEK(e);
  }
  async decryptOEKWithMEK(e) {
    return this.decryptBytesWithMEK(e);
  }
  cacheOEK(e, t) {
    h(this.oekCache.get(e)), this.oekCache.set(e, f(t));
  }
  getCachedOEK(e) {
    const t = this.oekCache.get(e);
    return t ? f(t) : null;
  }
  clearAll() {
    h(this.mek);
    for (const e of this.oekCache.values())
      h(e);
    this.mek = null, this.oekCache.clear();
  }
  clearOEK(e) {
    h(this.oekCache.get(e)), this.oekCache.delete(e);
  }
}
const W = new O(), v = "xsalsa20-poly1305";
function S(r, e) {
  if (r.length !== e)
    throw new Error(`OEK must be ${e} bytes`);
}
function k(r) {
  const e = r;
  if (!e || typeof e != "object")
    throw new Error("Encrypted envelope must be an object");
  if (e.algorithm !== v)
    throw new Error("Unsupported encrypted envelope algorithm");
  if (typeof e.ciphertext != "string" || typeof e.nonce != "string")
    throw new Error("Encrypted envelope is missing ciphertext or nonce");
}
async function P(r, e) {
  await s.ready;
  const t = s;
  S(e, t.crypto_secretbox_KEYBYTES);
  const o = t.from_string(JSON.stringify(r)), n = t.randombytes_buf(t.crypto_secretbox_NONCEBYTES), a = t.crypto_secretbox_easy(o, n, e);
  return {
    ciphertext: t.to_base64(a),
    nonce: t.to_base64(n),
    algorithm: v
  };
}
async function q(r, e) {
  await s.ready;
  const t = s;
  k(r), S(e, t.crypto_secretbox_KEYBYTES);
  let o, n;
  try {
    o = t.from_base64(r.ciphertext), n = t.from_base64(r.nonce);
  } catch {
    throw new Error("Encrypted envelope contains invalid base64");
  }
  if (n.length !== t.crypto_secretbox_NONCEBYTES)
    throw new Error("Encrypted envelope nonce has invalid length");
  const a = t.crypto_secretbox_open_easy(o, n, e);
  if (!a)
    throw new Error("Decryption failed: invalid ciphertext or key");
  return JSON.parse(t.to_string(a));
}
const d = "atlaset-sss-v1:", E = "atlaset-sss-v1", u = "hmac-sha256", N = "atlaset-crypto-client:mek-recovery:v1", g = 32, m = 2, _ = 255;
function w(r) {
  return Array.from(r).map((e) => e.toString(16).padStart(2, "0")).join("");
}
function b(r) {
  if (r.length % 2 !== 0)
    throw new Error("Invalid hex string length");
  if (!/^[0-9a-fA-F]*$/.test(r))
    throw new Error("Invalid hex string");
  const e = new Uint8Array(r.length / 2);
  for (let t = 0; t < r.length; t += 2)
    e[t / 2] = parseInt(r.slice(t, t + 2), 16);
  return e;
}
function I(r) {
  const e = new TextEncoder().encode(r);
  let t = "";
  for (const o of e)
    t += String.fromCharCode(o);
  return btoa(t).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function B(r) {
  const e = r.replace(/-/g, "+").replace(/_/g, "/"), t = e + "=".repeat((4 - e.length % 4) % 4), o = atob(t), n = new Uint8Array(o.length);
  for (let a = 0; a < o.length; a += 1)
    n[a] = o.charCodeAt(a);
  return new TextDecoder().decode(n);
}
function l(r, e) {
  if (!Number.isInteger(r) || r < m || r > _)
    throw new Error(`${e} must be an integer between ${m} and ${_}`);
}
function K(r) {
  if (r.length !== g)
    throw new Error(`MEK must be ${g} bytes`);
}
function T(r) {
  if (!/^[0-9a-fA-F]{64}$/.test(r))
    throw new Error("Invalid MEK verification tag");
  return r.toLowerCase();
}
function U(r, e) {
  const t = r.toLowerCase(), o = e.toLowerCase();
  let n = t.length ^ o.length;
  const a = Math.max(t.length, o.length);
  for (let i = 0; i < a; i += 1)
    n |= (t.charCodeAt(i) || 0) ^ (o.charCodeAt(i) || 0);
  return n === 0;
}
async function M(r) {
  const e = await crypto.subtle.importKey(
    "raw",
    new Uint8Array(r),
    { name: "HMAC", hash: "SHA-256" },
    !1,
    ["sign"]
  ), t = await crypto.subtle.sign(
    "HMAC",
    e,
    new TextEncoder().encode(N)
  );
  return w(new Uint8Array(t));
}
function L(r) {
  return `${d}${I(JSON.stringify(r))}`;
}
function Y(r) {
  if (!r.startsWith(d))
    throw new Error("Unsupported recovery share format");
  const e = JSON.parse(B(r.slice(d.length)));
  if (e.format !== E)
    throw new Error("Unsupported recovery share format");
  if (typeof e.share != "string")
    throw new Error("Recovery share payload is missing share data");
  if (typeof e.threshold != "number")
    throw new Error("Recovery share payload is missing threshold");
  if (typeof e.totalShares != "number")
    throw new Error("Recovery share payload is missing totalShares");
  if (!e.verification || e.verification.algorithm !== u || typeof e.verification.tag != "string")
    throw new Error("Recovery share payload is missing MEK verification metadata");
  if (l(e.threshold, "threshold"), l(e.totalShares, "totalShares"), e.threshold > e.totalShares)
    throw new Error("threshold must be between 2 and totalShares");
  return {
    format: E,
    share: e.share,
    threshold: e.threshold,
    totalShares: e.totalShares,
    verification: {
      algorithm: u,
      tag: T(e.verification.tag)
    }
  };
}
function V(r) {
  if (r.share.startsWith(d)) {
    const e = Y(r.share), t = b(e.share);
    if (t.length <= 1)
      throw new Error("Recovery share payload is malformed");
    return {
      shareBytes: t,
      threshold: e.threshold,
      totalShares: e.totalShares,
      verificationTag: e.verification.tag,
      legacy: !1
    };
  }
  return {
    shareBytes: b(r.share),
    threshold: null,
    totalShares: null,
    verificationTag: null,
    legacy: !0
  };
}
async function z(r, e, t) {
  if (K(r), l(e, "totalShares"), l(t, "threshold"), t > e)
    throw new Error("threshold must be between 2 and totalShares");
  const o = await C(r, e, t), n = await M(r);
  return o.map((a) => ({
    id: crypto.randomUUID(),
    share: L({
      format: E,
      share: w(a),
      threshold: t,
      totalShares: e,
      verification: {
        algorithm: u,
        tag: n
      }
    })
  }));
}
async function G(r, e = {}) {
  if (r.length === 0)
    throw new Error("At least one share is required to reconstruct MEK");
  const t = r.map(V), o = t.some((c) => c.legacy), n = t.some((c) => !c.legacy);
  if (o && n)
    throw new Error("Cannot mix legacy and versioned recovery shares");
  let a = e.threshold ?? null, i = e.verificationTag ? T(e.verificationTag) : null;
  if (n) {
    const c = t[0];
    a = c.threshold, i = c.verificationTag;
    for (const p of t)
      if (p.threshold !== a || p.totalShares !== c.totalShares || p.verificationTag !== i)
        throw new Error("Recovery shares do not belong to the same recovery set");
  } else if (!e.allowUnverifiedLegacyShares && !i)
    throw new Error("Legacy recovery shares require verification metadata");
  if (a !== null && (l(a, "threshold"), r.length < a))
    throw new Error("Not enough recovery shares to reconstruct MEK");
  if (new Set(t.map((c) => w(c.shareBytes))).size !== t.length)
    throw new Error("Duplicate recovery shares are not allowed");
  const x = t.map((c) => c.shareBytes), A = await R(x), y = new Uint8Array(A);
  if (K(y), i) {
    const c = await M(y);
    if (!U(c, i))
      throw y.fill(0), new Error("MEK reconstruction failed verification");
  }
  return y;
}
async function J() {
  await s.ready;
  const r = s, { publicKey: e, privateKey: t } = r.crypto_box_keypair();
  return {
    publicKey: e,
    privateKey: t,
    publicKeyBase64: r.to_base64(e)
  };
}
async function X(r, e) {
  await s.ready;
  const t = s, o = t.from_base64(e), n = t.crypto_box_seal(r, o);
  return t.to_base64(n);
}
async function j(r, e, t) {
  await s.ready;
  const o = s, n = o.from_base64(r), a = o.from_base64(e), i = o.crypto_box_seal_open(n, a, t);
  if (!i) throw new Error("Failed to unwrap OEK for recipient");
  return i;
}
export {
  O as OEKManager,
  z as createRecoveryShares,
  q as decryptData,
  D as deriveMEKFromPassword,
  P as encryptData,
  J as generateSharingKeypair,
  W as oekManager,
  G as reconstructMEK,
  j as unwrapOEKForRecipient,
  X as wrapOEKForRecipient
};
//# sourceMappingURL=index.js.map
