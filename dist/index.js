import o from "libsodium-wrappers-sumo";
import { split as i, combine as y } from "shamir-secret-sharing";
async function E(r, t) {
  await o.ready;
  const e = o;
  return e.crypto_pwhash(
    32,
    // 256 bits
    e.from_string(r),
    t,
    e.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    e.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    e.crypto_pwhash_ALG_DEFAULT
  );
}
class p {
  mek = null;
  oekCache = /* @__PURE__ */ new Map();
  setMEK(t) {
    this.mek = t;
  }
  getMEK() {
    return this.mek;
  }
  async generateOEK() {
    return await o.ready, o.crypto_secretbox_keygen();
  }
  async encryptBytesWithMEK(t) {
    if (!this.mek) throw new Error("MEK not set");
    await o.ready;
    const e = o, n = e.randombytes_buf(e.crypto_secretbox_NONCEBYTES), s = e.crypto_secretbox_easy(t, n, this.mek), c = new Uint8Array([...n, ...s]);
    return e.to_base64(c);
  }
  async decryptBytesWithMEK(t) {
    if (!this.mek) throw new Error("MEK not set");
    await o.ready;
    const e = o, n = e.from_base64(t), s = n.slice(0, e.crypto_secretbox_NONCEBYTES), c = n.slice(e.crypto_secretbox_NONCEBYTES), a = e.crypto_secretbox_open_easy(c, s, this.mek);
    if (!a) throw new Error("MEK decryption failed");
    return a;
  }
  async encryptOEKWithMEK(t) {
    return this.encryptBytesWithMEK(t);
  }
  async decryptOEKWithMEK(t) {
    return this.decryptBytesWithMEK(t);
  }
  cacheOEK(t, e) {
    this.oekCache.set(t, e);
  }
  getCachedOEK(t) {
    return this.oekCache.get(t) ?? null;
  }
  clearAll() {
    this.mek = null, this.oekCache.clear();
  }
  clearOEK(t) {
    this.oekCache.delete(t);
  }
}
const d = new p();
async function w(r, t) {
  await o.ready;
  const e = o, n = e.from_string(JSON.stringify(r)), s = e.randombytes_buf(e.crypto_secretbox_NONCEBYTES), c = e.crypto_secretbox_easy(n, s, t);
  return {
    ciphertext: e.to_base64(c),
    nonce: e.to_base64(s),
    algorithm: "xsalsa20-poly1305"
  };
}
async function b(r, t) {
  await o.ready;
  const e = o, n = e.from_base64(r.ciphertext), s = e.from_base64(r.nonce), c = e.crypto_secretbox_open_easy(n, s, t);
  if (!c)
    throw new Error("Decryption failed: invalid ciphertext or key");
  return JSON.parse(e.to_string(c));
}
function h(r) {
  return Array.from(r).map((t) => t.toString(16).padStart(2, "0")).join("");
}
function u(r) {
  if (r.length % 2 !== 0)
    throw new Error("Invalid hex string length");
  const t = new Uint8Array(r.length / 2);
  for (let e = 0; e < r.length; e += 2)
    t[e / 2] = parseInt(r.slice(e, e + 2), 16);
  return t;
}
async function l(r, t, e) {
  if (t < 1)
    throw new Error("totalShares must be >= 1");
  if (e < 1 || e > t)
    throw new Error("threshold must be between 1 and totalShares");
  return (await i(r, t, e)).map((s) => ({
    id: crypto.randomUUID(),
    share: h(s)
  }));
}
async function f(r) {
  if (r.length === 0)
    throw new Error("At least one share is required to reconstruct MEK");
  const t = r.map((n) => u(n.share)), e = await y(t);
  return new Uint8Array(e);
}
async function K() {
  await o.ready;
  const r = o, { publicKey: t, privateKey: e } = r.crypto_box_keypair();
  return {
    publicKey: t,
    privateKey: e,
    publicKeyBase64: r.to_base64(t)
  };
}
async function x(r, t) {
  await o.ready;
  const e = o, n = e.from_base64(t), s = e.crypto_box_seal(r, n);
  return e.to_base64(s);
}
async function g(r, t, e) {
  await o.ready;
  const n = o, s = n.from_base64(r), c = n.from_base64(t), a = n.crypto_box_seal_open(s, c, e);
  if (!a) throw new Error("Failed to unwrap OEK for recipient");
  return a;
}
export {
  p as OEKManager,
  l as createRecoveryShares,
  b as decryptData,
  E as deriveMEKFromPassword,
  w as encryptData,
  K as generateSharingKeypair,
  d as oekManager,
  f as reconstructMEK,
  g as unwrapOEKForRecipient,
  x as wrapOEKForRecipient
};
//# sourceMappingURL=index.js.map
