import _sodium from 'libsodium-wrappers-sumo'

function copyBytes(bytes: Uint8Array): Uint8Array {
  return new Uint8Array(bytes)
}

function zeroize(bytes: Uint8Array | null | undefined): void {
  bytes?.fill(0)
}

export class OEKManager {
  private mek: Uint8Array | null = null
  private oekCache: Map<string, Uint8Array> = new Map()

  setMEK(mek: Uint8Array): void {
    zeroize(this.mek)
    this.mek = copyBytes(mek)
  }

  getMEK(): Uint8Array | null {
    return this.mek ? copyBytes(this.mek) : null
  }

  async generateOEK(): Promise<Uint8Array> {
    await _sodium.ready
    const sodium = _sodium
    return sodium.crypto_secretbox_keygen()
  }

  async encryptBytesWithMEK(plaintext: Uint8Array): Promise<string> {
    if (!this.mek) throw new Error('MEK not set')

    await _sodium.ready
    const sodium = _sodium

    const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
    const encrypted = sodium.crypto_secretbox_easy(plaintext, nonce, this.mek)

    const combined = new Uint8Array([...nonce, ...encrypted])
    return sodium.to_base64(combined)
  }

  async decryptBytesWithMEK(encrypted: string): Promise<Uint8Array> {
    if (!this.mek) throw new Error('MEK not set')

    await _sodium.ready
    const sodium = _sodium

    const combined = sodium.from_base64(encrypted)
    const nonce = combined.slice(0, sodium.crypto_secretbox_NONCEBYTES)
    const ciphertext = combined.slice(sodium.crypto_secretbox_NONCEBYTES)

    const plaintext = sodium.crypto_secretbox_open_easy(ciphertext, nonce, this.mek)
    if (!plaintext) throw new Error('MEK decryption failed')

    return plaintext
  }

  async encryptOEKWithMEK(oek: Uint8Array): Promise<string> {
    return this.encryptBytesWithMEK(oek)
  }

  async decryptOEKWithMEK(encryptedOEK: string): Promise<Uint8Array> {
    return this.decryptBytesWithMEK(encryptedOEK)
  }

  cacheOEK(objectId: string, oek: Uint8Array): void {
    zeroize(this.oekCache.get(objectId))
    this.oekCache.set(objectId, copyBytes(oek))
  }

  getCachedOEK(objectId: string): Uint8Array | null {
    const oek = this.oekCache.get(objectId)
    return oek ? copyBytes(oek) : null
  }

  clearAll(): void {
    zeroize(this.mek)
    for (const oek of this.oekCache.values()) {
      zeroize(oek)
    }
    this.mek = null
    this.oekCache.clear()
  }

  clearOEK(objectId: string): void {
    zeroize(this.oekCache.get(objectId))
    this.oekCache.delete(objectId)
  }
}

export const oekManager = new OEKManager()
