import _sodium from 'libsodium-wrappers-sumo'

export class OEKManager {
  private mek: Uint8Array | null = null
  private oekCache: Map<string, Uint8Array> = new Map()

  setMEK(mek: Uint8Array): void {
    this.mek = mek
  }

  getMEK(): Uint8Array | null {
    return this.mek
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
    this.oekCache.set(objectId, oek)
  }

  getCachedOEK(objectId: string): Uint8Array | null {
    return this.oekCache.get(objectId) ?? null
  }

  clearAll(): void {
    this.mek = null
    this.oekCache.clear()
  }

  clearOEK(objectId: string): void {
    this.oekCache.delete(objectId)
  }
}

export const oekManager = new OEKManager()
