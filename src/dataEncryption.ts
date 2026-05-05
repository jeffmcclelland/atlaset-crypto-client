import _sodium from 'libsodium-wrappers-sumo'

export interface EncryptedEnvelope {
  ciphertext: string // Base64
  nonce: string // Base64 (24 bytes)
  algorithm: 'xsalsa20-poly1305'
}

export async function encryptData(
  plaintext: unknown,
  oek: Uint8Array,
): Promise<EncryptedEnvelope> {
  await _sodium.ready
  const sodium = _sodium

  const plaintextBytes = sodium.from_string(JSON.stringify(plaintext))
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
  const ciphertext = sodium.crypto_secretbox_easy(plaintextBytes, nonce, oek)

  return {
    ciphertext: sodium.to_base64(ciphertext),
    nonce: sodium.to_base64(nonce),
    algorithm: 'xsalsa20-poly1305',
  }
}

export async function decryptData(
  envelope: EncryptedEnvelope,
  oek: Uint8Array,
): Promise<unknown> {
  await _sodium.ready
  const sodium = _sodium

  const ciphertext = sodium.from_base64(envelope.ciphertext)
  const nonce = sodium.from_base64(envelope.nonce)

  const plaintextBytes = sodium.crypto_secretbox_open_easy(ciphertext, nonce, oek)
  if (!plaintextBytes) {
    throw new Error('Decryption failed: invalid ciphertext or key')
  }

  return JSON.parse(sodium.to_string(plaintextBytes))
}
