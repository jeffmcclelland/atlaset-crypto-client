import _sodium from 'libsodium-wrappers-sumo'

const DATA_ENCRYPTION_ALGORITHM = 'xsalsa20-poly1305'

export interface EncryptedEnvelope {
  ciphertext: string // Base64
  nonce: string // Base64 (24 bytes)
  algorithm: typeof DATA_ENCRYPTION_ALGORITHM
}

function validateOEK(oek: Uint8Array, keyBytes: number): void {
  if (oek.length !== keyBytes) {
    throw new Error(`OEK must be ${keyBytes} bytes`)
  }
}

function validateEncryptedEnvelope(envelope: EncryptedEnvelope): void {
  const candidate = envelope as {
    ciphertext?: unknown
    nonce?: unknown
    algorithm?: unknown
  }

  if (!candidate || typeof candidate !== 'object') {
    throw new Error('Encrypted envelope must be an object')
  }
  if (candidate.algorithm !== DATA_ENCRYPTION_ALGORITHM) {
    throw new Error('Unsupported encrypted envelope algorithm')
  }
  if (typeof candidate.ciphertext !== 'string' || typeof candidate.nonce !== 'string') {
    throw new Error('Encrypted envelope is missing ciphertext or nonce')
  }
}

export async function encryptData(
  plaintext: unknown,
  oek: Uint8Array,
): Promise<EncryptedEnvelope> {
  await _sodium.ready
  const sodium = _sodium
  validateOEK(oek, sodium.crypto_secretbox_KEYBYTES)

  const plaintextBytes = sodium.from_string(JSON.stringify(plaintext))
  const nonce = sodium.randombytes_buf(sodium.crypto_secretbox_NONCEBYTES)
  const ciphertext = sodium.crypto_secretbox_easy(plaintextBytes, nonce, oek)

  return {
    ciphertext: sodium.to_base64(ciphertext),
    nonce: sodium.to_base64(nonce),
    algorithm: DATA_ENCRYPTION_ALGORITHM,
  }
}

export async function decryptData(
  envelope: EncryptedEnvelope,
  oek: Uint8Array,
): Promise<unknown> {
  await _sodium.ready
  const sodium = _sodium
  validateEncryptedEnvelope(envelope)
  validateOEK(oek, sodium.crypto_secretbox_KEYBYTES)

  let ciphertext: Uint8Array
  let nonce: Uint8Array
  try {
    ciphertext = sodium.from_base64(envelope.ciphertext)
    nonce = sodium.from_base64(envelope.nonce)
  } catch {
    throw new Error('Encrypted envelope contains invalid base64')
  }

  if (nonce.length !== sodium.crypto_secretbox_NONCEBYTES) {
    throw new Error('Encrypted envelope nonce has invalid length')
  }

  const plaintextBytes = sodium.crypto_secretbox_open_easy(ciphertext, nonce, oek)
  if (!plaintextBytes) {
    throw new Error('Decryption failed: invalid ciphertext or key')
  }

  return JSON.parse(sodium.to_string(plaintextBytes))
}
