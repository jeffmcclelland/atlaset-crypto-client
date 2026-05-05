import _sodium from 'libsodium-wrappers-sumo'

export interface SharingKeypair {
  publicKeyBase64: string
  privateKey: Uint8Array
  publicKey: Uint8Array
}

export async function generateSharingKeypair(): Promise<SharingKeypair> {
  await _sodium.ready
  const sodium = _sodium

  const { publicKey, privateKey } = sodium.crypto_box_keypair()

  return {
    publicKey,
    privateKey,
    publicKeyBase64: sodium.to_base64(publicKey),
  }
}

export async function wrapOEKForRecipient(
  oek: Uint8Array,
  recipientPublicKeyBase64: string,
): Promise<string> {
  await _sodium.ready
  const sodium = _sodium

  const recipientPublicKey = sodium.from_base64(recipientPublicKeyBase64)
  const ciphertext = sodium.crypto_box_seal(oek, recipientPublicKey)
  return sodium.to_base64(ciphertext)
}

export async function unwrapOEKForRecipient(
  encryptedOEKForRecipientBase64: string,
  recipientPublicKeyBase64: string,
  recipientPrivateKey: Uint8Array,
): Promise<Uint8Array> {
  await _sodium.ready
  const sodium = _sodium

  const ciphertext = sodium.from_base64(encryptedOEKForRecipientBase64)
  const recipientPublicKey = sodium.from_base64(recipientPublicKeyBase64)

  const oek = sodium.crypto_box_seal_open(ciphertext, recipientPublicKey, recipientPrivateKey)
  if (!oek) throw new Error('Failed to unwrap OEK for recipient')

  return oek
}
