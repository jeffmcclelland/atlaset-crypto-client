import _sodium from 'libsodium-wrappers-sumo'

/**
 * Derives MEK from user password using Argon2id.
 * Salt must be a unique, randomly generated value stored with the user's profile.
 */
export async function deriveMEKFromPassword(
  password: string,
  salt: Uint8Array,
): Promise<Uint8Array> {
  await _sodium.ready
  const sodium = _sodium

  // Argon2id with libsodium interactive parameters (see security TRD)
  const mek = sodium.crypto_pwhash(
    32, // 256 bits
    sodium.from_string(password),
    salt,
    sodium.crypto_pwhash_OPSLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_MEMLIMIT_INTERACTIVE,
    sodium.crypto_pwhash_ALG_DEFAULT,
  )

  return mek
}
