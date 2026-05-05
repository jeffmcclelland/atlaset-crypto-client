declare module 'libsodium-wrappers-sumo' {
  const ready: Promise<void>
  
  // Encoding
  function from_string(str: string): Uint8Array
  function to_string(data: Uint8Array): string
  function to_base64(data: Uint8Array): string
  function from_base64(str: string): Uint8Array
  
  // Random
  function randombytes_buf(length: number): Uint8Array
  
  // Password hashing (Argon2)
  function crypto_pwhash(
    keyLength: number,
    password: Uint8Array,
    salt: Uint8Array,
    opsLimit: number,
    memLimit: number,
    algorithm: number
  ): Uint8Array
  const crypto_pwhash_OPSLIMIT_INTERACTIVE: number
  const crypto_pwhash_MEMLIMIT_INTERACTIVE: number
  const crypto_pwhash_ALG_DEFAULT: number
  
  // Secret box (symmetric encryption)
  function crypto_secretbox_keygen(): Uint8Array
  function crypto_secretbox_easy(message: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array
  function crypto_secretbox_open_easy(ciphertext: Uint8Array, nonce: Uint8Array, key: Uint8Array): Uint8Array
  const crypto_secretbox_NONCEBYTES: number
  const crypto_secretbox_KEYBYTES: number
  
  // AEAD (authenticated encryption)
  function crypto_aead_xchacha20poly1305_ietf_encrypt(
    message: Uint8Array,
    additionalData: Uint8Array | null,
    secretNonce: null,
    publicNonce: Uint8Array,
    key: Uint8Array
  ): Uint8Array
  function crypto_aead_xchacha20poly1305_ietf_decrypt(
    secretNonce: null,
    ciphertext: Uint8Array,
    additionalData: Uint8Array | null,
    publicNonce: Uint8Array,
    key: Uint8Array
  ): Uint8Array
  const crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: number
  const crypto_aead_xchacha20poly1305_ietf_KEYBYTES: number

  // Public-key encryption (Curve25519 / crypto_box)
  function crypto_box_keypair(): { publicKey: Uint8Array; privateKey: Uint8Array }
  function crypto_box_seal(message: Uint8Array, publicKey: Uint8Array): Uint8Array
  function crypto_box_seal_open(
    ciphertext: Uint8Array,
    publicKey: Uint8Array,
    privateKey: Uint8Array
  ): Uint8Array

  const _default: {
    ready: Promise<void>
    from_string: typeof from_string
    to_string: typeof to_string
    to_base64: typeof to_base64
    from_base64: typeof from_base64
    randombytes_buf: typeof randombytes_buf
    crypto_pwhash: typeof crypto_pwhash
    crypto_pwhash_OPSLIMIT_INTERACTIVE: number
    crypto_pwhash_MEMLIMIT_INTERACTIVE: number
    crypto_pwhash_ALG_DEFAULT: number
    crypto_secretbox_keygen: typeof crypto_secretbox_keygen
    crypto_secretbox_easy: typeof crypto_secretbox_easy
    crypto_secretbox_open_easy: typeof crypto_secretbox_open_easy
    crypto_secretbox_NONCEBYTES: number
    crypto_secretbox_KEYBYTES: number
    crypto_aead_xchacha20poly1305_ietf_encrypt: typeof crypto_aead_xchacha20poly1305_ietf_encrypt
    crypto_aead_xchacha20poly1305_ietf_decrypt: typeof crypto_aead_xchacha20poly1305_ietf_decrypt
    crypto_aead_xchacha20poly1305_ietf_NPUBBYTES: number
    crypto_aead_xchacha20poly1305_ietf_KEYBYTES: number
    crypto_box_keypair: typeof crypto_box_keypair
    crypto_box_seal: typeof crypto_box_seal
    crypto_box_seal_open: typeof crypto_box_seal_open
  }
  export default _default
}
