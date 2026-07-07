import { describe, expect, it } from 'vitest'
import {
  OEKManager,
  createRecoveryShares,
  decryptData,
  deriveMEKFromPassword,
  encryptData,
  generateSharingKeypair,
  reconstructMEK,
  unwrapOEKForRecipient,
  wrapOEKForRecipient,
} from '../src/index'

const saltA = new Uint8Array([
  1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
])
const saltB = new Uint8Array([
  16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1,
])
const recoverySharePrefix = 'atlaset-sss-v1:'

function base64UrlEncode(value: string): string {
  const bytes = new TextEncoder().encode(value)
  let binary = ''
  for (const byte of bytes) {
    binary += String.fromCharCode(byte)
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

function base64UrlDecode(value: string): string {
  const base64 = value.replace(/-/g, '+').replace(/_/g, '/')
  const padded = base64 + '='.repeat((4 - (base64.length % 4)) % 4)
  const binary = atob(padded)
  const bytes = new Uint8Array(binary.length)
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i)
  }
  return new TextDecoder().decode(bytes)
}

function decodeRecoveryShareToken(
  token: string,
): { share: string; verification: { tag: string } } & Record<string, unknown> {
  const decoded = JSON.parse(base64UrlDecode(token.slice(recoverySharePrefix.length))) as unknown
  if (typeof decoded !== 'object' || decoded === null) {
    throw new Error('Invalid recovery share token')
  }
  const payload = decoded as {
    share?: unknown
    verification?: { tag?: unknown }
  } & Record<string, unknown>
  if (typeof payload.share !== 'string' || typeof payload.verification?.tag !== 'string') {
    throw new Error('Invalid recovery share token')
  }
  return payload as { share: string; verification: { tag: string } } & Record<string, unknown>
}

function encodeRecoveryShareToken(payload: Record<string, unknown>): string {
  return `${recoverySharePrefix}${base64UrlEncode(JSON.stringify(payload))}`
}

describe('deriveMEKFromPassword', () => {
  it('derives a deterministic 32-byte MEK from password and salt', async () => {
    const first = await deriveMEKFromPassword('correct horse battery staple', saltA)
    const second = await deriveMEKFromPassword('correct horse battery staple', saltA)

    expect(first).toHaveLength(32)
    expect(Array.from(second)).toEqual(Array.from(first))
  })

  it('produces a different MEK when the salt changes', async () => {
    const first = await deriveMEKFromPassword('correct horse battery staple', saltA)
    const second = await deriveMEKFromPassword('correct horse battery staple', saltB)

    expect(Array.from(second)).not.toEqual(Array.from(first))
  })
})

describe('data encryption', () => {
  it('round-trips JSON-compatible data with randomized nonces', async () => {
    const manager = new OEKManager()
    const oek = await manager.generateOEK()
    const plaintext = { id: 'asset-1', label: 'Emergency fund', balance: 25000 }

    const first = await encryptData(plaintext, oek)
    const second = await encryptData(plaintext, oek)

    expect(first.algorithm).toBe('xsalsa20-poly1305')
    expect(first.nonce).not.toBe(second.nonce)
    await expect(decryptData(first, oek)).resolves.toEqual(plaintext)
  })

  it('rejects decryption with the wrong OEK', async () => {
    const manager = new OEKManager()
    const correctOEK = await manager.generateOEK()
    const wrongOEK = await manager.generateOEK()
    const encrypted = await encryptData({ secret: true }, correctOEK)

    await expect(decryptData(encrypted, wrongOEK)).rejects.toThrow()
  })

  it('rejects unsupported envelope algorithms before decryption', async () => {
    const manager = new OEKManager()
    const oek = await manager.generateOEK()
    const encrypted = await encryptData({ secret: true }, oek)

    await expect(
      decryptData({ ...encrypted, algorithm: 'aes-256-gcm' as never }, oek),
    ).rejects.toThrow('Unsupported encrypted envelope algorithm')
  })

  it('rejects malformed envelope nonces', async () => {
    const manager = new OEKManager()
    const oek = await manager.generateOEK()
    const encrypted = await encryptData({ secret: true }, oek)

    await expect(decryptData({ ...encrypted, nonce: encrypted.ciphertext }, oek)).rejects.toThrow(
      'Encrypted envelope nonce has invalid length',
    )
  })
})

describe('OEKManager', () => {
  it('wraps and unwraps OEKs with the active MEK', async () => {
    const manager = new OEKManager()
    const mek = await deriveMEKFromPassword('password', saltA)
    const oek = await manager.generateOEK()

    manager.setMEK(mek)
    const encryptedOEK = await manager.encryptOEKWithMEK(oek)
    const decryptedOEK = await manager.decryptOEKWithMEK(encryptedOEK)

    expect(oek).toHaveLength(32)
    expect(Array.from(decryptedOEK)).toEqual(Array.from(oek))
  })

  it('clears MEK and cached OEKs', async () => {
    const manager = new OEKManager()
    const mek = await deriveMEKFromPassword('password', saltA)
    const oek = await manager.generateOEK()

    manager.setMEK(mek)
    manager.cacheOEK('object-1', oek)
    manager.clearAll()

    expect(manager.getMEK()).toBeNull()
    expect(manager.getCachedOEK('object-1')).toBeNull()
  })

  it('keeps manager-owned key copies isolated from caller mutation', async () => {
    const manager = new OEKManager()
    const mek = await deriveMEKFromPassword('password', saltA)
    const oek = await manager.generateOEK()
    const expectedOEK = Array.from(oek)

    manager.setMEK(mek)
    const encryptedOEK = await manager.encryptOEKWithMEK(oek)
    mek.fill(0)

    await expect(manager.decryptOEKWithMEK(encryptedOEK)).resolves.toEqual(oek)

    manager.cacheOEK('object-1', oek)
    oek.fill(0)
    expect(Array.from(manager.getCachedOEK('object-1') ?? [])).toEqual(expectedOEK)

    const cached = manager.getCachedOEK('object-1')
    cached?.fill(0)
    expect(Array.from(manager.getCachedOEK('object-1') ?? [])).toEqual(expectedOEK)
  })
})

describe('sharing crypto', () => {
  it('wraps an OEK for a recipient keypair', async () => {
    const manager = new OEKManager()
    const oek = await manager.generateOEK()
    const recipient = await generateSharingKeypair()

    const wrapped = await wrapOEKForRecipient(oek, recipient.publicKeyBase64)
    const unwrapped = await unwrapOEKForRecipient(
      wrapped,
      recipient.publicKeyBase64,
      recipient.privateKey,
    )

    expect(Array.from(unwrapped)).toEqual(Array.from(oek))
  })

  it('rejects unwrap with a different recipient keypair', async () => {
    const manager = new OEKManager()
    const oek = await manager.generateOEK()
    const recipient = await generateSharingKeypair()
    const otherRecipient = await generateSharingKeypair()

    const wrapped = await wrapOEKForRecipient(oek, recipient.publicKeyBase64)

    await expect(
      unwrapOEKForRecipient(wrapped, otherRecipient.publicKeyBase64, otherRecipient.privateKey),
    ).rejects.toThrow()
  })
})

describe('Shamir recovery', () => {
  it('reconstructs the MEK at threshold', async () => {
    const mek = await deriveMEKFromPassword('password', saltA)
    const shares = await createRecoveryShares(mek, 3, 2)
    const reconstructed = await reconstructMEK(shares.slice(0, 2))

    expect(shares).toHaveLength(3)
    expect(shares[0].share.startsWith(recoverySharePrefix)).toBe(true)
    expect(Array.from(reconstructed)).toEqual(Array.from(mek))
  })

  it('rejects reconstruction below the embedded threshold', async () => {
    const mek = await deriveMEKFromPassword('password', saltA)
    const shares = await createRecoveryShares(mek, 3, 3)

    await expect(reconstructMEK(shares.slice(0, 2))).rejects.toThrow(
      'Not enough recovery shares to reconstruct MEK',
    )
  })

  it('rejects tampered shares with valid token metadata', async () => {
    const mek = await deriveMEKFromPassword('password', saltA)
    const shares = await createRecoveryShares(mek, 3, 2)
    const tamperedShares = shares.slice(0, 2)
    const payload = decodeRecoveryShareToken(tamperedShares[0].share)
    const replacement = payload.share.endsWith('0') ? '1' : '0'
    payload.share = `${payload.share.slice(0, -1)}${replacement}`
    tamperedShares[0] = {
      ...tamperedShares[0],
      share: encodeRecoveryShareToken(payload),
    }

    await expect(reconstructMEK(tamperedShares)).rejects.toThrow(
      'MEK reconstruction failed verification',
    )
  })

  it('rejects legacy raw-hex shares by default', async () => {
    const mek = await deriveMEKFromPassword('password', saltA)
    const shares = await createRecoveryShares(mek, 3, 2)
    const legacyShares = shares.slice(0, 2).map((share) => ({
      ...share,
      share: decodeRecoveryShareToken(share.share).share,
    }))

    await expect(reconstructMEK(legacyShares)).rejects.toThrow(
      'Legacy recovery shares require verification metadata',
    )
  })

  it('can verify legacy raw-hex shares when metadata is supplied separately', async () => {
    const mek = await deriveMEKFromPassword('password', saltA)
    const shares = await createRecoveryShares(mek, 3, 2)
    const verificationTag = decodeRecoveryShareToken(shares[0].share).verification.tag
    const legacyShares = shares.slice(0, 2).map((share) => ({
      ...share,
      share: decodeRecoveryShareToken(share.share).share,
    }))

    const reconstructed = await reconstructMEK(legacyShares, {
      threshold: 2,
      verificationTag,
    })

    expect(Array.from(reconstructed)).toEqual(Array.from(mek))
  })
})
