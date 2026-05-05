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
    expect(Array.from(reconstructed)).toEqual(Array.from(mek))
  })
})
