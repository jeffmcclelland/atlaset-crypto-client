import { split, combine } from 'shamir-secret-sharing'

export interface RecoveryShare {
  id: string
  share: string // Hex-encoded share
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('')
}

function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Invalid hex string length')
  }
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return bytes
}

/**
 * Split MEK into Shamir shares.
 * totalShares: total number of shares to generate.
 * threshold: minimum number of shares required to reconstruct the MEK.
 */
export async function createRecoveryShares(
  mek: Uint8Array,
  totalShares: number,
  threshold: number,
): Promise<RecoveryShare[]> {
  if (totalShares < 1) {
    throw new Error('totalShares must be >= 1')
  }
  if (threshold < 1 || threshold > totalShares) {
    throw new Error('threshold must be between 1 and totalShares')
  }

  const shares = await split(mek, totalShares, threshold)

  return shares.map((share) => ({
    id: crypto.randomUUID(),
    share: bytesToHex(share as Uint8Array),
  }))
}

/**
 * Reconstruct MEK from a set of Shamir shares.
 * Caller is responsible for ensuring at least `threshold` shares are provided.
 */
export async function reconstructMEK(shares: RecoveryShare[]): Promise<Uint8Array> {
  if (shares.length === 0) {
    throw new Error('At least one share is required to reconstruct MEK')
  }

  const decodedShares = shares.map((s) => hexToBytes(s.share))
  const mek = await combine(decodedShares)
  return new Uint8Array(mek as Uint8Array)
}
