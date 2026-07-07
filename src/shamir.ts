import { split, combine } from 'shamir-secret-sharing'

const RECOVERY_SHARE_PREFIX = 'atlaset-sss-v1:'
const RECOVERY_SHARE_FORMAT = 'atlaset-sss-v1'
const RECOVERY_VERIFICATION_ALGORITHM = 'hmac-sha256'
const RECOVERY_VERIFICATION_MESSAGE = 'atlaset-crypto-client:mek-recovery:v1'
const MEK_LENGTH_BYTES = 32
const MIN_SHARES = 2
const MAX_SHARES = 255

export interface RecoveryShare {
  id: string
  share: string // Versioned recovery share token
}

export interface ReconstructMEKOptions {
  /**
   * Required for legacy raw-hex shares that do not carry threshold metadata.
   */
  threshold?: number
  /**
   * Required for legacy raw-hex shares unless allowUnverifiedLegacyShares is true.
   */
  verificationTag?: string
  /**
   * Compatibility escape hatch for pre-v1 raw-hex shares. New callers should not use this.
   */
  allowUnverifiedLegacyShares?: boolean
}

interface VersionedRecoverySharePayload {
  format: typeof RECOVERY_SHARE_FORMAT
  share: string
  threshold: number
  totalShares: number
  verification: {
    algorithm: typeof RECOVERY_VERIFICATION_ALGORITHM
    tag: string
  }
}

interface ParsedRecoveryShare {
  shareBytes: Uint8Array
  threshold: number | null
  totalShares: number | null
  verificationTag: string | null
  legacy: boolean
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
  if (!/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error('Invalid hex string')
  }
  const bytes = new Uint8Array(hex.length / 2)
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16)
  }
  return bytes
}

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

function validateShareCount(value: number, label: string): void {
  if (!Number.isInteger(value) || value < MIN_SHARES || value > MAX_SHARES) {
    throw new Error(`${label} must be an integer between ${MIN_SHARES} and ${MAX_SHARES}`)
  }
}

function validateMEK(mek: Uint8Array): void {
  if (mek.length !== MEK_LENGTH_BYTES) {
    throw new Error(`MEK must be ${MEK_LENGTH_BYTES} bytes`)
  }
}

function validateVerificationTag(tag: string): string {
  if (!/^[0-9a-fA-F]{64}$/.test(tag)) {
    throw new Error('Invalid MEK verification tag')
  }
  return tag.toLowerCase()
}

function timingSafeEqualHex(left: string, right: string): boolean {
  const normalizedLeft = left.toLowerCase()
  const normalizedRight = right.toLowerCase()
  let diff = normalizedLeft.length ^ normalizedRight.length
  const maxLength = Math.max(normalizedLeft.length, normalizedRight.length)

  for (let i = 0; i < maxLength; i += 1) {
    diff |= (normalizedLeft.charCodeAt(i) || 0) ^ (normalizedRight.charCodeAt(i) || 0)
  }

  return diff === 0
}

async function createMEKVerificationTag(mek: Uint8Array): Promise<string> {
  const key = await crypto.subtle.importKey(
    'raw',
    new Uint8Array(mek),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  )
  const signature = await crypto.subtle.sign(
    'HMAC',
    key,
    new TextEncoder().encode(RECOVERY_VERIFICATION_MESSAGE),
  )

  return bytesToHex(new Uint8Array(signature))
}

function encodeRecoveryShareToken(payload: VersionedRecoverySharePayload): string {
  return `${RECOVERY_SHARE_PREFIX}${base64UrlEncode(JSON.stringify(payload))}`
}

function parseRecoveryShareToken(token: string): VersionedRecoverySharePayload {
  if (!token.startsWith(RECOVERY_SHARE_PREFIX)) {
    throw new Error('Unsupported recovery share format')
  }

  const decoded = JSON.parse(base64UrlDecode(token.slice(RECOVERY_SHARE_PREFIX.length))) as Partial<
    VersionedRecoverySharePayload
  >

  if (decoded.format !== RECOVERY_SHARE_FORMAT) {
    throw new Error('Unsupported recovery share format')
  }
  if (typeof decoded.share !== 'string') {
    throw new Error('Recovery share payload is missing share data')
  }
  if (typeof decoded.threshold !== 'number') {
    throw new Error('Recovery share payload is missing threshold')
  }
  if (typeof decoded.totalShares !== 'number') {
    throw new Error('Recovery share payload is missing totalShares')
  }
  if (
    !decoded.verification ||
    decoded.verification.algorithm !== RECOVERY_VERIFICATION_ALGORITHM ||
    typeof decoded.verification.tag !== 'string'
  ) {
    throw new Error('Recovery share payload is missing MEK verification metadata')
  }

  validateShareCount(decoded.threshold, 'threshold')
  validateShareCount(decoded.totalShares, 'totalShares')
  if (decoded.threshold > decoded.totalShares) {
    throw new Error('threshold must be between 2 and totalShares')
  }

  return {
    format: RECOVERY_SHARE_FORMAT,
    share: decoded.share,
    threshold: decoded.threshold,
    totalShares: decoded.totalShares,
    verification: {
      algorithm: RECOVERY_VERIFICATION_ALGORITHM,
      tag: validateVerificationTag(decoded.verification.tag),
    },
  }
}

function parseRecoveryShare(recoveryShare: RecoveryShare): ParsedRecoveryShare {
  if (recoveryShare.share.startsWith(RECOVERY_SHARE_PREFIX)) {
    const payload = parseRecoveryShareToken(recoveryShare.share)
    const shareBytes = hexToBytes(payload.share)
    if (shareBytes.length <= 1) {
      throw new Error('Recovery share payload is malformed')
    }
    return {
      shareBytes,
      threshold: payload.threshold,
      totalShares: payload.totalShares,
      verificationTag: payload.verification.tag,
      legacy: false,
    }
  }

  return {
    shareBytes: hexToBytes(recoveryShare.share),
    threshold: null,
    totalShares: null,
    verificationTag: null,
    legacy: true,
  }
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
  validateMEK(mek)
  validateShareCount(totalShares, 'totalShares')
  validateShareCount(threshold, 'threshold')
  if (threshold > totalShares) {
    throw new Error('threshold must be between 2 and totalShares')
  }

  const shares = await split(mek, totalShares, threshold)
  const verificationTag = await createMEKVerificationTag(mek)

  return shares.map((share) => ({
    id: crypto.randomUUID(),
    share: encodeRecoveryShareToken({
      format: RECOVERY_SHARE_FORMAT,
      share: bytesToHex(share as Uint8Array),
      threshold,
      totalShares,
      verification: {
        algorithm: RECOVERY_VERIFICATION_ALGORITHM,
        tag: verificationTag,
      },
    }),
  }))
}

/**
 * Reconstruct MEK from a set of Shamir shares.
 * Versioned shares include threshold and verification metadata.
 */
export async function reconstructMEK(
  shares: RecoveryShare[],
  options: ReconstructMEKOptions = {},
): Promise<Uint8Array> {
  if (shares.length === 0) {
    throw new Error('At least one share is required to reconstruct MEK')
  }

  const parsedShares = shares.map(parseRecoveryShare)
  const hasLegacyShares = parsedShares.some((share) => share.legacy)
  const hasVersionedShares = parsedShares.some((share) => !share.legacy)

  if (hasLegacyShares && hasVersionedShares) {
    throw new Error('Cannot mix legacy and versioned recovery shares')
  }

  let threshold = options.threshold ?? null
  let verificationTag = options.verificationTag ? validateVerificationTag(options.verificationTag) : null

  if (hasVersionedShares) {
    const first = parsedShares[0]
    threshold = first.threshold
    verificationTag = first.verificationTag

    for (const share of parsedShares) {
      if (
        share.threshold !== threshold ||
        share.totalShares !== first.totalShares ||
        share.verificationTag !== verificationTag
      ) {
        throw new Error('Recovery shares do not belong to the same recovery set')
      }
    }
  } else if (!options.allowUnverifiedLegacyShares && !verificationTag) {
    throw new Error('Legacy recovery shares require verification metadata')
  }

  if (threshold !== null) {
    validateShareCount(threshold, 'threshold')
    if (shares.length < threshold) {
      throw new Error('Not enough recovery shares to reconstruct MEK')
    }
  }

  const uniqueShareValues = new Set(parsedShares.map((share) => bytesToHex(share.shareBytes)))
  if (uniqueShareValues.size !== parsedShares.length) {
    throw new Error('Duplicate recovery shares are not allowed')
  }

  const decodedShares = parsedShares.map((share) => share.shareBytes)
  const mek = await combine(decodedShares)
  const reconstructed = new Uint8Array(mek as Uint8Array)
  validateMEK(reconstructed)

  if (verificationTag) {
    const reconstructedTag = await createMEKVerificationTag(reconstructed)
    if (!timingSafeEqualHex(reconstructedTag, verificationTag)) {
      reconstructed.fill(0)
      throw new Error('MEK reconstruction failed verification')
    }
  }

  return reconstructed
}
