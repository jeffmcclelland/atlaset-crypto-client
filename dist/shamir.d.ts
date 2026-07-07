export interface RecoveryShare {
    id: string;
    share: string;
}
export interface ReconstructMEKOptions {
    /**
     * Required for legacy raw-hex shares that do not carry threshold metadata.
     */
    threshold?: number;
    /**
     * Required for legacy raw-hex shares unless allowUnverifiedLegacyShares is true.
     */
    verificationTag?: string;
    /**
     * Compatibility escape hatch for pre-v1 raw-hex shares. New callers should not use this.
     */
    allowUnverifiedLegacyShares?: boolean;
}
/**
 * Split MEK into Shamir shares.
 * totalShares: total number of shares to generate.
 * threshold: minimum number of shares required to reconstruct the MEK.
 */
export declare function createRecoveryShares(mek: Uint8Array, totalShares: number, threshold: number): Promise<RecoveryShare[]>;
/**
 * Reconstruct MEK from a set of Shamir shares.
 * Versioned shares include threshold and verification metadata.
 */
export declare function reconstructMEK(shares: RecoveryShare[], options?: ReconstructMEKOptions): Promise<Uint8Array>;
//# sourceMappingURL=shamir.d.ts.map