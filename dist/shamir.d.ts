export interface RecoveryShare {
    id: string;
    share: string;
}
/**
 * Split MEK into Shamir shares.
 * totalShares: total number of shares to generate.
 * threshold: minimum number of shares required to reconstruct the MEK.
 */
export declare function createRecoveryShares(mek: Uint8Array, totalShares: number, threshold: number): Promise<RecoveryShare[]>;
/**
 * Reconstruct MEK from a set of Shamir shares.
 * Caller is responsible for ensuring at least `threshold` shares are provided.
 */
export declare function reconstructMEK(shares: RecoveryShare[]): Promise<Uint8Array>;
//# sourceMappingURL=shamir.d.ts.map