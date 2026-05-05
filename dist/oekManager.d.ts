export declare class OEKManager {
    private mek;
    private oekCache;
    setMEK(mek: Uint8Array): void;
    getMEK(): Uint8Array | null;
    generateOEK(): Promise<Uint8Array>;
    encryptBytesWithMEK(plaintext: Uint8Array): Promise<string>;
    decryptBytesWithMEK(encrypted: string): Promise<Uint8Array>;
    encryptOEKWithMEK(oek: Uint8Array): Promise<string>;
    decryptOEKWithMEK(encryptedOEK: string): Promise<Uint8Array>;
    cacheOEK(objectId: string, oek: Uint8Array): void;
    getCachedOEK(objectId: string): Uint8Array | null;
    clearAll(): void;
    clearOEK(objectId: string): void;
}
export declare const oekManager: OEKManager;
//# sourceMappingURL=oekManager.d.ts.map