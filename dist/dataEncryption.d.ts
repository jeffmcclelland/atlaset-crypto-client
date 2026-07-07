declare const DATA_ENCRYPTION_ALGORITHM = "xsalsa20-poly1305";
export interface EncryptedEnvelope {
    ciphertext: string;
    nonce: string;
    algorithm: typeof DATA_ENCRYPTION_ALGORITHM;
}
export declare function encryptData(plaintext: unknown, oek: Uint8Array): Promise<EncryptedEnvelope>;
export declare function decryptData(envelope: EncryptedEnvelope, oek: Uint8Array): Promise<unknown>;
export {};
//# sourceMappingURL=dataEncryption.d.ts.map