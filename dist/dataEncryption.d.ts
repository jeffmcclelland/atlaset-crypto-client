export interface EncryptedEnvelope {
    ciphertext: string;
    nonce: string;
    algorithm: 'xsalsa20-poly1305';
}
export declare function encryptData(plaintext: unknown, oek: Uint8Array): Promise<EncryptedEnvelope>;
export declare function decryptData(envelope: EncryptedEnvelope, oek: Uint8Array): Promise<unknown>;
//# sourceMappingURL=dataEncryption.d.ts.map