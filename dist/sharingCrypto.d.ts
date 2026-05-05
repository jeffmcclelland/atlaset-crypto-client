export interface SharingKeypair {
    publicKeyBase64: string;
    privateKey: Uint8Array;
    publicKey: Uint8Array;
}
export declare function generateSharingKeypair(): Promise<SharingKeypair>;
export declare function wrapOEKForRecipient(oek: Uint8Array, recipientPublicKeyBase64: string): Promise<string>;
export declare function unwrapOEKForRecipient(encryptedOEKForRecipientBase64: string, recipientPublicKeyBase64: string, recipientPrivateKey: Uint8Array): Promise<Uint8Array>;
//# sourceMappingURL=sharingCrypto.d.ts.map