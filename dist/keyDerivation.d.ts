/**
 * Derives MEK from user password using Argon2id.
 * Salt must be a unique, randomly generated value stored with the user's profile.
 */
export declare function deriveMEKFromPassword(password: string, salt: Uint8Array): Promise<Uint8Array>;
//# sourceMappingURL=keyDerivation.d.ts.map