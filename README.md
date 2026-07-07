# atlaset-crypto-client

Auditable client-side cryptography helpers for Atlaset.

This package is the public implementation boundary for Atlaset's security-critical browser crypto:

- MEK derivation from user password and per-user random salt using libsodium Argon2id.
- OEK generation and wrapping/unwrapping with the MEK.
- Data encryption/decryption envelopes using libsodium secretbox.
- Sealed-box wrapping for sharing OEKs with recipients.
- Shamir Secret Sharing helpers for recovery flows.

Application code should import these helpers from `atlaset-crypto-client` rather than calling `libsodium-wrappers-sumo` or `shamir-secret-sharing` directly.

## Recovery Share Integrity

`createRecoveryShares` returns self-contained versioned share tokens. Each token
includes threshold metadata and an HMAC-SHA-256 verification tag for the MEK, so
`reconstructMEK` can reject insufficient or tampered share sets before returning
a key to callers.

Legacy raw-hex shares from pre-`0.2.0` releases are rejected by default because
they do not carry verification metadata. Callers that need a migration window
can pass `threshold` plus `verificationTag`, or explicitly set
`allowUnverifiedLegacyShares: true` for old data that cannot be verified.

## Development

```sh
npm install
npm test
npm run build
```

## Release Verification

For source auditability, reviewers can check out a tagged release, install dependencies, run the tests, and build the package:

```sh
git checkout v0.2.0
npm ci
npm test
npm run build
```

Atlaset's main app consumes tagged versions of this package. A later release step will also publish a dedicated SRI-checkable browser bundle for production integrity verification.
