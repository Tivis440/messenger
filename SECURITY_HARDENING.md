# Security Hardening Notes

## Implemented

- TLS is mandatory for the client/server transport.
- The client pins the server certificate SHA-256 fingerprint and blocks unexpected changes.
- The client rejects expired or not-yet-valid pinned certificates.
- Server-side password records use Argon2id for new passwords.
- Legacy PBKDF2 and SHA-256 password records are migrated after successful login.
- Login, registration, message, and prekey request rate limits are enforced in memory.
- Offline messages are capped per recipient and expire after 30 days.
- The server no longer broadcasts the complete registered-user list or online events.
- New registrations use random public IDs instead of human-readable usernames.
- Contact discovery is manual-ID based; the server is not used as a searchable people directory.
- Runtime logs avoid message bodies, passwords, prekey payloads, and raw usernames.
- Local Signal state is encrypted with AES-256-GCM; on macOS the state key is stored in Keychain.
- Peer identity fingerprints are exposed in the chat header as safety numbers.

## Release Checklist

- Replace the development self-signed TLS certificate before shipping.
- Keep at least two pinned certificate fingerprints during certificate rotation.
- Sign and notarize the macOS application bundle.
- Verify dynamic library paths with `otool -L`.
- Record exact build versions of Qt, OpenSSL, libsignal-protocol-c, and argon2.
- Run security tests for certificate mismatch, expired certificate, password brute-force, corrupted packets, offline TTL, and identity-key changes.

## Cross-Platform Secure State Key

The encrypted Signal state format is platform-neutral AES-256-GCM. Only the state-key backend is platform-specific:

- macOS: Keychain.
- Windows target: Credential Manager or DPAPI.
- Linux target: Secret Service/libsecret or KWallet.
- Fallback target: user passphrase with Argon2id key derivation.

## Contact Model

The server account identifier is a random public ID, for example `nlk_0123456789ABCDEF0123`.
Display names and `@handle` values are local-only client metadata. A contact should be added
through a manual public ID and an optional local `@handle` label.

The server does not receive or index the `@handle`; it is only a local address-book label.
