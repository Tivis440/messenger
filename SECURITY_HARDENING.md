# Security Hardening Notes

## Implemented

- TLS is mandatory for the client/server transport.
- The client pins the server certificate SHA-256 fingerprint and blocks unexpected changes.
- The client rejects expired or not-yet-valid pinned certificates.
- Server-side password records use Argon2id for new passwords.
- Legacy PBKDF2 and SHA-256 password records are migrated after successful login.
- Login, registration, message, and prekey request rate limits are enforced in memory.
- Offline messages are capped per recipient and expire after 30 days.
- New registrations use human-readable usernames.
- Users and local dialogs are found through a unified username/dialog search.
- Runtime logs avoid message bodies, passwords, and prekey payloads; usernames should be hashed or minimized in production logs where practical.
- Local Signal state is encrypted with AES-256-GCM; on macOS the state key is stored in Keychain.

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

## Account Model

The server account identifier is a human-readable username, for example `alice` or `user.name`.
A conversation is started through that username.

The security focus is encrypted message content, mandatory TLS transport, local key protection,
password hardening, and identity-key verification.
