# Changelog

## 0.1.0

Initial release.

### Added

- `vault add <name> [--force] [--stdin] [--file <path>]` — store a secret,
  creating the vault and setting its passphrase on first use.
- `vault get <name> [--file <path>]` — decrypt and print a stored secret.
- `vault list [--file <path>]` — decrypt the vault and print the stored
  entry names.
- A single encrypted vault file per machine, defaulting to
  `~/.vault/vault.json` and overridable with `VAULT_FILE`, written atomically
  at mode `0600` inside a `0700` directory.
- Passphrase-based encryption: scrypt (`n=131072, r=8, p=1`) key derivation
  with AES-256-GCM, a fresh salt and nonce on every save. The on-disk
  envelope format is versioned (`version: 1`) so a future release can tell a
  vault written by this version apart from one written by an older or newer
  build.

### Compatibility

The envelope format version is `1` and is not changed by this release. A
vault created by 0.1.0 will continue to load under any later 0.x release that
also reads format version 1, which is what makes `npm install -g
ganjeh@<previous-version>` a safe rollback: the previous binary reads the
same on-disk format, so no vault migration is needed in either direction.
