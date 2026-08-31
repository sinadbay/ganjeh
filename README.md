# ganjeh

A command-line password vault. `ganjeh` encrypts credentials into a single
file on your own machine, protected by a passphrase you choose. There is no
server, no daemon, no sync, and no cloud account — everything happens on the
disk in front of you.

## Install

```
npm i -g ganjeh
```

This installs a `vault` command.

## Commands

`vault` has three commands: `add`, `get` and `list`. None of them ever accept
a passphrase or a secret as a command-line argument — arguments are visible
to every other process on the machine (`ps`, `/proc/<pid>/cmdline`) and end up
in shell history, so both are always read from a prompt or from stdin.

### `vault add <name> [--force] [--stdin] [--file <path>]`

Store a secret under `<name>`. If the vault does not exist yet, `add` creates
it and asks you to set a new passphrase. `--force` overwrites an existing
entry of the same name; without it, adding a name that already exists fails.
`--stdin` reads the secret from stdin instead of prompting for it — use this
for scripting or for multi-line secrets such as a PEM key.

```
$ vault add npm-token --stdin
New passphrase: ********
<secret is read from stdin here>
added "npm-token"
```

Piped end to end (passphrase and secret both fed in), the same command looks
like this, with no prompt text at all — there is no terminal to prompt:

```
$ printf 'correct-horse-battery\nsuper-secret-value\n' | vault add npm-token --stdin
added "npm-token"
```

### `vault get <name> [--file <path>]`

Print the stored secret for `<name>` to stdout, after asking for the
passphrase.

```
$ vault get npm-token
Passphrase: ********
super-secret-value
```

### `vault list [--file <path>]`

Print every stored entry name, after asking for the passphrase (the vault has
to be decrypted to read the names — they are not stored in the clear).

```
$ vault list
Passphrase: ********
npm-token
```

If no vault file exists yet, `list` fails immediately without prompting:

```
$ vault list
vault: no vault found; run "vault add" first to create one
```

### Exit codes

A shell script can branch on these:

| code | meaning                                          |
|------|---------------------------------------------------|
| 0    | success                                            |
| 1    | the caller's input was not valid                   |
| 2    | the passphrase did not open the vault              |
| 3    | the vault file is unreadable or unsafe to write    |
| 4    | the requested entry does not exist                 |
| 5    | the entry exists and `--force` was not given       |
| 6    | there is no vault file at the resolved path        |
| 130  | the read was cancelled with Ctrl-C                 |

## Where the vault file lives

By default, the vault is a single file at `~/.vault/vault.json`. Set
`VAULT_FILE` to use a different path — a relative value is resolved against
the current directory, not against your home directory:

```
$ VAULT_FILE=/tmp/scratch-vault.json vault add test-entry --stdin
```

The vault's parent directory is created with mode `0700`, and the vault file
itself is written with mode `0600` — owner read/write only, no access for
anyone else who can log into the machine. Every save writes to a temporary
file in the same directory and renames it into place, so a crash mid-write
never leaves a partially-written or world-readable vault behind.

## Encryption

Every secret is stored inside one encrypted envelope per vault file. The key
is derived from your passphrase with **scrypt** (`n=131072, r=8, p=1`), using
a random 16-byte salt generated fresh on every save. The derived key encrypts
the vault's contents with **AES-256-GCM** (`cipher: "aes-256-gcm"` in the
envelope), using a random 12-byte nonce, so the same passphrase never
produces the same ciphertext twice. The envelope records its own format
version, cipher name and KDF parameters, so a future version of `ganjeh` can
recognize and safely refuse a vault written with weaker settings than it's
willing to accept.

## What this does not protect against

- **A compromised machine.** If malware or another user can already run code
  as you, they can read your passphrase as you type it, dump the decrypted
  secret from process memory while `vault get` is running, or simply wait for
  you to use the secret elsewhere. Encryption at rest does not help once the
  machine itself is untrusted.
- **Memory scraping.** Passphrases and secrets exist in plaintext in this
  process's memory for as long as it takes to derive the key and read or
  write the entry. This is inherent to a passphrase-based CLI tool with no
  external key management service, not a bug to be fixed here.
- **A forgotten passphrase.** There is no way to recover a forgotten
  passphrase. The passphrase is never stored, in any form — the vault only
  stores what scrypt needs to *re-derive* the same key from the *correct*
  passphrase. If you lose it, the vault and everything in it is gone; there
  is no backdoor, no key escrow and no support ticket that gets it back.
- **Losing the only copy.** There is deliberately no sync or backup. If the
  machine holding `~/.vault/vault.json` is lost, so is the vault.

## License

MIT — see [LICENSE](./LICENSE).
