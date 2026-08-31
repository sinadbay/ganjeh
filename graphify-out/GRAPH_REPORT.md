# Graph Report - t7-release  (2026-08-31)

## Corpus Check
- 16 files · ~20,312 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 207 nodes · 329 edges · 11 communities (9 shown, 2 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 5 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `4d44d910`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- vault.ts
- crypto.ts
- store.ts
- compilerOptions
- package.json
- prompt.ts
- package.test.ts
- ganjeh
- 0.1.0
- paths.ts
- VaultStore

## God Nodes (most connected - your core abstractions)
1. `VaultError` - 22 edges
2. `compilerOptions` - 15 edges
3. `save()` - 11 edges
4. `open()` - 10 edges
5. `FsDeps` - 9 edges
6. `VaultCorruptError` - 9 edges
7. `validateKdfParams()` - 7 edges
8. `ganjeh` - 7 edges
9. `scripts` - 6 edges
10. `readHidden()` - 6 edges

## Surprising Connections (you probably didn't know these)
- `AbortedError` --inherits--> `VaultError`  [EXTRACTED]
  src/prompt.ts → src/types.ts
- `PassphraseMismatchError` --inherits--> `VaultError`  [EXTRACTED]
  src/prompt.ts → src/types.ts
- `WeakPassphraseError` --inherits--> `VaultError`  [EXTRACTED]
  src/prompt.ts → src/types.ts
- `InputTooLongError` --inherits--> `VaultError`  [EXTRACTED]
  src/prompt.ts → src/types.ts
- `decodeVault()` --calls--> `describeUntrusted()`  [EXTRACTED]
  src/vault.ts → src/types.ts

## Import Cycles
- None detected.

## Communities (11 total, 2 thin omitted)

### Community 0 - "vault.ts"
Cohesion: 0.14
Nodes (22): AddEntryOptions, describeUntrusted(), EntryExistsError, EntryNotFoundError, InvalidNameError, InvalidSecretError, NAME_PATTERN, VaultCorruptError (+14 more)

### Community 1 - "crypto.ts"
Cohesion: 0.13
Nodes (22): Cipher, CIPHER_ALGORITHM, decodeBase64(), deriveKey(), describeUntrusted(), EncryptedEnvelope, isPlainRecord(), KDF_PARAMS (+14 more)

### Community 2 - "store.ts"
Cohesion: 0.09
Nodes (14): createStore(), exists(), load(), save(), defaultDeps, EncryptedEnvelope, FileHandleLike, FsDeps (+6 more)

### Community 3 - "compilerOptions"
Cohesion: 0.10
Nodes (19): ES2023, node, src/**/*.ts, compilerOptions, allowImportingTsExtensions, exactOptionalPropertyTypes, forceConsistentCasingInFileNames, lib (+11 more)

### Community 4 - "package.json"
Cohesion: 0.08
Nodes (25): bin, vault, description, devDependencies, @types/node, typescript, engines, node (+17 more)

### Community 5 - "prompt.ts"
Cohesion: 0.11
Nodes (19): AbortedError, assertPassphraseStrength(), getReaderState(), InputTooLongError, MAX_HIDDEN_INPUT_LENGTH, nextChar(), PassphraseMismatchError, PromptDeps (+11 more)

### Community 6 - "package.test.ts"
Cohesion: 0.22
Nodes (7): ENVELOPE_VERSION, CHANGELOG_PATH, execFileAsync, PACKAGE_JSON_PATH, packDryRun(), README_PATH, REPO_ROOT

### Community 7 - "ganjeh"
Cohesion: 0.17
Nodes (11): Commands, Encryption, Exit codes, ganjeh, Install, License, `vault add <name> [--force] [--stdin] [--file <path>]`, `vault get <name> [--file <path>]` (+3 more)

### Community 8 - "0.1.0"
Cohesion: 0.40
Nodes (4): 0.1.0, Added, Changelog, Compatibility

## Knowledge Gaps
- **60 isolated node(s):** `name`, `version`, `description`, `license`, `type` (+55 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `VaultError` connect `vault.ts` to `crypto.ts`, `store.ts`, `prompt.ts`?**
  _High betweenness centrality (0.200) - this node is a cross-community bridge._
- **Why does `VaultCorruptError` connect `vault.ts` to `crypto.ts`, `store.ts`?**
  _High betweenness centrality (0.052) - this node is a cross-community bridge._
- **What connects `name`, `version`, `description` to the rest of the system?**
  _60 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `vault.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.14112903225806453 - nodes in this community are weakly interconnected._
- **Should `crypto.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.12643678160919541 - nodes in this community are weakly interconnected._
- **Should `store.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.09269162210338681 - nodes in this community are weakly interconnected._
- **Should `compilerOptions` be split into smaller, more focused modules?**
  _Cohesion score 0.1 - nodes in this community are weakly interconnected._