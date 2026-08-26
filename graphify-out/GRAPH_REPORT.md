# Graph Report - t7-release  (2026-08-26)

## Corpus Check
- 14 files · ~16,499 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 177 nodes · 273 edges · 10 communities (8 shown, 2 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 5 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `9fc5f6ba`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- vault.ts
- crypto.ts
- store.ts
- package.json
- compilerOptions
- ganjeh
- package.test.ts
- store.test.ts
- 0.1.0
- paths.ts

## God Nodes (most connected - your core abstractions)
1. `VaultError` - 16 edges
2. `compilerOptions` - 15 edges
3. `save()` - 11 edges
4. `open()` - 10 edges
5. `FsDeps` - 9 edges
6. `VaultCorruptError` - 9 edges
7. `validateKdfParams()` - 7 edges
8. `ganjeh` - 7 edges
9. `scripts` - 6 edges
10. `decodeVault()` - 6 edges

## Surprising Connections (you probably didn't know these)
- `decodeVault()` --calls--> `describeUntrusted()`  [EXTRACTED]
  src/vault.ts → src/types.ts

## Import Cycles
- None detected.

## Communities (10 total, 2 thin omitted)

### Community 0 - "vault.ts"
Cohesion: 0.14
Nodes (22): AddEntryOptions, describeUntrusted(), EntryExistsError, EntryNotFoundError, InvalidNameError, InvalidSecretError, NAME_PATTERN, VaultCorruptError (+14 more)

### Community 1 - "crypto.ts"
Cohesion: 0.12
Nodes (23): Cipher, CIPHER_ALGORITHM, decodeBase64(), deriveKey(), describeUntrusted(), EncryptedEnvelope, ENVELOPE_VERSION, isPlainRecord() (+15 more)

### Community 2 - "store.ts"
Cohesion: 0.10
Nodes (13): createStore(), exists(), load(), save(), defaultDeps, EncryptedEnvelope, FileHandleLike, FsDeps (+5 more)

### Community 3 - "package.json"
Cohesion: 0.08
Nodes (25): bin, vault, description, devDependencies, @types/node, typescript, engines, node (+17 more)

### Community 4 - "compilerOptions"
Cohesion: 0.10
Nodes (19): ES2023, node, src/**/*.ts, compilerOptions, allowImportingTsExtensions, exactOptionalPropertyTypes, forceConsistentCasingInFileNames, lib (+11 more)

### Community 5 - "ganjeh"
Cohesion: 0.17
Nodes (11): Commands, Encryption, Exit codes, ganjeh, Install, License, `vault add <name> [--force] [--stdin] [--file <path>]`, `vault get <name> [--file <path>]` (+3 more)

### Community 6 - "package.test.ts"
Cohesion: 0.25
Nodes (6): CHANGELOG_PATH, execFileAsync, PACKAGE_JSON_PATH, packDryRun(), README_PATH, REPO_ROOT

### Community 8 - "0.1.0"
Cohesion: 0.40
Nodes (4): 0.1.0, Added, Changelog, Compatibility

## Knowledge Gaps
- **57 isolated node(s):** `name`, `version`, `description`, `license`, `type` (+52 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `VaultError` connect `vault.ts` to `crypto.ts`, `store.ts`, `store.test.ts`?**
  _High betweenness centrality (0.106) - this node is a cross-community bridge._
- **Why does `VaultCorruptError` connect `vault.ts` to `crypto.ts`, `store.ts`, `store.test.ts`?**
  _High betweenness centrality (0.069) - this node is a cross-community bridge._
- **What connects `name`, `version`, `description` to the rest of the system?**
  _57 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `vault.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.14112903225806453 - nodes in this community are weakly interconnected._
- **Should `crypto.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.12258064516129032 - nodes in this community are weakly interconnected._
- **Should `store.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.10344827586206896 - nodes in this community are weakly interconnected._
- **Should `package.json` be split into smaller, more focused modules?**
  _Cohesion score 0.07692307692307693 - nodes in this community are weakly interconnected._