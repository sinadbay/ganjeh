# Graph Report - t5-prompt  (2026-08-25)

## Corpus Check
- 14 files · ~16,557 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 174 nodes · 295 edges · 8 communities (6 shown, 2 thin omitted)
- Extraction: 98% EXTRACTED · 2% INFERRED · 0% AMBIGUOUS · INFERRED: 5 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `f149b1aa`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- vault.ts
- crypto.ts
- store.ts
- compilerOptions
- package.json
- prompt.ts
- paths.ts
- README.md

## God Nodes (most connected - your core abstractions)
1. `VaultError` - 22 edges
2. `compilerOptions` - 15 edges
3. `save()` - 11 edges
4. `open()` - 10 edges
5. `FsDeps` - 9 edges
6. `VaultCorruptError` - 9 edges
7. `validateKdfParams()` - 7 edges
8. `readHidden()` - 6 edges
9. `decodeVault()` - 6 edges
10. `deriveKey()` - 5 edges

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

## Communities (8 total, 2 thin omitted)

### Community 0 - "vault.ts"
Cohesion: 0.14
Nodes (22): AddEntryOptions, describeUntrusted(), EntryExistsError, EntryNotFoundError, InvalidNameError, InvalidSecretError, NAME_PATTERN, VaultCorruptError (+14 more)

### Community 1 - "crypto.ts"
Cohesion: 0.12
Nodes (23): Cipher, CIPHER_ALGORITHM, decodeBase64(), deriveKey(), describeUntrusted(), EncryptedEnvelope, ENVELOPE_VERSION, isPlainRecord() (+15 more)

### Community 2 - "store.ts"
Cohesion: 0.08
Nodes (15): createStore(), exists(), load(), save(), defaultDeps, EncryptedEnvelope, FileHandleLike, FsDeps (+7 more)

### Community 3 - "compilerOptions"
Cohesion: 0.10
Nodes (19): ES2023, node, src/**/*.ts, compilerOptions, allowImportingTsExtensions, exactOptionalPropertyTypes, forceConsistentCasingInFileNames, lib (+11 more)

### Community 4 - "package.json"
Cohesion: 0.12
Nodes (16): description, devDependencies, @types/node, typescript, engines, node, name, private (+8 more)

### Community 5 - "prompt.ts"
Cohesion: 0.11
Nodes (19): AbortedError, assertPassphraseStrength(), getReaderState(), InputTooLongError, MAX_HIDDEN_INPUT_LENGTH, nextChar(), PassphraseMismatchError, PromptDeps (+11 more)

## Knowledge Gaps
- **40 isolated node(s):** `name`, `version`, `private`, `description`, `type` (+35 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `VaultError` connect `vault.ts` to `crypto.ts`, `store.ts`, `prompt.ts`?**
  _High betweenness centrality (0.255) - this node is a cross-community bridge._
- **Why does `VaultCorruptError` connect `vault.ts` to `crypto.ts`, `store.ts`?**
  _High betweenness centrality (0.062) - this node is a cross-community bridge._
- **What connects `name`, `version`, `private` to the rest of the system?**
  _40 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `vault.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.14112903225806453 - nodes in this community are weakly interconnected._
- **Should `crypto.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.12258064516129032 - nodes in this community are weakly interconnected._
- **Should `store.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.07965860597439545 - nodes in this community are weakly interconnected._
- **Should `compilerOptions` be split into smaller, more focused modules?**
  _Cohesion score 0.1 - nodes in this community are weakly interconnected._