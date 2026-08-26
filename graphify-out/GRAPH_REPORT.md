# Graph Report - t6-cli  (2026-08-26)

## Corpus Check
- 21 files · ~22,905 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 230 nodes · 442 edges · 10 communities (9 shown, 1 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 5 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `9eaa6ce4`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- src/vault.ts
- crypto.ts
- store.ts
- compilerOptions
- package.json
- prompt.ts
- cli.ts
- commands.test.ts
- README.md
- cli.e2e.test.ts

## God Nodes (most connected - your core abstractions)
1. `VaultError` - 24 edges
2. `compilerOptions` - 15 edges
3. `decodeVault()` - 13 edges
4. `run()` - 12 edges
5. `save()` - 11 edges
6. `open()` - 10 edges
7. `FsDeps` - 9 edges
8. `VaultCorruptError` - 9 edges
9. `realPrompt()` - 8 edges
10. `readHidden()` - 8 edges

## Surprising Connections (you probably didn't know these)
- `runWith()` --calls--> `run()`  [EXTRACTED]
  test/commands.test.ts → src/cli.ts
- `CliUsageError` --inherits--> `VaultError`  [EXTRACTED]
  src/cli.ts → src/types.ts
- `buildRunDeps()` --calls--> `createStore()`  [EXTRACTED]
  src/cli.ts → src/store.ts
- `run()` --calls--> `runAdd()`  [EXTRACTED]
  src/cli.ts → src/commands/add.ts
- `run()` --calls--> `runGet()`  [EXTRACTED]
  src/cli.ts → src/commands/get.ts

## Import Cycles
- None detected.

## Communities (10 total, 1 thin omitted)

### Community 0 - "src/vault.ts"
Cohesion: 0.12
Nodes (26): AddOptions, runAdd(), runGet(), AddEntryOptions, describeUntrusted(), EntryExistsError, EntryNotFoundError, InvalidNameError (+18 more)

### Community 1 - "crypto.ts"
Cohesion: 0.13
Nodes (22): Cipher, CIPHER_ALGORITHM, decodeBase64(), deriveKey(), describeUntrusted(), EncryptedEnvelope, ENVELOPE_VERSION, isPlainRecord() (+14 more)

### Community 2 - "store.ts"
Cohesion: 0.10
Nodes (12): createStore(), exists(), load(), save(), defaultDeps, FileHandleLike, FsDeps, isEncryptedEnvelopeShape() (+4 more)

### Community 3 - "compilerOptions"
Cohesion: 0.10
Nodes (19): ES2023, node, src/**/*.ts, compilerOptions, allowImportingTsExtensions, exactOptionalPropertyTypes, forceConsistentCasingInFileNames, lib (+11 more)

### Community 4 - "package.json"
Cohesion: 0.12
Nodes (16): description, devDependencies, @types/node, typescript, engines, node, name, private (+8 more)

### Community 5 - "prompt.ts"
Cohesion: 0.10
Nodes (20): CommandPrompt, realPrompt(), AbortedError, assertPassphraseStrength(), getReaderState(), InputTooLongError, MAX_HIDDEN_INPUT_LENGTH, nextChar() (+12 more)

### Community 6 - "cli.ts"
Cohesion: 0.09
Nodes (27): AddParsed, bridgedCipher(), buildRunDeps(), CliUsageError, CommandDeps, CommandParsed, FlagSpec, flagString() (+19 more)

### Community 7 - "commands.test.ts"
Cohesion: 0.18
Nodes (4): CommandCipher, EncryptedEnvelope, makeSink(), runWith()

### Community 9 - "cli.e2e.test.ts"
Cohesion: 0.29
Nodes (3): BIN_PATH, CliResult, exec

## Knowledge Gaps
- **48 isolated node(s):** `name`, `version`, `private`, `description`, `type` (+43 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **1 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `VaultError` connect `src/vault.ts` to `crypto.ts`, `store.ts`, `prompt.ts`, `cli.ts`?**
  _High betweenness centrality (0.145) - this node is a cross-community bridge._
- **Why does `createStore()` connect `store.ts` to `cli.ts`?**
  _High betweenness centrality (0.034) - this node is a cross-community bridge._
- **What connects `name`, `version`, `private` to the rest of the system?**
  _48 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `src/vault.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.12051282051282051 - nodes in this community are weakly interconnected._
- **Should `crypto.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.1330049261083744 - nodes in this community are weakly interconnected._
- **Should `store.ts` be split into smaller, more focused modules?**
  _Cohesion score 0.1032258064516129 - nodes in this community are weakly interconnected._
- **Should `compilerOptions` be split into smaller, more focused modules?**
  _Cohesion score 0.1 - nodes in this community are weakly interconnected._