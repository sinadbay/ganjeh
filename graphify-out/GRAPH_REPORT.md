# Graph Report - a-command-line-password-vault-va-3d05edb6  (2026-08-27)

## Corpus Check
- 21 files · ~22,905 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 361 nodes · 815 edges · 12 communities (10 shown, 2 thin omitted)
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 5 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `2bbe6cf7`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]

## God Nodes (most connected - your core abstractions)
1. `VaultError` - 33 edges
2. `src/vault.ts` - 28 edges
3. `decodeVault()` - 22 edges
4. `run()` - 18 edges
5. `VaultCorruptError` - 16 edges
6. `compilerOptions` - 15 edges
7. `compilerOptions` - 15 edges
8. `addEntry()` - 12 edges
9. `open()` - 12 edges
10. `VaultNotFoundError` - 12 edges

## Surprising Connections (you probably didn't know these)
- `runWith()` --calls--> `run()`  [EXTRACTED]
  test/commands.test.ts → src/cli.ts
- `realPrompt()` --calls--> `readHidden()`  [EXTRACTED]
  src/cli.ts → src/prompt.ts
- `realPrompt()` --calls--> `readNewPassphrase()`  [EXTRACTED]
  src/cli.ts → src/prompt.ts
- `realPrompt()` --calls--> `readSecret()`  [EXTRACTED]
  src/cli.ts → src/prompt.ts
- `CommandDeps` --references--> `VaultStore`  [EXTRACTED]
  src/cli.ts → src/store.ts

## Communities (12 total, 2 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.10
Nodes (44): AddOptions, runAdd(), runGet(), runList(), CommandDeps, AddOptions, runAdd(), runGet() (+36 more)

### Community 1 - "Community 1"
Cohesion: 0.08
Nodes (46): Cipher, CIPHER_ALGORITHM, decodeBase64(), deriveKey(), describeUntrusted(), EncryptedEnvelope, ENVELOPE_VERSION, isPlainRecord() (+38 more)

### Community 2 - "Community 2"
Cohesion: 0.06
Nodes (33): node:fs/promises, CommandCipher, RunDeps, exists(), load(), save(), defaultDeps, EncryptedEnvelope (+25 more)

### Community 3 - "Community 3"
Cohesion: 0.06
Nodes (35): compilerOptions, allowImportingTsExtensions, exactOptionalPropertyTypes, forceConsistentCasingInFileNames, lib, module, moduleResolution, noEmit (+27 more)

### Community 4 - "Community 4"
Cohesion: 0.06
Nodes (30): description, devDependencies, @types/node, typescript, engines, node, name, private (+22 more)

### Community 5 - "Community 5"
Cohesion: 0.13
Nodes (28): AbortedError, assertPassphraseStrength(), getReaderState(), InputTooLongError, MAX_HIDDEN_INPUT_LENGTH, nextChar(), PassphraseMismatchError, RawModeCapable (+20 more)

### Community 6 - "Community 6"
Cohesion: 0.11
Nodes (30): bin/vault.ts, AddParsed, bridgedCipher(), buildRunDeps(), CliUsageError, CommandParsed, CommandPrompt, FlagSpec (+22 more)

### Community 7 - "Community 7"
Cohesion: 0.12
Nodes (16): dir, dirAsFilePath, envelope, fileChmods, filePath, { fs }, { fs, log }, linkPath (+8 more)

### Community 9 - "Community 9"
Cohesion: 0.29
Nodes (3): BIN_PATH, CliResult, exec

### Community 10 - "Community 10"
Cohesion: 0.15
Nodes (9): BIN_PATH, child, CliResult, env, envelope, exec, lockedParent, secret (+1 more)

## Knowledge Gaps
- **120 isolated node(s):** `name`, `version`, `private`, `description`, `type` (+115 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **2 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `VaultError` connect `Community 5` to `Community 0`, `Community 1`, `Community 2`, `Community 6`, `Community 7`?**
  _High betweenness centrality (0.171) - this node is a cross-community bridge._
- **Why does `VaultCorruptError` connect `Community 1` to `Community 0`, `Community 2`, `Community 5`, `Community 7`?**
  _High betweenness centrality (0.046) - this node is a cross-community bridge._
- **What connects `name`, `version`, `private` to the rest of the system?**
  _120 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.09717514124293786 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.08127721335268505 - nodes in this community are weakly interconnected._
- **Should `Community 2` be split into smaller, more focused modules?**
  _Cohesion score 0.06170598911070781 - nodes in this community are weakly interconnected._
- **Should `Community 3` be split into smaller, more focused modules?**
  _Cohesion score 0.057057057057057055 - nodes in this community are weakly interconnected._