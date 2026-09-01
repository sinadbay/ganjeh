# Graph Report - t7-release-mtiqvrwh  (2026-09-01)

## Corpus Check
- 24 files · ~27,390 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 420 nodes · 740 edges · 14 communities
- Extraction: 99% EXTRACTED · 1% INFERRED · 0% AMBIGUOUS · INFERRED: 5 edges (avg confidence: 0.85)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `bb825d10`
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
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]

## God Nodes (most connected - your core abstractions)
1. `VaultError` - 25 edges
2. `VaultCorruptError` - 16 edges
3. `compilerOptions` - 15 edges
4. `decodeVault()` - 15 edges
5. `compilerOptions` - 15 edges
6. `run()` - 12 edges
7. `open()` - 12 edges
8. `save()` - 11 edges
9. `VaultNotFoundError` - 10 edges
10. `FsDeps` - 10 edges

## Surprising Connections (you probably didn't know these)
- `runWith()` --calls--> `run()`  [EXTRACTED]
  test/commands.test.ts → src/cli.ts
- `buildRunDeps()` --calls--> `createStore()`  [EXTRACTED]
  src/cli.ts → src/store.ts
- `run()` --calls--> `runAdd()`  [EXTRACTED]
  src/cli.ts → src/commands/add.ts
- `run()` --calls--> `runGet()`  [EXTRACTED]
  src/cli.ts → src/commands/get.ts
- `run()` --calls--> `runList()`  [EXTRACTED]
  src/cli.ts → src/commands/list.ts

## Communities (14 total, 0 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.10
Nodes (42): AddOptions, runAdd(), runGet(), runList(), CommandDeps, AddEntryOptions, describeUntrusted(), EntryExistsError (+34 more)

### Community 1 - "Community 1"
Cohesion: 0.08
Nodes (45): Cipher, CIPHER_ALGORITHM, decodeBase64(), deriveKey(), describeUntrusted(), EncryptedEnvelope, ENVELOPE_VERSION, isPlainRecord() (+37 more)

### Community 2 - "Community 2"
Cohesion: 0.06
Nodes (31): createStore(), exists(), load(), save(), defaultDeps, EncryptedEnvelope, FileHandleLike, FsDeps (+23 more)

### Community 3 - "Community 3"
Cohesion: 0.04
Nodes (47): bin, vault, description, devDependencies, @types/node, typescript, engines, node (+39 more)

### Community 4 - "Community 4"
Cohesion: 0.06
Nodes (35): ES2023, node, src/**/*.ts, compilerOptions, allowImportingTsExtensions, exactOptionalPropertyTypes, forceConsistentCasingInFileNames, lib (+27 more)

### Community 5 - "Community 5"
Cohesion: 0.17
Nodes (11): Commands, Encryption, Exit codes, ganjeh, Install, License, `vault add <name> [--force] [--stdin] [--file <path>]`, `vault get <name> [--file <path>]` (+3 more)

### Community 6 - "Community 6"
Cohesion: 0.10
Nodes (23): args, binJs, CHANGELOG_PATH, env, execFileAsync, npmrcFiles, outDir, outDirFlagIndex (+15 more)

### Community 7 - "Community 7"
Cohesion: 0.10
Nodes (23): realPrompt(), AbortedError, assertPassphraseStrength(), getReaderState(), InputTooLongError, nextChar(), PassphraseMismatchError, RawModeCapable (+15 more)

### Community 8 - "Community 8"
Cohesion: 0.40
Nodes (4): 0.1.0, Added, Changelog, Compatibility

### Community 9 - "Community 9"
Cohesion: 0.06
Nodes (38): AddParsed, bridgedCipher(), buildRunDeps(), CliUsageError, CommandCipher, CommandParsed, CommandPrompt, FlagSpec (+30 more)

### Community 10 - "Community 10"
Cohesion: 0.11
Nodes (18): code:block1 (npm i -g ganjeh), code:block2 ($ vault add npm-token --stdin), code:block3 ($ printf 'correct-horse-battery\nsuper-secret-value\n' | vau), code:block4 ($ vault get npm-token), code:block5 ($ vault list), code:block6 ($ vault list), code:block7 ($ VAULT_FILE=/tmp/scratch-vault.json vault add test-entry --), Commands (+10 more)

### Community 11 - "Community 11"
Cohesion: 0.15
Nodes (9): BIN_PATH, child, CliResult, env, envelope, exec, lockedParent, secret (+1 more)

### Community 12 - "Community 12"
Cohesion: 0.40
Nodes (4): 0.1.0, Added, Changelog, Compatibility

### Community 13 - "Community 13"
Cohesion: 0.40
Nodes (4): Anything worth arguing about, How it works, Summary, What I tested

## Knowledge Gaps
- **174 isolated node(s):** `name`, `version`, `description`, `license`, `type` (+169 more)
  These have ≤1 connection - possible missing edges or undocumented components.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `VaultError` connect `Community 0` to `Community 9`, `Community 2`, `Community 1`, `Community 7`?**
  _High betweenness centrality (0.119) - this node is a cross-community bridge._
- **Why does `VaultCorruptError` connect `Community 0` to `Community 1`, `Community 2`?**
  _High betweenness centrality (0.040) - this node is a cross-community bridge._
- **What connects `name`, `version`, `description` to the rest of the system?**
  _174 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.09643483343074226 - nodes in this community are weakly interconnected._
- **Should `Community 1` be split into smaller, more focused modules?**
  _Cohesion score 0.08392156862745098 - nodes in this community are weakly interconnected._
- **Should `Community 2` be split into smaller, more focused modules?**
  _Cohesion score 0.06386066763425254 - nodes in this community are weakly interconnected._
- **Should `Community 3` be split into smaller, more focused modules?**
  _Cohesion score 0.04251700680272109 - nodes in this community are weakly interconnected._