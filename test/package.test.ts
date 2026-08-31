/**
 * Node t7 — package, document and prepare the 0.1.0 release.
 *
 * Scenario map (see brief):
 *   t7-s1  npm pack --dry-run --json lists only the allowed paths, plus a dist/bin/vault.js entry
 *   t7-s2  installing the packed tarball into a temp prefix and running `vault --version` prints 0.1.0
 *   t7-s3  add --stdin then get against a temp VAULT_FILE returns the stored secret
 *   t7-s4  README.md documents the KDF, cipher, file mode and the no-recovery guarantee
 *   t7-s5  package.json carries the fields a publish depends on
 *   t7-f1  install, list (no vault), add, get end-to-end
 *   t7-a1  the tarball excludes source, tests and dotfiles
 *   t7-a2  a vault written by this version stays readable after a rollback (format version unchanged)
 *   t7-a3  no committed npm auth token, no CI publish workflow
 *
 * t7-s1, t7-s2, t7-s3, t7-f1 and t7-a1 need a real dist/bin/vault.js. This repository does not have
 * one yet: `src/bin/vault.ts`, `src/cli.ts` and `src/commands/*` exist only on the unmerged
 * `keel/t6-cli-cli-wiring-vault-add-get-list-with-exit-` branch — not on this branch, and not on
 * `develop` either (checked with `git ls-tree -r develop` and `git branch -a`; `src/prompt.ts`, from
 * the sibling `keel/t5-...` node, *has* landed on `develop` already, so it is not part of this gap).
 * No amount of change within this node's owned paths (package.json, README.md, CHANGELOG.md, LICENSE,
 * .npmignore, this file) can make those tests pass, because the source they exercise does not exist
 * in this branch's history. Two things follow from that, both raised in review and both worth being
 * explicit about rather than "fixing" by editing around them:
 *
 *  - `package.json`'s `bin.vault: "dist/bin/vault.js"` looks wrong while that file can't be built, but
 *    it is the value t7-s5 requires and the value publishing actually needs the moment t6 lands — the
 *    defect is the missing merge, not this field. Reverting it would just trade a real, visible gap
 *    for a silent, permanent one that no future merge would ever fix on its own. See the "safety net"
 *    describe block below for why this can't accidentally get published in the meantime.
 *  - CHANGELOG.md documents `vault add`/`get`/`list` because that is what the 0.1.0 release this node
 *    prepares is scoped to ship (per the brief's own "Already in the repository" list), which is
 *    normal for a changelog — it describes the release, not the state of one contributing branch. Its
 *    content is exactly what the DoD and the "CHANGELOG.md and LICENSE" test below both require.
 *
 * A previous version of this file also documented a second, independent problem: `tsc -p
 * tsconfig.json --noEmit false` tripped `TS5096` because tsconfig.json sets
 * `allowImportingTsExtensions: true` together with `noEmit: true`, and TypeScript only permits that
 * combination while noEmit (or emitDeclarationOnly) stays set. That is now fixed, entirely within
 * this node's owned package.json, without touching tsconfig.json: the build script also passes
 * `--rewriteRelativeImportExtensions` on the tsc command line (a flag, not a tsconfig field, so it
 * does not require editing tsconfig.json), and the `typescript` devDependency is raised to `^5.7.0`,
 * the first version that supports it. That flag both permits the `allowImportingTsExtensions` +
 * emit combination and rewrites relative `./foo.ts` imports to `./foo.js` in the emitted output —
 * verified below by actually invoking the build's tsc step against this repo's existing src/ modules
 * and inspecting the emitted JS. The "build emits valid JS" test below is the regression test for
 * this: it fails again if the flag or the devDependency floor regresses.
 *
 * The six scenarios below that depend on dist/bin/vault.js (the five listed above, plus a `vault
 * --help` check for the DoD's "and vault --help lists add, get and list" clause, which has no
 * scenario ID of its own) are still written exactly as the brief describes them and are still
 * expected to fail, but now only for the missing-source reason above, not because of a defect in
 * this node's own files. They are left in place, unskipped and unweakened, so the gap stays visible
 * in `npm test` rather than being hidden.
 */

import { test, describe, before } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import path from 'node:path';
import os from 'node:os';
import * as fs from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';

import { ENVELOPE_VERSION } from '../src/crypto.ts';

const execFileAsync = promisify(execFile);
const REPO_ROOT = path.resolve(fileURLToPath(import.meta.url), '../..');
const PACKAGE_JSON_PATH = path.join(REPO_ROOT, 'package.json');
const README_PATH = path.join(REPO_ROOT, 'README.md');
const CHANGELOG_PATH = path.join(REPO_ROOT, 'CHANGELOG.md');

// t7-s1's allowlist, verbatim from the brief.
const ALLOWED_PACK_PATH = /^(dist\/|package\.json$|README\.md$|LICENSE$|CHANGELOG\.md$)/;
// t7-a1's forbidden-file pattern, verbatim from the brief.
const FORBIDDEN_PACK_PATH = /\.env|\.npmrc|test\/|src\//;

async function readPackageJson() {
  return JSON.parse(await fs.readFile(PACKAGE_JSON_PATH, 'utf8'));
}

async function withTmpDir(fn) {
  const dir = await fs.mkdtemp(path.join(os.tmpdir(), 'vault-pkg-test-'));
  try {
    return await fn(dir);
  } finally {
    await fs.rm(dir, { recursive: true, force: true });
  }
}

/** `npm pack --dry-run --json`'s single package entry, parsed. */
async function packDryRun() {
  const { stdout } = await execFileAsync('npm', ['pack', '--dry-run', '--json'], { cwd: REPO_ROOT });
  const [entry] = JSON.parse(stdout);
  return entry;
}

// dist/ is a build artifact, not committed to the repository (see .npmignore's
// comment: package.json's "files" field is the real allowlist, and a stale,
// committed dist/ would drift from src/ the moment either changed without the
// other). The tests below need a freshly built dist/ to inspect, so build it
// once, here, before any of them run.
//
// This currently cannot fully succeed: the build script's final step chmods
// dist/bin/vault.js executable, and that file cannot exist until
// src/bin/vault.ts lands (see the module comment above). Tolerate exactly
// that failure — verified by confirming its root cause is still the missing
// source file, not a regression — so the tsc step's output (everything except
// the CLI entry point) is still there for the tests that follow. Anything
// else the build fails on is a real problem and must fail loudly here.
before(async () => {
  try {
    await execFileAsync('npm', ['run', 'build'], { cwd: REPO_ROOT });
  } catch (error) {
    const stillMissing = !existsSync(path.join(REPO_ROOT, 'src', 'bin', 'vault.ts'));
    assert.ok(
      stillMissing,
      `npm run build failed for a reason other than the missing CLI source:\n${error.stderr ?? error.message}`,
    );
  }
});

// ---------------------------------------------------------------------------
// t7-s5 — package.json fields
// ---------------------------------------------------------------------------

describe('package.json fields a publish depends on (t7-s5)', () => {
  test('version is 0.1.0', async () => {
    const pkg = await readPackageJson();
    assert.equal(pkg.version, '0.1.0');
  });

  test('files is exactly ["dist"]', async () => {
    const pkg = await readPackageJson();
    assert.deepEqual(pkg.files, ['dist']);
  });

  test('bin.vault is dist/bin/vault.js', async () => {
    const pkg = await readPackageJson();
    assert.equal(pkg.bin?.vault, 'dist/bin/vault.js');
  });

  test('engines.node allows >=20', async () => {
    const pkg = await readPackageJson();
    assert.match(pkg.engines?.node ?? '', />=20/);
  });

  test('the package is licensed and publishable', async () => {
    const pkg = await readPackageJson();
    assert.equal(pkg.license, 'MIT');
    assert.equal(pkg.private, undefined, 'package.json marks the package private');
  });
});

// ---------------------------------------------------------------------------
// regression — the build's tsc step must not trip TS5096/TS5097
// ---------------------------------------------------------------------------

describe('build emits valid JS without TS5096/TS5097 (regression)', () => {
  test('the build script\'s tsc invocation compiles src/ and rewrites .ts imports to .js', async () => {
    await withTmpDir(async (tmp) => {
      const outDir = path.join(tmp, 'dist');
      const pkg = await readPackageJson();
      const steps = pkg.scripts.build.split('&&').map((step) => step.trim());
      const tscStep = steps.find((step) => step.startsWith('tsc '));
      assert.ok(tscStep, 'build script has no tsc step');
      const args = tscStep.split(/\s+/).slice(1);
      const outDirFlagIndex = args.indexOf('--outDir');
      assert.ok(outDirFlagIndex !== -1, 'build script has no --outDir flag to redirect');
      args[outDirFlagIndex + 1] = outDir;

      const tscBin = path.join(REPO_ROOT, 'node_modules', '.bin', 'tsc');
      await execFileAsync(tscBin, args, { cwd: REPO_ROOT });

      const emitted = await fs.readFile(path.join(outDir, 'store.js'), 'utf8');
      assert.doesNotMatch(emitted, /from ["'][^"']*\.ts["']/, 'emitted JS still imports a .ts path');
      assert.match(emitted, /from ["']\.\/types\.js["']/, 'emitted JS does not import the rewritten .js path');
    });
  });
});

// ---------------------------------------------------------------------------
// safety net — a package missing its CLI entry point cannot be published
//
// `package.json`'s `bin.vault` points at `dist/bin/vault.js`, which does not
// exist until `src/bin/vault.ts` lands (see the module comment above). That
// makes the *installed* package non-functional today — but `npm publish`
// cannot succeed today either: it runs `prepublishOnly` (`npm run build &&
// npm test`) first, and the build's last step chmods the compiled bin entry
// with no fallback that would let a missing file pass silently. So nothing
// broken can reach the registry through the normal `npm publish` path while
// this gap exists. This test is the proof, and the tripwire: if it starts
// passing for the wrong reason (a swallowed chmod failure rather than the
// CLI source actually landing), that is a real regression.
// ---------------------------------------------------------------------------

describe('a package with no working bin cannot be published (t6 merge-gap safety net)', () => {
  test('npm run build fails on the missing dist/bin/vault.js, so prepublishOnly does too', async () => {
    const pkg = await readPackageJson();
    assert.doesNotMatch(
      pkg.scripts.build,
      /chmod[^&]*(\|\|\s*true|;\s*true|2>\s*\/dev\/null)/,
      'the build script silences a failing chmod — it could then succeed and publish a package with no executable bin',
    );

    await assert.rejects(
      execFileAsync('npm', ['run', 'build'], { cwd: REPO_ROOT }),
      (error) => {
        assert.match(String(error.stderr ?? ''), /chmod.*dist\/bin\/vault\.js/);
        return true;
      },
      'npm run build succeeded — either src/bin/vault.ts has landed (delete this test; t7-s1/s2/s3/f1 above should now pass) or the build stopped failing loudly on a missing bin entry',
    );
    assert.ok(
      !existsSync(path.join(REPO_ROOT, 'src', 'bin', 'vault.ts')),
      'npm run build failed but src/bin/vault.ts exists — investigate why the build did not produce dist/bin/vault.js from it',
    );
  });
});

// ---------------------------------------------------------------------------
// t7-s4 — README content
// ---------------------------------------------------------------------------

describe('README.md documents the threat model (t7-s4)', () => {
  test('names the KDF, its parameters, the cipher, the file mode and the no-recovery guarantee', async () => {
    const readme = await fs.readFile(README_PATH, 'utf8');
    for (const needle of ['scrypt', '131072', 'aes-256-gcm', '0600', 'no way to recover']) {
      assert.ok(readme.includes(needle), `README.md is missing ${JSON.stringify(needle)}`);
    }
  });
});

// ---------------------------------------------------------------------------
// CHANGELOG.md / LICENSE — definition-of-done bullets not otherwise covered
// ---------------------------------------------------------------------------

describe('CHANGELOG.md and LICENSE', () => {
  test('CHANGELOG.md has a 0.1.0 section listing add, get and list', async () => {
    const changelog = await fs.readFile(CHANGELOG_PATH, 'utf8');
    assert.match(changelog, /##\s*0\.1\.0/);
    for (const command of ['vault add', 'vault get', 'vault list']) {
      assert.ok(changelog.includes(command), `CHANGELOG.md does not mention ${command}`);
    }
  });

  test('LICENSE contains the MIT text', async () => {
    const license = await fs.readFile(path.join(REPO_ROOT, 'LICENSE'), 'utf8');
    assert.match(license, /MIT License/);
    assert.match(license, /THE SOFTWARE IS PROVIDED "AS IS"/);
  });
});

// ---------------------------------------------------------------------------
// t7-a3 — publishing stays a manual, human action
// ---------------------------------------------------------------------------

describe('publishing stays a manual, human action (t7-a3)', () => {
  test('no .npmrc is committed to the repository', async () => {
    const { stdout } = await execFileAsync('git', ['ls-files'], { cwd: REPO_ROOT });
    const tracked = stdout.split('\n').filter(Boolean);
    const npmrcFiles = tracked.filter((file) => path.basename(file) === '.npmrc');
    assert.deepEqual(npmrcFiles, [], 'a .npmrc is committed to the repository');
  });

  test('no CI workflow runs npm publish', async () => {
    const workflowsDir = path.join(REPO_ROOT, '.github', 'workflows');
    if (!existsSync(workflowsDir)) {
      return;
    }
    const files = await fs.readdir(workflowsDir);
    for (const file of files) {
      const contents = await fs.readFile(path.join(workflowsDir, file), 'utf8');
      assert.ok(!/npm\s+publish/.test(contents), `${file} runs npm publish`);
    }
  });
});

// ---------------------------------------------------------------------------
// t7-a2 — a vault written by this version survives a rollback
// ---------------------------------------------------------------------------

describe('rollback safety (t7-a2)', () => {
  test('the envelope format version this release writes is 1', () => {
    // 0.1.0 is the first release, so there is no previously-published build to
    // install and test a real rollback against yet. What is verifiable now is
    // the guarantee CHANGELOG.md makes: the on-disk format version this build
    // writes is 1, and does not change from what src/crypto.ts already
    // shipped in t2. Once a 0.1.1+ is published, this test should be extended
    // to actually install the previous npm package and load a file this
    // version wrote with it.
    assert.equal(ENVELOPE_VERSION, 1);
  });
});

// ---------------------------------------------------------------------------
// t7-s1 / t7-a1 — the packed tarball's file list
//
// BLOCKED — see the module comment at the top of this file. dist/ does not
// exist on this branch, so packDryRun() below can never include a
// dist/bin/vault.js entry no matter how package.json is configured.
// ---------------------------------------------------------------------------

describe('npm pack contents (t7-s1, t7-a1)', () => {
  test('every packed path is allowed, and dist/bin/vault.js is present', async () => {
    const entry = await packDryRun();
    for (const file of entry.files) {
      assert.match(file.path, ALLOWED_PACK_PATH, `unexpected file in tarball: ${file.path}`);
    }
    assert.ok(
      entry.files.some((file) => file.path === 'dist/bin/vault.js'),
      'dist/bin/vault.js is not in the tarball — see the module comment for why',
    );
  });

  test('the tarball contains no .env, .npmrc, test/ or src/ file', async () => {
    const entry = await packDryRun();
    for (const file of entry.files) {
      assert.ok(!FORBIDDEN_PACK_PATH.test(file.path), `forbidden file in tarball: ${file.path}`);
    }
  });
});

// ---------------------------------------------------------------------------
// t7-s2 / t7-s3 / t7-f1 — the packed tarball, installed and run
//
// BLOCKED — see the module comment at the top of this file.
// ---------------------------------------------------------------------------

describe('installed binary (t7-s2, t7-s3, t7-f1)', () => {
  test('vault --version prints 0.1.0 from a global install of the packed tarball', async () => {
    await withTmpDir(async (tmp) => {
      const packOut = await execFileAsync('npm', ['pack', '--pack-destination', tmp], { cwd: REPO_ROOT });
      const tarballName = packOut.stdout.trim().split('\n').pop();
      const prefix = path.join(tmp, 'prefix');
      await fs.mkdir(prefix, { recursive: true });
      await execFileAsync('npm', ['install', '-g', '--prefix', prefix, path.join(tmp, tarballName)]);

      const binPath = path.join(prefix, 'bin', 'vault');
      const { stdout, code } = await execFileAsync(binPath, ['--version']).then(
        (result) => ({ ...result, code: 0 }),
        (error) => ({ stdout: error.stdout ?? '', code: error.code }),
      );

      assert.equal(stdout, '0.1.0\n');
      assert.equal(code, 0);
    });
  });

  // DoD bullet 2 also requires `vault --help` to list all three commands —
  // distinct from the `--version` check above, and not otherwise named as
  // its own scenario ID, but it is still a checkbox this PR claims.
  test('vault --help lists add, get and list', async () => {
    await withTmpDir(async (tmp) => {
      const packOut = await execFileAsync('npm', ['pack', '--pack-destination', tmp], { cwd: REPO_ROOT });
      const tarballName = packOut.stdout.trim().split('\n').pop();
      const prefix = path.join(tmp, 'prefix');
      await fs.mkdir(prefix, { recursive: true });
      await execFileAsync('npm', ['install', '-g', '--prefix', prefix, path.join(tmp, tarballName)]);

      const binPath = path.join(prefix, 'bin', 'vault');
      const { stdout } = await execFileAsync(binPath, ['--help']);
      for (const command of ['add', 'get', 'list']) {
        assert.ok(stdout.includes(command), `vault --help does not mention "${command}"`);
      }
    });
  });

  test('an install-then-add-then-get sequence returns the stored secret', async () => {
    await withTmpDir(async (tmp) => {
      const packOut = await execFileAsync('npm', ['pack', '--pack-destination', tmp], { cwd: REPO_ROOT });
      const tarballName = packOut.stdout.trim().split('\n').pop();
      const prefix = path.join(tmp, 'prefix');
      await fs.mkdir(prefix, { recursive: true });
      await execFileAsync('npm', ['install', '-g', '--prefix', prefix, path.join(tmp, tarballName)]);

      const binPath = path.join(prefix, 'bin', 'vault');
      const vaultFile = path.join(tmp, 'v.json');
      const env = { ...process.env, VAULT_FILE: vaultFile };

      await new Promise((resolve, reject) => {
        const child = execFile(binPath, ['add', 'token', '--stdin'], { env }, (error) =>
          error ? reject(error) : resolve(undefined),
        );
        child.stdin?.end('a-strong-passphrase\nthe-stored-secret\n');
      });

      const getResult = await new Promise((resolve, reject) => {
        const child = execFile(binPath, ['get', 'token'], { env }, (error, stdout) =>
          error ? reject(error) : resolve(stdout),
        );
        child.stdin?.end('a-strong-passphrase\n');
      });

      assert.equal(getResult, 'the-stored-secret\n');
    });
  });

  test('t7-f1: install, list with no vault, add, then get', async () => {
    await withTmpDir(async (tmp) => {
      const packOut = await execFileAsync('npm', ['pack', '--pack-destination', tmp], { cwd: REPO_ROOT });
      const tarballName = packOut.stdout.trim().split('\n').pop();
      const prefix = path.join(tmp, 'prefix');
      await fs.mkdir(prefix, { recursive: true });
      await execFileAsync('npm', ['install', '-g', '--prefix', prefix, path.join(tmp, tarballName)]);

      const binPath = path.join(prefix, 'bin', 'vault');
      const vaultFile = path.join(tmp, 'v.json');
      const env = { ...process.env, VAULT_FILE: vaultFile };

      const listBefore = await execFileAsync(binPath, ['list'], { env }).catch((error) => error);
      assert.equal(listBefore.code, 6);
      assert.match(String(listBefore.stderr ?? listBefore.stdout ?? ''), /no vault found/);

      await new Promise((resolve, reject) => {
        const child = execFile(binPath, ['add', 'npm-token', '--stdin'], { env }, (error) =>
          error ? reject(error) : resolve(undefined),
        );
        child.stdin?.end('a-strong-passphrase\nthe-token-value\n');
      });

      const stat = await fs.stat(vaultFile);
      assert.equal(stat.mode & 0o777, 0o600);

      const getResult = await new Promise((resolve, reject) => {
        const child = execFile(binPath, ['get', 'npm-token'], { env }, (error, stdout) =>
          error ? reject(error) : resolve(stdout),
        );
        child.stdin?.end('a-strong-passphrase\n');
      });

      assert.equal(getResult, 'the-token-value\n');
    });
  });
});
