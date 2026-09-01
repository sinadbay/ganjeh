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
 * t7-s1, t7-s2, t7-s3, t7-f1 and t7-a1 need a real, installable dist/bin/vault.js. That source
 * (`src/bin/vault.ts`, `src/cli.ts`, `src/commands/*`) previously only existed on the unmerged
 * `keel/t6-cli-cli-wiring-vault-add-get-list-with-exit-` branch; it has since landed on `develop` and
 * this branch has been merged up to include it, so the tests below exercise a real build end to end
 * rather than documenting the gap.
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

/** Packs a real tarball into `dir` and installs it globally under `dir/prefix`. Returns the `vault` bin path. */
async function packAndInstall(dir) {
  const packOut = await execFileAsync('npm', ['pack', '--pack-destination', dir], { cwd: REPO_ROOT });
  const tarballName = packOut.stdout.trim().split('\n').pop();
  const prefix = path.join(dir, 'prefix');
  await fs.mkdir(prefix, { recursive: true });
  await execFileAsync('npm', ['install', '-g', '--prefix', prefix, path.join(dir, tarballName)]);
  return path.join(prefix, 'bin', 'vault');
}

/**
 * Run the installed `vault` binary directly (not through the source tree), always closing stdin.
 *
 * Several commands (`get`, `list`, `add` against an existing vault) prompt for a passphrase before
 * doing anything else — even `list` against a missing vault prompts first and only then discovers
 * there is nothing to list (see `src/commands/list.ts`). A child process's stdin is left open by
 * default, so a call that never writes to or ends it would hang forever waiting for a keystroke that
 * never comes. `input` (default `''`) is always written and the stream is always ended, so a bare
 * `runVault(bin, ['list'], { env })` reads an empty passphrase and then fails on the real error (a
 * missing vault) instead of hanging.
 */
function runVault(binPath, args, { env = process.env, input = '' } = {}) {
  return new Promise((resolve) => {
    const child = execFile(binPath, args, { env }, (error, stdout, stderr) => {
      resolve({ code: error ? (error.code ?? 1) : 0, stdout, stderr, error });
    });
    child.stdin.end(input);
  });
}

// dist/ is a build artifact, not committed to the repository (see .npmignore's comment: package.json's
// "files" field is the real allowlist, and a stale, committed dist/ would drift from src/ the moment
// either changed without the other). The tests below need a freshly built dist/ to inspect, so build it
// once, here, before any of them run. A failure here is real and must fail loudly — there is no longer
// a known-missing-source reason to tolerate one.
before(async () => {
  await execFileAsync('npm', ['run', 'build'], { cwd: REPO_ROOT });
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
// build output — dist/bin/vault.js exists, is executable, and its shebang survives compilation
// ---------------------------------------------------------------------------

describe('build output', () => {
  test('dist/bin/vault.js exists, keeps its shebang, and is mode 0755', async () => {
    const binJs = path.join(REPO_ROOT, 'dist', 'bin', 'vault.js');
    const contents = await fs.readFile(binJs, 'utf8');
    assert.match(contents, /^#!\/usr\/bin\/env node\n/, 'compiled dist/bin/vault.js is missing its shebang line');

    const stat = await fs.stat(binJs);
    assert.equal(stat.mode & 0o777, 0o755, 'dist/bin/vault.js is not chmod 0755');
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
// ---------------------------------------------------------------------------

describe('npm pack contents (t7-s1, t7-a1)', () => {
  test('every packed path is allowed, and dist/bin/vault.js is present', async () => {
    const entry = await packDryRun();
    for (const file of entry.files) {
      assert.match(file.path, ALLOWED_PACK_PATH, `unexpected file in tarball: ${file.path}`);
    }
    assert.ok(
      entry.files.some((file) => file.path === 'dist/bin/vault.js'),
      'dist/bin/vault.js is not in the tarball',
    );
  });

  test('the tarball contains no .env, .npmrc, test/ or src/ file', async () => {
    const entry = await packDryRun();
    for (const file of entry.files) {
      assert.ok(!FORBIDDEN_PACK_PATH.test(file.path), `forbidden file in tarball: ${file.path}`);
    }
  });

  // t7-a1: a developer's machine can have stray files with real credentials
  // sitting right next to the source tree (a .env, a leftover .npmrc). The
  // two tests above only prove today's clean checkout packs cleanly — they
  // would not catch `files` silently widening to something like `"."`. This
  // one plants exactly the files the abuse case names, in the repo root, and
  // proves `files: ["dist"]` keeps them out regardless.
  test('t7-a1: stray .env and .npmrc files on disk are not swept into the tarball', async () => {
    const strayFiles = [path.join(REPO_ROOT, '.env'), path.join(REPO_ROOT, '.npmrc')];
    await Promise.all(strayFiles.map((file) => fs.writeFile(file, 'STRAY_SECRET=do-not-ship\n')));
    try {
      const entry = await packDryRun();
      for (const file of entry.files) {
        assert.ok(!FORBIDDEN_PACK_PATH.test(file.path), `stray file leaked into tarball: ${file.path}`);
      }
    } finally {
      await Promise.all(strayFiles.map((file) => fs.rm(file, { force: true })));
    }
  });
});

// ---------------------------------------------------------------------------
// t7-s2 / t7-s3 / t7-f1 — the packed tarball, installed and run
// ---------------------------------------------------------------------------

describe('installed binary (t7-s2, t7-s3, t7-f1)', () => {
  test('vault --version prints 0.1.0 from a global install of the packed tarball', async () => {
    await withTmpDir(async (tmp) => {
      const binPath = await packAndInstall(tmp);
      const result = await runVault(binPath, ['--version']);
      assert.equal(result.code, 0);
      assert.equal(result.stdout, '0.1.0\n');
    });
  });

  // DoD bullet 2 also requires `vault --help` to list all three commands —
  // distinct from the `--version` check above, and not otherwise named as
  // its own scenario ID, but it is still a checkbox this PR claims.
  test('vault --help lists add, get and list', async () => {
    await withTmpDir(async (tmp) => {
      const binPath = await packAndInstall(tmp);
      const result = await runVault(binPath, ['--help']);
      assert.equal(result.code, 0);
      for (const command of ['add', 'get', 'list']) {
        assert.ok(result.stdout.includes(command), `vault --help does not mention "${command}"`);
      }
    });
  });

  test('an install-then-add-then-get sequence returns the stored secret (t7-s3)', async () => {
    await withTmpDir(async (tmp) => {
      const binPath = await packAndInstall(tmp);
      const vaultFile = path.join(tmp, 'v.json');
      const env = { ...process.env, VAULT_FILE: vaultFile };

      const addResult = await runVault(binPath, ['add', 'token', '--stdin'], {
        env,
        input: 'a-strong-passphrase\nthe-stored-secret\n',
      });
      assert.equal(addResult.code, 0, `add failed: ${addResult.stderr}`);

      const getResult = await runVault(binPath, ['get', 'token'], {
        env,
        input: 'a-strong-passphrase\n',
      });
      assert.equal(getResult.code, 0, `get failed: ${getResult.stderr}`);
      assert.equal(getResult.stdout, 'the-stored-secret\n');
    });
  });

  test('t7-f1: install, list with no vault, add, then get, in under five seconds', async () => {
    await withTmpDir(async (tmp) => {
      const binPath = await packAndInstall(tmp);
      const vaultFile = path.join(tmp, 'v.json');
      const env = { ...process.env, VAULT_FILE: vaultFile };
      const start = Date.now();

      const listBefore = await runVault(binPath, ['list'], { env });
      assert.equal(listBefore.code, 6);
      assert.match(listBefore.stderr, /no vault found/);

      const addResult = await runVault(binPath, ['add', 'npm-token', '--stdin'], {
        env,
        input: 'a-strong-passphrase\nthe-token-value\n',
      });
      assert.equal(addResult.code, 0, `add failed: ${addResult.stderr}`);

      const stat = await fs.stat(vaultFile);
      assert.equal(stat.mode & 0o777, 0o600);

      const getResult = await runVault(binPath, ['get', 'npm-token'], {
        env,
        input: 'a-strong-passphrase\n',
      });
      assert.equal(getResult.code, 0, `get failed: ${getResult.stderr}`);
      assert.equal(getResult.stdout, 'the-token-value\n');

      assert.ok(Date.now() - start < 5000, 'list+add+get took 5 seconds or more');
    });
  });
});
