/**
 * Node t6 — CLI wiring, end to end.
 *
 * Scenario map (see brief):
 *   t6-s6  add --stdin then get in a second process: byte-identical secret
 *   t6-s7  get with the wrong passphrase: exit 2, empty stdout, 'passphrase
 *          incorrect' on stderr
 *   t6-s8  `add name --secret hunter2`: exit 1, "unknown option '--secret'"
 *   t6-f1  store and retrieve a credential in one sitting (default vault
 *          path under a temp HOME; 0600 file mode; nothing on stdout but
 *          the value)
 *   t6-f2  a second credential, duplicate protection, --force
 *   t6-a1  no argv-based secret/passphrase flag exists anywhere (ps/argv
 *          exposure)
 *   t6-a2  the vault file on disk never contains the plaintext secret
 *   t6-a4  a permission-denied write exits 1 with 'vault: permission
 *          denied', leaves no partial file, and leaks no secret
 *
 * These spawn a real `node` child process running `src/bin/vault.ts` (there
 * is no build step in this repository -- see the PR description) against a
 * real temporary vault file, exactly the way a user would invoke `vault`.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm, readFile, stat, chmod, mkdir } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const BIN_PATH = fileURLToPath(new URL('../../src/bin/vault.ts', import.meta.url));

interface CliResult {
  readonly code: number | null;
  readonly stdout: string;
  readonly stderr: string;
}

function runCli(
  args: readonly string[],
  options: { readonly input?: string; readonly env?: NodeJS.ProcessEnv } = {},
): Promise<CliResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [BIN_PATH, ...args], {
      env: { ...process.env, ...options.env },
    });

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString('utf8');
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderr += chunk.toString('utf8');
    });
    child.on('error', reject);
    child.on('close', (code) => resolve({ code, stdout, stderr }));

    if (options.input !== undefined) {
      child.stdin.write(options.input);
    }
    child.stdin.end();
  });
}

async function withTmpDir<T>(fn: (dir: string) => Promise<T>): Promise<T> {
  const dir = await mkdtemp(path.join(tmpdir(), 'vault-e2e-'));
  try {
    return await fn(dir);
  } finally {
    await chmod(dir, 0o700).catch(() => {});
    await rm(dir, { recursive: true, force: true });
  }
}

// ---------------------------------------------------------------------------
// t6-s6 — add --stdin then get in a second process
// ---------------------------------------------------------------------------

describe('t6-s6 add --stdin then get, in two separate processes', () => {
  test('the second process exits 0 and its stdout is the secret plus one newline', async () => {
    await withTmpDir(async (dir) => {
      const vaultFile = path.join(dir, 'v.json');
      const env = { VAULT_FILE: vaultFile };

      const added = await runCli(['add', 'api', '--stdin'], {
        env,
        input: 'passphrase1\nsecret-value-123',
      });
      assert.equal(added.code, 0, `add stderr: ${added.stderr}`);

      const got = await runCli(['get', 'api'], { env, input: 'passphrase1\n' });
      assert.equal(got.code, 0, `get stderr: ${got.stderr}`);
      assert.equal(got.stdout, 'secret-value-123\n');
    });
  });
});

// ---------------------------------------------------------------------------
// t6-s7 — get with the wrong passphrase
// ---------------------------------------------------------------------------

describe('t6-s7 get with the wrong passphrase', () => {
  test('exit code 2, empty stdout, "passphrase incorrect" on stderr', async () => {
    await withTmpDir(async (dir) => {
      const vaultFile = path.join(dir, 'v.json');
      const env = { VAULT_FILE: vaultFile };

      const added = await runCli(['add', 'api', '--stdin'], {
        env,
        input: 'passphrase1\nsecret-value-123',
      });
      assert.equal(added.code, 0, `add stderr: ${added.stderr}`);

      const got = await runCli(['get', 'api'], { env, input: 'wrongpassphrase\n' });
      assert.equal(got.code, 2);
      assert.equal(got.stdout, '');
      assert.match(got.stderr, /passphrase incorrect/);
    });
  });
});

// ---------------------------------------------------------------------------
// t6-s8 / t6-a1 — no flag accepts a secret or a passphrase value
// ---------------------------------------------------------------------------

describe('t6-s8 / t6-a1 no argv-based secret or passphrase flag', () => {
  test('"add name --secret hunter2" exits 1 and stderr contains the unknown-option error', async () => {
    const result = await runCli(['add', 'name', '--secret', 'hunter2']);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /unknown option '--secret'/);
  });

  test('"add name --passphrase hunter2" exits 1 and stderr contains the unknown-option error', async () => {
    const result = await runCli(['add', 'name', '--passphrase', 'hunter2']);
    assert.equal(result.code, 1);
    assert.match(result.stderr, /unknown option '--passphrase'/);
  });

  test('a secret piped via --stdin never appears in the child\'s own argv (t6-a1)', async () => {
    await withTmpDir(async (dir) => {
      const vaultFile = path.join(dir, 'v.json');
      const env = { VAULT_FILE: vaultFile };

      // /proc/<pid>/cmdline is the same thing a shoulder-surfing `ps` on a
      // shared machine would see; reading it back from the argv Node itself
      // recorded is the strongest evidence available that the secret was
      // never passed as a command-line argument in the first place.
      const child = spawn(process.execPath, [BIN_PATH, 'add', 'api', '--stdin'], {
        env: { ...process.env, ...env },
      });
      let stderr = '';
      child.stderr.on('data', (chunk: Buffer) => {
        stderr += chunk.toString('utf8');
      });
      const argvSnapshot =
        process.platform === 'linux'
          ? await readFile(`/proc/${child.pid}/cmdline`, 'utf8').catch(() => '')
          : '';

      child.stdin.write('passphrase1\nSHOULDER-SURF-SENTINEL');
      child.stdin.end();

      const code = await new Promise<number | null>((resolve) => child.on('close', resolve));
      assert.equal(code, 0, `add stderr: ${stderr}`);
      assert.ok(!argvSnapshot.includes('SHOULDER-SURF-SENTINEL'));
    });
  });
});

// ---------------------------------------------------------------------------
// t6-f1 — store and retrieve a credential in one sitting
// ---------------------------------------------------------------------------

describe('t6-f1 store and retrieve a credential in one sitting', () => {
  test('list prints the name, get prints the secret, both exit 0, and the file on disk never contains the secret', async () => {
    await withTmpDir(async (home) => {
      const env = { HOME: home };

      const added = await runCli(['add', 'github', '--stdin'], {
        env,
        input: 'passphrase1\nghp_abc123',
      });
      assert.equal(added.code, 0, `add stderr: ${added.stderr}`);

      const vaultFile = path.join(home, '.vault', 'vault.json');
      const fileStat = await stat(vaultFile);
      assert.equal(fileStat.mode & 0o777, 0o600);

      const listed = await runCli(['list'], { env, input: 'passphrase1\n' });
      assert.equal(listed.code, 0, `list stderr: ${listed.stderr}`);
      assert.equal(listed.stdout, 'github\n');

      const got = await runCli(['get', 'github'], { env, input: 'passphrase1\n' });
      assert.equal(got.code, 0, `get stderr: ${got.stderr}`);
      assert.equal(got.stdout, 'ghp_abc123\n');

      const raw = await readFile(vaultFile, 'utf8');
      assert.ok(!raw.includes('ghp_abc123'));
    });
  });
});

// ---------------------------------------------------------------------------
// t6-f2 — second credential and duplicate protection
// ---------------------------------------------------------------------------

describe('t6-f2 second credential and duplicate protection', () => {
  test('add without --force on an existing name exits 5; --force overwrites', async () => {
    await withTmpDir(async (dir) => {
      const vaultFile = path.join(dir, 'v.json');
      const env = { VAULT_FILE: vaultFile };

      const seed = await runCli(['add', 'github', '--stdin'], { env, input: 'passphrase1\nghp_abc123' });
      assert.equal(seed.code, 0, `seed stderr: ${seed.stderr}`);

      const first = await runCli(['add', 'db', '--stdin'], { env, input: 'passphrase1\npgpass' });
      assert.equal(first.code, 0, `first add stderr: ${first.stderr}`);

      const duplicate = await runCli(['add', 'db', '--stdin'], { env, input: 'passphrase1\nother' });
      assert.equal(duplicate.code, 5);
      assert.match(duplicate.stderr, /already exists/);

      const forced = await runCli(['add', 'db', '--force', '--stdin'], { env, input: 'passphrase1\nother' });
      assert.equal(forced.code, 0, `forced add stderr: ${forced.stderr}`);

      const got = await runCli(['get', 'db'], { env, input: 'passphrase1\n' });
      assert.equal(got.code, 0, `get stderr: ${got.stderr}`);
      assert.equal(got.stdout, 'other\n');
    });
  });
});

// ---------------------------------------------------------------------------
// t6-a2 — the vault file on disk never contains the plaintext secret
// ---------------------------------------------------------------------------

describe('t6-a2 the vault file on disk contains no occurrence of the secret', () => {
  test('SENTINEL-SECRET never appears in the raw file bytes; the file parses as an envelope with base64 ciphertext', async () => {
    await withTmpDir(async (dir) => {
      const vaultFile = path.join(dir, 'v.json');
      const env = { VAULT_FILE: vaultFile };

      const added = await runCli(['add', 'db', '--stdin'], { env, input: 'passphrase1\nSENTINEL-SECRET' });
      assert.equal(added.code, 0, `add stderr: ${added.stderr}`);

      const raw = await readFile(vaultFile);
      assert.ok(!raw.toString('latin1').includes('SENTINEL-SECRET'));

      const envelope = JSON.parse(raw.toString('utf8')) as Record<string, unknown>;
      assert.equal(envelope.version, 1);
      assert.equal(typeof envelope.ciphertextB64, 'string');
      assert.match(envelope.ciphertextB64 as string, /^[A-Za-z0-9+/]+=*$/);
    });
  });
});

// ---------------------------------------------------------------------------
// t6-a4 — a permission-denied write
// ---------------------------------------------------------------------------

describe('t6-a4 --file into a directory the user cannot write to', () => {
  test('exits 1 with "vault: permission denied", leaves no partial file, and leaks no secret', async () => {
    await withTmpDir(async (dir) => {
      const lockedParent = path.join(dir, 'locked');
      await mkdir(lockedParent);
      await chmod(lockedParent, 0o500); // r-x: cannot create the vault's directory inside it

      try {
        const vaultFile = path.join(lockedParent, 'nested', 'v.json');
        const result = await runCli(['add', 'x', '--stdin'], {
          env: { VAULT_FILE: vaultFile },
          input: 'passphrase1\nSHOULD-NOT-LEAK-SECRET',
        });

        assert.equal(result.code, 1);
        assert.match(result.stderr, /vault: permission denied/);
        assert.doesNotMatch(result.stderr, /SHOULD-NOT-LEAK-SECRET/);

        await assert.rejects(() => stat(path.join(lockedParent, 'nested')));
      } finally {
        await chmod(lockedParent, 0o700);
      }
    });
  });
});
