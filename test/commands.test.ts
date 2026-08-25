/**
 * Node t6 — CLI wiring (add/get/list, exit codes).
 *
 * Scenario map (see brief):
 *   t6-s1  add against an empty (nonexistent) vault: store.save gets the
 *          envelope cipher.seal returned, and the sealed plaintext decodes
 *          to the new entry
 *   t6-s2  get, with cipher.open throwing WrongPassphraseError -> exit 2,
 *          nothing on stdout
 *   t6-s3  list with two entries -> sorted, one per stdout line, exit 0
 *   t6-s4  list with no entries -> stdout empty, 'vault is empty' on
 *          stderr, exit 0
 *   t6-s5  get with no vault file -> exit 6, 'no vault found' on stderr
 *   t6-a3  a hostile lookup name (path-traversal-shaped, or carrying an ANSI
 *          escape) is rejected before store or prompt are ever touched
 *   t6-a5  an unexpected internal exception prints one generic line and no
 *          stack unless VAULT_DEBUG=1, and never echoes the passphrase
 *
 * These are unit tests: `store`/`cipher`/`prompt` are all fakes injected
 * through `run`'s second parameter, so nothing here touches a real file,
 * terminal or subprocess. End-to-end behaviour against a real vault file and
 * a real spawned process is in `test/e2e/cli.e2e.test.ts`.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { Writable } from 'node:stream';

import { run } from '../src/cli.ts';
import type { CommandCipher, CommandPrompt, RunDeps } from '../src/cli.ts';
import type { VaultStore, EncryptedEnvelope } from '../src/store.ts';
import { VaultNotFoundError, WrongPassphraseError, InvalidNameError } from '../src/types.ts';
import { decodeVault, emptyVault, encodeVault, addEntry } from '../src/vault.ts';

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/** A `Writable` that records every chunk written to it as text. */
function makeSink() {
  const chunks: string[] = [];
  const stream = new Writable({
    write(chunk, _encoding, callback) {
      chunks.push(chunk.toString('utf8'));
      callback();
    },
  });
  return Object.assign(stream, { text: () => chunks.join('') });
}

/**
 * A fake `VaultStore` backed by a plain in-memory slot rather than a file.
 * `initial` is the envelope already "on disk", or `undefined` for no vault
 * file at all -- `exists()`/`load()` follow the same contract `store.ts`'s
 * real implementation does for that case (`load()` on a missing file throws
 * `VaultNotFoundError`).
 */
function makeFakeStore(initial: EncryptedEnvelope | undefined): VaultStore & { saveCalls: EncryptedEnvelope[] } {
  let envelope = initial;
  const saveCalls: EncryptedEnvelope[] = [];
  return {
    saveCalls,
    async exists() {
      return envelope !== undefined;
    },
    async load() {
      if (envelope === undefined) {
        throw new VaultNotFoundError('/fake/vault.json');
      }
      return envelope;
    },
    async save(next) {
      saveCalls.push(next);
      envelope = next;
    },
  };
}

/** A store whose every method fails the test if called -- proves a code path never touches it. */
function makeUntouchableStore(): VaultStore {
  return {
    exists: () => assert.fail('store.exists() should not have been called'),
    load: () => assert.fail('store.load() should not have been called'),
    save: () => assert.fail('store.save() should not have been called'),
  };
}

/** A fake `CommandCipher` that does not encrypt: it round-trips plaintext through base64 in the envelope. */
function makeFakeCipher(): CommandCipher {
  return {
    async seal(plaintext) {
      return { version: 1, plaintextB64: plaintext.toString('base64') };
    },
    async open(envelope) {
      const plaintextB64 = (envelope as { plaintextB64?: unknown }).plaintextB64;
      if (typeof plaintextB64 !== 'string') {
        throw new Error('fake envelope missing plaintextB64');
      }
      return Buffer.from(plaintextB64, 'base64');
    },
  };
}

/** A `CommandCipher` whose `open` always rejects with `err`. */
function makeThrowingOpenCipher(err: unknown): CommandCipher {
  return {
    seal: () => assert.fail('cipher.seal() should not have been called'),
    open: () => Promise.reject(err),
  };
}

/** A `CommandPrompt` returning canned values; each method fails the test if called without one configured. */
function makeFakePrompt(canned: Partial<Record<keyof CommandPrompt, string>>): CommandPrompt {
  return {
    readHidden: async () => {
      if (canned.readHidden === undefined) assert.fail('prompt.readHidden() should not have been called');
      return canned.readHidden;
    },
    readNewPassphrase: async () => {
      if (canned.readNewPassphrase === undefined) assert.fail('prompt.readNewPassphrase() should not have been called');
      return canned.readNewPassphrase;
    },
    readSecret: async () => {
      if (canned.readSecret === undefined) assert.fail('prompt.readSecret() should not have been called');
      return canned.readSecret;
    },
  };
}

function makeUntouchablePrompt(): CommandPrompt {
  return {
    readHidden: () => assert.fail('prompt.readHidden() should not have been called'),
    readNewPassphrase: () => assert.fail('prompt.readNewPassphrase() should not have been called'),
    readSecret: () => assert.fail('prompt.readSecret() should not have been called'),
  };
}

function runWith(args: readonly string[], overrides: Partial<RunDeps>) {
  const stdout = overrides.stdout ?? makeSink();
  const stderr = overrides.stderr ?? makeSink();
  return run(args, { ...overrides, stdout, stderr }).then((code) => ({
    code,
    stdout: (stdout as ReturnType<typeof makeSink>).text(),
    stderr: (stderr as ReturnType<typeof makeSink>).text(),
  }));
}

// ---------------------------------------------------------------------------
// t6-s1 — add against an empty vault
// ---------------------------------------------------------------------------

describe('t6-s1 add handler against an empty vault', () => {
  test('store.save is called once with cipher.seal\'s envelope, and it decodes to entries.db.secret === "p@ss"', async () => {
    const store = makeFakeStore(undefined);
    const cipher = makeFakeCipher();
    const prompt = makeFakePrompt({ readNewPassphrase: 'passphrase1', readSecret: 'p@ss' });

    const result = await runWith(['add', 'db'], { store, cipher, prompt });

    assert.equal(result.code, 0);
    assert.equal(store.saveCalls.length, 1);

    const saved = store.saveCalls[0];
    assert.ok(saved);
    const plaintextB64 = (saved as { plaintextB64?: unknown }).plaintextB64;
    assert.equal(typeof plaintextB64, 'string');

    const vault = decodeVault(Buffer.from(plaintextB64 as string, 'base64'));
    assert.equal(vault.entries.db?.secret, 'p@ss');
  });

  test('an existing vault instead reads the passphrase via readHidden, not readNewPassphrase', async () => {
    const seedPlaintext = encodeVault(emptyVault());
    const store = makeFakeStore({ version: 1, plaintextB64: seedPlaintext.toString('base64') });
    const cipher = makeFakeCipher();
    const prompt = makeFakePrompt({ readHidden: 'passphrase1', readSecret: 'other-secret' });

    const result = await runWith(['add', 'x'], { store, cipher, prompt });

    assert.equal(result.code, 0);
    assert.equal(store.saveCalls.length, 1);
  });
});

// ---------------------------------------------------------------------------
// t6-s2 — get with the wrong passphrase
// ---------------------------------------------------------------------------

describe('t6-s2 get with a cipher that rejects with WrongPassphraseError', () => {
  test('exit code 2, empty stdout', async () => {
    const store = makeFakeStore({ version: 1, plaintextB64: '' });
    const cipher = makeThrowingOpenCipher(new WrongPassphraseError());
    const prompt = makeFakePrompt({ readHidden: 'whatever-was-typed' });

    const result = await runWith(['get', 'db'], { store, cipher, prompt });

    assert.equal(result.code, 2);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /passphrase incorrect/);
  });
});

// ---------------------------------------------------------------------------
// t6-s3 — list with two entries
// ---------------------------------------------------------------------------

describe('t6-s3 list with entries "b" and "a"', () => {
  test('stdout is "a\\nb\\n", exit code 0', async () => {
    let vault = emptyVault();
    vault = addEntry(vault, 'b', 'secret-b', { now: () => '2026-01-01T00:00:00.000Z' });
    vault = addEntry(vault, 'a', 'secret-a', { now: () => '2026-01-01T00:00:00.000Z' });
    const plaintext = encodeVault(vault);

    const store = makeFakeStore({ version: 1, plaintextB64: plaintext.toString('base64') });
    const cipher = makeFakeCipher();
    const prompt = makeFakePrompt({ readHidden: 'passphrase1' });

    const result = await runWith(['list'], { store, cipher, prompt });

    assert.equal(result.code, 0);
    assert.equal(result.stdout, 'a\nb\n');
  });
});

// ---------------------------------------------------------------------------
// t6-s4 — list with no entries
// ---------------------------------------------------------------------------

describe('t6-s4 list with no entries', () => {
  test('stdout is empty, stderr contains "vault is empty", exit code 0', async () => {
    const plaintext = encodeVault(emptyVault());
    const store = makeFakeStore({ version: 1, plaintextB64: plaintext.toString('base64') });
    const cipher = makeFakeCipher();
    const prompt = makeFakePrompt({ readHidden: 'passphrase1' });

    const result = await runWith(['list'], { store, cipher, prompt });

    assert.equal(result.code, 0);
    assert.equal(result.stdout, '');
    assert.match(result.stderr, /vault is empty/);
  });
});

// ---------------------------------------------------------------------------
// t6-s5 — get with no vault file present
// ---------------------------------------------------------------------------

describe('t6-s5 get with no vault file present', () => {
  test('exit code 6, stderr contains "no vault found"', async () => {
    const store = makeFakeStore(undefined);
    const cipher = makeFakeCipher();
    const prompt = makeFakePrompt({ readHidden: 'whatever' });

    const result = await runWith(['get', 'x'], { store, cipher, prompt });

    assert.equal(result.code, 6);
    assert.match(result.stderr, /no vault found/);
  });
});

// ---------------------------------------------------------------------------
// t6-a3 — hostile lookup names are rejected before any I/O
// ---------------------------------------------------------------------------

describe('t6-a3 hostile get names', () => {
  test('a path-traversal-shaped name exits 1 with an assertValidName message; store and prompt are never touched', async () => {
    const store = makeUntouchableStore();
    const cipher = makeFakeCipher();
    const prompt = makeUntouchablePrompt();

    const result = await runWith(['get', '../../etc/passwd'], { store, cipher, prompt });

    assert.equal(result.code, 1);
    assert.match(result.stderr, /invalid entry name/);
  });

  test('a name carrying an ANSI escape exits 1 with an assertValidName message; store and prompt are never touched', async () => {
    const store = makeUntouchableStore();
    const cipher = makeFakeCipher();
    const prompt = makeUntouchablePrompt();

    // \u001b is ESC (0x1b), written as a JS escape rather than a literal byte
    // so this file stays text and the diff stays readable (matches t4-a2's fixture).
    const hostile = 'name\u001b[2J';
    const result = await runWith(['get', hostile], { store, cipher, prompt });

    assert.equal(result.code, 1);
    assert.match(result.stderr, /invalid entry name/);
  });

  test('directly: assertValidName is what the CLI relies on (sanity check on the fixture)', () => {
    assert.throws(() => {
      throw new InvalidNameError('../../etc/passwd');
    }, InvalidNameError);
  });
});

// ---------------------------------------------------------------------------
// t6-a5 — an unexpected internal exception
// ---------------------------------------------------------------------------

describe('t6-a5 unexpected internal exception during get', () => {
  const PASSPHRASE_SENTINEL = 'do-not-print-me-passphrase-9f3c';

  test('VAULT_DEBUG unset: one generic line, no stack, no passphrase', async () => {
    const previous = process.env.VAULT_DEBUG;
    delete process.env.VAULT_DEBUG;
    try {
      const store = makeFakeStore({ version: 1, plaintextB64: '' });
      const cipher = makeThrowingOpenCipher(new Error('internal failure: boom'));
      const prompt = makeFakePrompt({ readHidden: PASSPHRASE_SENTINEL });

      const result = await runWith(['get', 'db'], { store, cipher, prompt });

      assert.equal(result.code, 1);
      assert.equal(result.stderr.split('\n').filter((line) => line.length > 0).length, 1);
      assert.doesNotMatch(result.stderr, /boom/);
      assert.doesNotMatch(result.stderr, new RegExp(PASSPHRASE_SENTINEL));
    } finally {
      if (previous === undefined) delete process.env.VAULT_DEBUG;
      else process.env.VAULT_DEBUG = previous;
    }
  });

  test('VAULT_DEBUG=1: the stack is printed, and it still contains no passphrase', async () => {
    const previous = process.env.VAULT_DEBUG;
    process.env.VAULT_DEBUG = '1';
    try {
      const store = makeFakeStore({ version: 1, plaintextB64: '' });
      const cipher = makeThrowingOpenCipher(new Error('internal failure: boom'));
      const prompt = makeFakePrompt({ readHidden: PASSPHRASE_SENTINEL });

      const result = await runWith(['get', 'db'], { store, cipher, prompt });

      assert.equal(result.code, 1);
      assert.match(result.stderr, /boom/);
      assert.doesNotMatch(result.stderr, new RegExp(PASSPHRASE_SENTINEL));
    } finally {
      if (previous === undefined) delete process.env.VAULT_DEBUG;
      else process.env.VAULT_DEBUG = previous;
    }
  });
});

// ---------------------------------------------------------------------------
// No flag accepts a secret or a passphrase value
// ---------------------------------------------------------------------------

describe('no CLI flag accepts a secret or passphrase value', () => {
  test('--secret is rejected as an unknown option, exit code 1', async () => {
    const result = await runWith(['add', 'n', '--secret', 's'], {
      store: makeUntouchableStore(),
      cipher: makeFakeCipher(),
      prompt: makeUntouchablePrompt(),
    });
    assert.equal(result.code, 1);
    assert.match(result.stderr, /unknown option '--secret'/);
  });

  test('--passphrase is rejected as an unknown option, exit code 1', async () => {
    const result = await runWith(['add', 'n', '--passphrase', 'p'], {
      store: makeUntouchableStore(),
      cipher: makeFakeCipher(),
      prompt: makeUntouchablePrompt(),
    });
    assert.equal(result.code, 1);
    assert.match(result.stderr, /unknown option '--passphrase'/);
  });
});

// ---------------------------------------------------------------------------
// --help / --version
// ---------------------------------------------------------------------------

describe('--help and --version', () => {
  test('--help lists add, get and list; exit code 0', async () => {
    const result = await runWith(['--help'], {});
    assert.equal(result.code, 0);
    assert.match(result.stdout, /\badd\b/);
    assert.match(result.stdout, /\bget\b/);
    assert.match(result.stdout, /\blist\b/);
  });

  test('--version prints the package.json version; exit code 0', async () => {
    const pkg = JSON.parse(
      await import('node:fs/promises').then((fs) => fs.readFile(new URL('../package.json', import.meta.url), 'utf8')),
    ) as { version: string };

    const result = await runWith(['--version'], {});
    assert.equal(result.code, 0);
    assert.equal(result.stdout, `${pkg.version}\n`);
  });
});
