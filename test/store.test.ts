/**
 * Node t3 — encrypted vault file store (path resolution, atomic 0600 writes).
 *
 * Scenario map (see brief):
 *   t3-s1  save then load round-trips the envelope, creating the parent dir
 *   t3-s2  save sets file mode 0o600 and directory mode 0o700 (POSIX)
 *   t3-s3  a save whose rename throws leaves the old file untouched, no tmp file left
 *   t3-s4  the temp file is opened at mode 0o600 up front, never chmod-ed after
 *   t3-s5  load on a missing file -> VaultNotFoundError (exit 6); exists() false
 *   t3-s6  load on non-JSON bytes -> VaultCorruptError (exit 3), path named in message
 *   t3-s7  resolveVaultPath -- see test/paths.test.ts
 *   t3-a1  save refuses to write through a symlinked target
 *   t3-a2  vault file/dir permissions exclude group/other bits
 *   t3-a3  a crash between writing and renaming leaves no ciphertext copy behind
 *   t3-a4  a vault file whose JSON parses to a non-object -> VaultCorruptError
 *
 * `src/types.ts` -- described in this node's brief as an already-landed
 * prerequisite carrying the shared `VaultStore` interface, `EncryptedEnvelope`
 * type and error taxonomy -- does not exist anywhere in this repository's
 * history (checked main, develop and every node branch). `src/store.ts`
 * declares local stand-ins with the shapes and exit codes the brief
 * specifies; see the PR description for what that means for integration.
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';
import os from 'node:os';
import * as realFs from 'node:fs/promises';

import {
  createStore,
  VaultError,
  VaultNotFoundError,
  VaultCorruptError,
  UnsafeVaultPathError,
} from '../src/store.ts';

const isWindows = process.platform === 'win32';

async function withTmpDir(fn) {
  const dir = await realFs.mkdtemp(path.join(os.tmpdir(), 'vault-store-test-'));
  try {
    return await fn(dir);
  } finally {
    await realFs.rm(dir, { recursive: true, force: true });
  }
}

function sampleEnvelope(extra = {}) {
  return {
    version: 1,
    cipher: 'aes-256-gcm',
    kdf: { name: 'scrypt', n: 131072, r: 8, p: 1 },
    saltB64: Buffer.from('0123456789abcdef').toString('base64'),
    nonceB64: Buffer.from('012345678901').toString('base64'),
    ciphertextB64: Buffer.from('ciphertext-and-tag-bytes-here!!').toString('base64'),
    ...extra,
  };
}

/**
 * An fs deps object that proxies every call through to the real
 * `fs/promises`, except that `rename`/the handle's `sync` can be swapped for
 * a throwing implementation. `log` records `[method, ...args]` per call so a
 * test can assert both the value passed to `open` and the order calls
 * happened in.
 */
function makeSpyFs({ renameImpl, syncImpl } = {}) {
  const log = [];
  const fs = {
    readFile: (...args) => {
      log.push(['readFile', ...args]);
      return realFs.readFile(...args);
    },
    mkdir: (...args) => {
      log.push(['mkdir', ...args]);
      return realFs.mkdir(...args);
    },
    chmod: (...args) => {
      log.push(['chmod', ...args]);
      return realFs.chmod(...args);
    },
    lstat: (...args) => {
      log.push(['lstat', ...args]);
      return realFs.lstat(...args);
    },
    stat: (...args) => {
      log.push(['stat', ...args]);
      return realFs.stat(...args);
    },
    unlink: (...args) => {
      log.push(['unlink', ...args]);
      return realFs.unlink(...args);
    },
    rename: (...args) => {
      log.push(['rename', ...args]);
      if (renameImpl) return renameImpl(...args);
      return realFs.rename(...args);
    },
    open: async (targetPath, flags, mode) => {
      log.push(['open', targetPath, flags, mode]);
      const handle = await realFs.open(targetPath, flags, mode);
      return {
        writeFile: async (data) => {
          log.push(['writeFile']);
          return handle.writeFile(data);
        },
        sync: async () => {
          log.push(['sync']);
          if (syncImpl) return syncImpl();
          return handle.sync();
        },
        close: async () => {
          log.push(['close']);
          return handle.close();
        },
      };
    },
  };
  return { fs, log };
}

describe('t3-s1 round-trip', () => {
  test('save then load returns a deep-equal envelope and creates the parent directory', () =>
    withTmpDir(async (tmp) => {
      const filePath = path.join(tmp, 'sub', 'vault.json');
      const store = createStore(filePath);
      const envelope = sampleEnvelope();

      await store.save(envelope);
      const loaded = await store.load();

      assert.deepEqual(loaded, envelope);
      const dirStat = await realFs.stat(path.join(tmp, 'sub'));
      assert.ok(dirStat.isDirectory());
    }));

  test('exists() is true after a successful save', () =>
    withTmpDir(async (tmp) => {
      const filePath = path.join(tmp, 'vault.json');
      const store = createStore(filePath);
      await store.save(sampleEnvelope());
      assert.equal(await store.exists(), true);
    }));

  test('exists() is false when the target path is a directory, not a regular file', () =>
    withTmpDir(async (tmp) => {
      const dirAsFilePath = path.join(tmp, 'vault.json');
      await realFs.mkdir(dirAsFilePath);
      const store = createStore(dirAsFilePath);
      assert.equal(await store.exists(), false);
    }));

  test('a second save atomically replaces an existing regular vault file', () =>
    withTmpDir(async (tmp) => {
      const filePath = path.join(tmp, 'vault.json');
      const store = createStore(filePath);

      await store.save(sampleEnvelope({ ciphertextB64: 'first' }));
      await store.save(sampleEnvelope({ ciphertextB64: 'second' }));

      const loaded = await store.load();
      assert.equal(loaded.ciphertextB64, 'second');

      const entries = await realFs.readdir(tmp);
      assert.deepEqual(entries, ['vault.json']);
    }));
});

test('t3-s2 save sets file mode 0o600 and directory mode 0o700', { skip: isWindows }, () =>
  withTmpDir(async (tmp) => {
    const filePath = path.join(tmp, 'sub', 'vault.json');
    const store = createStore(filePath);
    await store.save(sampleEnvelope());

    const fileStat = await realFs.stat(filePath);
    const dirStat = await realFs.stat(path.join(tmp, 'sub'));
    assert.equal(fileStat.mode & 0o777, 0o600);
    assert.equal(dirStat.mode & 0o777, 0o700);
  }));

test('t3-s3 a save whose rename throws leaves the previous bytes untouched and no tmp file behind', () =>
  withTmpDir(async (tmp) => {
    const filePath = path.join(tmp, 'vault.json');
    await realFs.writeFile(filePath, 'OLD');

    const { fs } = makeSpyFs({
      renameImpl: async () => {
        throw Object.assign(new Error('simulated EIO on rename'), { code: 'EIO' });
      },
    });
    const store = createStore(filePath, { fs });

    await assert.rejects(() => store.save(sampleEnvelope()), /EIO/);

    const contents = await realFs.readFile(filePath, 'utf8');
    assert.equal(contents, 'OLD');

    const entries = await realFs.readdir(tmp);
    assert.ok(!entries.some((name) => /\.tmp-/.test(name)), `unexpected tmp entries: ${entries}`);
  }));

test('t3-s4 the temp file is opened at mode 0o600 up front, never chmod-ed afterwards', () =>
  withTmpDir(async (tmp) => {
    const filePath = path.join(tmp, 'vault.json');
    const { fs, log } = makeSpyFs();
    const store = createStore(filePath, { fs });

    await store.save(sampleEnvelope());

    const openCall = log.find((entry) => entry[0] === 'open');
    assert.ok(openCall, 'expected an open() call');
    const [, tmpPath, , mode] = openCall;
    assert.equal(mode, 0o600);

    const openIndex = log.indexOf(openCall);
    const writeIndex = log.findIndex((entry) => entry[0] === 'writeFile');
    assert.ok(openIndex >= 0 && writeIndex > openIndex, 'open must precede the write');

    // The directory's mode is enforced with an explicit chmod (see the
    // pre-existing-directory test below), but the vault *file*'s permissions
    // must come only from the mode given to `open`, never a chmod on the
    // file itself or on the temp path that becomes it.
    const fileChmods = log.filter(
      (entry) => entry[0] === 'chmod' && (entry[1] === filePath || entry[1] === tmpPath),
    );
    assert.equal(fileChmods.length, 0, 'save must never chmod the vault file or its temp path');
  }));

describe('t3-s5 missing vault file', () => {
  test('load rejects with VaultNotFoundError, exitCode 6', () =>
    withTmpDir(async (tmp) => {
      const filePath = path.join(tmp, 'vault.json');
      const store = createStore(filePath);

      await assert.rejects(
        () => store.load(),
        (err) => {
          assert.ok(err instanceof VaultNotFoundError);
          assert.equal(err.exitCode, 6);
          return true;
        },
      );
    }));

  test('exists() resolves to false', () =>
    withTmpDir(async (tmp) => {
      const store = createStore(path.join(tmp, 'vault.json'));
      assert.equal(await store.exists(), false);
    }));
});

test('t3-s6 load on non-JSON bytes rejects with VaultCorruptError naming the file path', () =>
  withTmpDir(async (tmp) => {
    const filePath = path.join(tmp, 'vault.json');
    await realFs.writeFile(filePath, 'not json at all');
    const store = createStore(filePath);

    await assert.rejects(
      () => store.load(),
      (err) => {
        assert.ok(err instanceof VaultCorruptError);
        assert.equal(err.exitCode, 3);
        assert.ok(err.message.includes(filePath), `message should name ${filePath}: ${err.message}`);
        return true;
      },
    );
  }));

test('t3-a1 save refuses to write through a symlinked target, leaving the symlink destination unmodified', { skip: isWindows }, () =>
  withTmpDir(async (tmp) => {
    const victimPath = path.join(tmp, 'authorized_keys');
    const victimContents = 'ssh-ed25519 AAAAattacker-should-never-see-this\n';
    await realFs.writeFile(victimPath, victimContents, { mode: 0o600 });
    const victimStatBefore = await realFs.stat(victimPath);

    const linkPath = path.join(tmp, 'vault.json');
    await realFs.symlink(victimPath, linkPath);

    const store = createStore(linkPath);
    await assert.rejects(
      () => store.save(sampleEnvelope()),
      (err) => {
        assert.ok(err instanceof UnsafeVaultPathError);
        assert.equal(err.exitCode, 3);
        return true;
      },
    );

    const victimContentsAfter = await realFs.readFile(victimPath, 'utf8');
    const victimStatAfter = await realFs.stat(victimPath);
    assert.equal(victimContentsAfter, victimContents);
    assert.equal(victimStatAfter.mtimeMs, victimStatBefore.mtimeMs);

    const linkStat = await realFs.lstat(linkPath);
    assert.ok(linkStat.isSymbolicLink(), 'the symlink itself must also be left in place');
  }));

test('save tightens an already-existing, loosely-permissioned vault directory to 0o700', { skip: isWindows }, () =>
  withTmpDir(async (tmp) => {
    const dir = path.join(tmp, 'sub');
    await realFs.mkdir(dir, { mode: 0o755 });
    const filePath = path.join(dir, 'vault.json');
    const store = createStore(filePath);

    await store.save(sampleEnvelope());

    const dirStat = await realFs.stat(dir);
    assert.equal(dirStat.mode & 0o777, 0o700);
  }));

test('t3-a2 vault file and directory permissions exclude every group/other bit', { skip: isWindows }, () =>
  withTmpDir(async (tmp) => {
    const filePath = path.join(tmp, 'sub', 'vault.json');
    const store = createStore(filePath);
    await store.save(sampleEnvelope());

    const fileStat = await realFs.stat(filePath);
    const dirStat = await realFs.stat(path.join(tmp, 'sub'));

    assert.equal(fileStat.mode & 0o777, 0o600);
    assert.equal(dirStat.mode & 0o777, 0o700);
    assert.equal(fileStat.mode & 0o077, 0, 'no group/other bits on the vault file');
    assert.equal(dirStat.mode & 0o077, 0, 'no group/other bits on the vault directory');
  }));

test('t3-a3 a crash between writing and renaming leaves no ciphertext copy behind', () =>
  withTmpDir(async (tmp) => {
    const filePath = path.join(tmp, 'vault.json');
    const { fs } = makeSpyFs({
      syncImpl: async () => {
        throw Object.assign(new Error('simulated crash before fsync completes'), { code: 'EIO' });
      },
    });
    const store = createStore(filePath, { fs });

    await assert.rejects(() => store.save(sampleEnvelope()));

    const entries = await realFs.readdir(tmp);
    assert.ok(!entries.some((name) => /\.tmp-/.test(name)), `unexpected tmp entries: ${entries}`);
    assert.equal(await store.exists(), false);
  }));

test('t3-a4 a vault file whose JSON parses to a non-object rejects with VaultCorruptError', () =>
  withTmpDir(async (tmp) => {
    for (const bytes of ['42', 'null']) {
      const filePath = path.join(tmp, `vault-${bytes}.json`);
      await realFs.writeFile(filePath, bytes);
      const store = createStore(filePath);
      await assert.rejects(
        () => store.load(),
        (err) => {
          assert.ok(err instanceof VaultCorruptError, `expected VaultCorruptError for body ${bytes}`);
          assert.equal(err.exitCode, 3);
          return true;
        },
      );
    }
  }));

test('createStore rejects a relative filePath rather than risking a chmod on an unrelated directory', () => {
  assert.throws(() => createStore('relative/vault.json'), TypeError);
});

describe('error taxonomy', () => {
  test('each store error carries the documented exit code and descends from VaultError', () => {
    assert.equal(new VaultNotFoundError('/x').exitCode, 6);
    assert.equal(new VaultCorruptError('/x').exitCode, 3);
    assert.equal(new UnsafeVaultPathError('/x').exitCode, 3);
    assert.ok(new VaultNotFoundError('/x') instanceof VaultError);
    assert.ok(new VaultCorruptError('/x') instanceof VaultError);
    assert.ok(new UnsafeVaultPathError('/x') instanceof VaultError);
    assert.ok(new VaultNotFoundError('/x') instanceof Error);
  });
});
