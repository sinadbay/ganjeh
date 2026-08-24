/**
 * Node t4 — vault data model: add/get/list and the plaintext codec.
 *
 * Scenario map (see brief):
 *   t4-s1  addEntry populates a fresh entry and does not mutate its input
 *   t4-s2  adding an existing name without overwrite -> EntryExistsError
 *   t4-s3  overwrite keeps createdAt, bumps updatedAt and the secret
 *   t4-s4  listEntries returns names in plain lexicographic order
 *   t4-s5  invalid names -> InvalidNameError, nothing added
 *   t4-s6  encode/decode round-trips quotes, newlines and non-ASCII
 *   t4-s7  secret length limits -> InvalidSecretError (exit code 1)
 *   t4-a1  __proto__ entry key -> VaultCorruptError, no prototype pollution
 *   t4-a2  control bytes / ANSI escapes in a name -> InvalidNameError
 *   t4-a3  oversized document -> VaultCorruptError before it is fully parsed
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  emptyVault,
  encodeVault,
  decodeVault,
  assertValidName,
  addEntry,
  getEntry,
  listEntries,
  InvalidNameError,
  InvalidSecretError,
  EntryExistsError,
  EntryNotFoundError,
  VaultCorruptError,
  VaultError,
  type VaultData,
} from '../src/vault.ts';

const T0 = '2024-01-01T00:00:00.000Z';
const T1 = '2024-06-15T12:30:00.000Z';

function clockOf(value: string): () => string {
  return () => value;
}

// ---------------------------------------------------------------------------
// t4-s1 — addEntry populates a fresh entry and does not mutate its input
// ---------------------------------------------------------------------------

describe('t4-s1 addEntry from an empty vault', () => {
  test('sets secret, createdAt and updatedAt from the fixed clock', () => {
    const data = emptyVault();
    const result = addEntry(data, 'github', 'ghp_x', { now: clockOf(T0) });

    assert.equal(result.entries.github.secret, 'ghp_x');
    assert.equal(result.entries.github.createdAt, T0);
    assert.equal(result.entries.github.updatedAt, T0);
  });

  test('does not mutate the input VaultData', () => {
    const data = emptyVault();
    addEntry(data, 'github', 'ghp_x', { now: clockOf(T0) });

    assert.equal(Object.keys(data.entries).length, 0);
    assert.deepStrictEqual(data, emptyVault());
  });

  test('returns a different object than the input', () => {
    const data = emptyVault();
    const result = addEntry(data, 'github', 'ghp_x', { now: clockOf(T0) });

    assert.notStrictEqual(result, data);
    assert.notStrictEqual(result.entries, data.entries);
  });
});

// ---------------------------------------------------------------------------
// t4-s2 — existing name without overwrite
// ---------------------------------------------------------------------------

describe('t4-s2 addEntry without overwrite on an existing name', () => {
  test('throws EntryExistsError with exit code 5 and the exact message', () => {
    const withGithub = addEntry(emptyVault(), 'github', 'ghp_x', { now: clockOf(T0) });

    assert.throws(
      () => addEntry(withGithub, 'github', 'ghp_y'),
      (err: unknown) => {
        assert.ok(err instanceof EntryExistsError);
        assert.ok(err instanceof VaultError);
        assert.equal(err.exitCode, 5);
        assert.equal(err.message, 'entry "github" already exists (use --force to overwrite)');
        return true;
      },
    );
  });

  test('leaves the original entry untouched', () => {
    const withGithub = addEntry(emptyVault(), 'github', 'ghp_x', { now: clockOf(T0) });

    assert.throws(() => addEntry(withGithub, 'github', 'ghp_y'));
    assert.equal(withGithub.entries.github.secret, 'ghp_x');
  });
});

// ---------------------------------------------------------------------------
// t4-s3 — overwrite semantics
// ---------------------------------------------------------------------------

describe('t4-s3 addEntry with overwrite true', () => {
  test('keeps createdAt at T0 and bumps updatedAt to T1 with the new secret', () => {
    const withGithub = addEntry(emptyVault(), 'github', 'ghp_old', { now: clockOf(T0) });
    const result = addEntry(withGithub, 'github', 'ghp_new', {
      overwrite: true,
      now: clockOf(T1),
    });

    assert.equal(result.entries.github.secret, 'ghp_new');
    assert.equal(result.entries.github.createdAt, T0);
    assert.equal(result.entries.github.updatedAt, T1);
  });

  test('does not mutate the vault it was called on', () => {
    const withGithub = addEntry(emptyVault(), 'github', 'ghp_old', { now: clockOf(T0) });
    addEntry(withGithub, 'github', 'ghp_new', { overwrite: true, now: clockOf(T1) });

    assert.equal(withGithub.entries.github.secret, 'ghp_old');
    assert.equal(withGithub.entries.github.updatedAt, T0);
  });
});

// ---------------------------------------------------------------------------
// t4-s4 — listEntries ordering
// ---------------------------------------------------------------------------

describe('t4-s4 listEntries', () => {
  test('returns names in plain lexicographic order', () => {
    let data = emptyVault();
    data = addEntry(data, 'zeta', 's1', { now: clockOf(T0) });
    data = addEntry(data, 'alpha', 's2', { now: clockOf(T0) });
    data = addEntry(data, 'mid', 's3', { now: clockOf(T0) });

    assert.deepStrictEqual(listEntries(data), ['alpha', 'mid', 'zeta']);
  });

  test('returns [] for an empty vault', () => {
    assert.deepStrictEqual(listEntries(emptyVault()), []);
  });
});

// ---------------------------------------------------------------------------
// t4-s5 — invalid names
// ---------------------------------------------------------------------------

describe('t4-s5 invalid entry names', () => {
  const badNames = ['has space', 'nl\nname', '../escape', 'a'.repeat(129)];

  for (const name of badNames) {
    test(`assertValidName rejects ${JSON.stringify(name.slice(0, 20))}`, () => {
      assert.throws(
        () => assertValidName(name),
        (err: unknown) => {
          assert.ok(err instanceof InvalidNameError);
          assert.equal(err.exitCode, 1);
          return true;
        },
      );
    });

    test(`addEntry rejects ${JSON.stringify(name.slice(0, 20))} and adds nothing`, () => {
      const data = emptyVault();
      assert.throws(() => addEntry(data, name, 'secret'), InvalidNameError);
      assert.equal(Object.keys(data.entries).length, 0);
    });
  }

  test('a 128-character name is accepted', () => {
    const name = 'a'.repeat(128);
    const data = addEntry(emptyVault(), name, 'secret', { now: clockOf(T0) });
    assert.equal(data.entries[name].secret, 'secret');
  });
});

// ---------------------------------------------------------------------------
// t4-s6 — codec round trip
// ---------------------------------------------------------------------------

describe('t4-s6 encodeVault / decodeVault round trip', () => {
  test('deep-equals the original for entries with quotes, newlines and non-ASCII', () => {
    let data = emptyVault();
    data = addEntry(data, 'quoted', 'has "quotes" inside', { now: clockOf(T0) });
    data = addEntry(data, 'multiline', 'line one\nline two\nline three', { now: clockOf(T1) });
    data = addEntry(data, 'unicode', 'pässwörd — ünïcode — 🔐', {
      now: clockOf(T0),
    });

    const decoded = decodeVault(encodeVault(data));
    assert.deepStrictEqual(decoded, data);
  });

  test('encodeVault returns a Buffer of UTF-8 JSON', () => {
    const data = addEntry(emptyVault(), 'github', 'ghp_x', { now: clockOf(T0) });
    const buf = encodeVault(data);

    assert.ok(Buffer.isBuffer(buf));
    const parsed = JSON.parse(buf.toString('utf8'));
    assert.equal(parsed.entries.github.secret, 'ghp_x');
  });

  test('round-trips an empty vault', () => {
    const data = emptyVault();
    assert.deepStrictEqual(decodeVault(encodeVault(data)), data);
  });
});

// ---------------------------------------------------------------------------
// t4-s7 — secret length limits
// ---------------------------------------------------------------------------

describe('t4-s7 secret length limits', () => {
  test('rejects an empty-string secret', () => {
    assert.throws(
      () => addEntry(emptyVault(), 'github', ''),
      (err: unknown) => {
        assert.ok(err instanceof VaultError);
        assert.equal(err.exitCode, 1);
        assert.match((err as Error).message, /8192/);
        return true;
      },
    );
  });

  test('rejects a secret of 8193 bytes', () => {
    assert.throws(
      () => addEntry(emptyVault(), 'github', 'x'.repeat(8193)),
      (err: unknown) => {
        assert.ok(err instanceof VaultError);
        assert.equal(err.exitCode, 1);
        assert.match((err as Error).message, /8192/);
        return true;
      },
    );
  });

  test('accepts a secret of exactly 8192 bytes', () => {
    const data = addEntry(emptyVault(), 'github', 'x'.repeat(8192), { now: clockOf(T0) });
    assert.equal(data.entries.github.secret.length, 8192);
  });

  test('rejected secrets add nothing to the vault', () => {
    const data = emptyVault();
    assert.throws(() => addEntry(data, 'github', ''));
    assert.equal(Object.keys(data.entries).length, 0);
  });
});

// ---------------------------------------------------------------------------
// getEntry / EntryNotFoundError
// ---------------------------------------------------------------------------

describe('getEntry', () => {
  test('returns the secret for an existing entry', () => {
    const data = addEntry(emptyVault(), 'github', 'ghp_x', { now: clockOf(T0) });
    assert.equal(getEntry(data, 'github'), 'ghp_x');
  });

  test('throws EntryNotFoundError with exit code 4 for a missing name', () => {
    assert.throws(
      () => getEntry(emptyVault(), 'missing'),
      (err: unknown) => {
        assert.ok(err instanceof EntryNotFoundError);
        assert.ok(err instanceof VaultError);
        assert.equal(err.exitCode, 4);
        return true;
      },
    );
  });
});

// ---------------------------------------------------------------------------
// t4-a1 — __proto__ entry key must not pollute Object.prototype
// ---------------------------------------------------------------------------

describe('t4-a1 __proto__ entry key', () => {
  test('decodeVault throws VaultCorruptError and Object.prototype stays clean', () => {
    // Built from a raw JSON string, exactly as the brief's abuse case gives
    // it, and not via a `{ __proto__: ... }` object literal -- an
    // un-computed `__proto__` key in a JS object literal is special-cased by
    // the language to set the object's prototype instead of creating an own
    // property, so it would silently vanish from JSON.stringify and this
    // test would not exercise the attack it claims to.
    const hostile = Buffer.from(
      '{"entries":{"__proto__":{"secret":"x","createdAt":"","updatedAt":""}}}',
      'utf8',
    );

    assert.throws(() => decodeVault(hostile), VaultCorruptError);
    assert.equal(({} as Record<string, unknown>).secret, undefined);
  });

  test('also rejects "constructor" and "prototype" entry keys', () => {
    for (const key of ['constructor', 'prototype']) {
      const hostile = Buffer.from(
        JSON.stringify({ entries: { [key]: { secret: 'x', createdAt: '', updatedAt: '' } } }),
        'utf8',
      );
      assert.throws(() => decodeVault(hostile), VaultCorruptError);
    }
    assert.equal(({} as Record<string, unknown>).secret, undefined);
  });

  test('a __proto__ key built via JSON.parse is a real own property (sanity check on the attack)', () => {
    // Confirms the premise of this abuse case: JSON.parse defines "__proto__"
    // as an ordinary own data property rather than invoking the accessor, so
    // decodeVault must check for the key explicitly -- the object's actual
    // prototype is untouched by parsing alone.
    const parsed = JSON.parse('{"__proto__":{"secret":"x"}}') as Record<string, unknown>;
    assert.ok(Object.hasOwn(parsed, '__proto__'));
    assert.equal(Object.getPrototypeOf(parsed), Object.prototype);
  });
});

// ---------------------------------------------------------------------------
// t4-a2 — control bytes / ANSI escapes in a name
// ---------------------------------------------------------------------------

describe('t4-a2 control bytes and ANSI escapes in a name', () => {
  test('a newline in the name throws InvalidNameError', () => {
    assert.throws(() => assertValidName('foo\nbar'), InvalidNameError);
  });

  test('an ANSI CSI escape sequence in the name throws InvalidNameError', () => {
    // Written as a JS escape, not a literal byte, so this file stays text and
    // the diff stays readable; \u001b is ESC (0x1b).
    const hostile = 'name\u001b[2J';
    assert.throws(
      () => assertValidName(hostile),
      (err: unknown) => {
        assert.ok(err instanceof InvalidNameError);
        assert.equal(err.exitCode, 1);
        // The escape byte must not survive into the thrown message either --
        // it would otherwise reach a terminal via a caught-and-printed error.
        assert.ok(!(err as Error).message.includes('\u001b'));
        return true;
      },
    );
  });

  test('addEntry rejects the same hostile name and adds nothing', () => {
    const data = emptyVault();
    assert.throws(() => addEntry(data, 'name\u001b[2J', 'secret'), InvalidNameError);
    assert.equal(Object.keys(data.entries).length, 0);
  });

  test('getEntry on a hostile lookup key does not echo the escape byte into its message', () => {
    // getEntry has no name-format gate of its own -- any lookup key reaches
    // EntryNotFoundError's constructor, so this checks that path directly
    // rather than relying on assertValidName having run first.
    assert.throws(
      () => getEntry(emptyVault(), 'name\u001b[2J'),
      (err: unknown) => {
        assert.ok(err instanceof EntryNotFoundError);
        assert.ok(!(err as Error).message.includes('\u001b'));
        return true;
      },
    );
  });
});

// ---------------------------------------------------------------------------
// t4-a3 — oversized document
// ---------------------------------------------------------------------------

describe('t4-a3 oversized document', () => {
  test('decodeVault throws VaultCorruptError for a document over 5 MiB, not OOM/hang', () => {
    // 100000 small entries comfortably clears 5 MiB without actually
    // constructing a 20 MiB fixture in the test process.
    const entries: Record<string, unknown> = {};
    for (let i = 0; i < 100_000; i += 1) {
      entries[`entry-${i}`] = { secret: 'x'.repeat(100), createdAt: '', updatedAt: '' };
    }
    const huge = Buffer.from(JSON.stringify({ entries }), 'utf8');
    assert.ok(huge.length > 5 * 1024 * 1024, `fixture must exceed 5 MiB, was ${huge.length}`);

    assert.throws(
      () => decodeVault(huge),
      (err: unknown) => {
        assert.ok(err instanceof VaultCorruptError);
        assert.equal(err.exitCode, 3);
        return true;
      },
    );
  });

  test('a document just under the limit is not rejected for size', () => {
    // Many entries, each within the 8192-byte per-secret cap, sized so the
    // whole document sits just below 5 MiB; decoding must succeed.
    let data = emptyVault();
    for (let i = 0; i < 500; i += 1) {
      data = addEntry(data, `entry-${i}`, 'x'.repeat(8000), { now: clockOf(T0) });
    }
    const encoded = encodeVault(data);
    assert.ok(encoded.length < 5 * 1024 * 1024, `fixture must stay under 5 MiB, was ${encoded.length}`);

    assert.deepStrictEqual(decodeVault(encoded), data);
  });
});

// ---------------------------------------------------------------------------
// decodeVault — additional corruption shapes from the Definition of Done
// ---------------------------------------------------------------------------

describe('decodeVault corruption handling', () => {
  test('throws VaultCorruptError for non-object JSON', () => {
    assert.throws(() => decodeVault(Buffer.from('"just a string"', 'utf8')), VaultCorruptError);
    assert.throws(() => decodeVault(Buffer.from('42', 'utf8')), VaultCorruptError);
    assert.throws(() => decodeVault(Buffer.from('[1,2,3]', 'utf8')), VaultCorruptError);
    assert.throws(() => decodeVault(Buffer.from('null', 'utf8')), VaultCorruptError);
  });

  test('throws VaultCorruptError for invalid JSON', () => {
    assert.throws(() => decodeVault(Buffer.from('{not json', 'utf8')), VaultCorruptError);
  });

  test('throws VaultCorruptError when "entries" is missing', () => {
    assert.throws(() => decodeVault(Buffer.from('{}', 'utf8')), VaultCorruptError);
  });

  test('throws VaultCorruptError when "entries" is not an object', () => {
    assert.throws(
      () => decodeVault(Buffer.from(JSON.stringify({ entries: 'nope' }), 'utf8')),
      VaultCorruptError,
    );
    assert.throws(
      () => decodeVault(Buffer.from(JSON.stringify({ entries: [] }), 'utf8')),
      VaultCorruptError,
    );
  });

  test('throws VaultCorruptError for an entry with a numeric secret', () => {
    const doc = { entries: { github: { secret: 12345, createdAt: T0, updatedAt: T0 } } };
    assert.throws(() => decodeVault(Buffer.from(JSON.stringify(doc), 'utf8')), VaultCorruptError);
  });

  test('throws VaultCorruptError for an entry missing createdAt/updatedAt', () => {
    const doc = { entries: { github: { secret: 'x' } } };
    assert.throws(() => decodeVault(Buffer.from(JSON.stringify(doc), 'utf8')), VaultCorruptError);
  });

  test('all VaultCorruptError instances carry exit code 3', () => {
    assert.throws(
      () => decodeVault(Buffer.from('null', 'utf8')),
      (err: unknown) => {
        assert.ok(err instanceof VaultCorruptError);
        assert.equal(err.exitCode, 3);
        return true;
      },
    );
  });
});

// ---------------------------------------------------------------------------
// emptyVault
// ---------------------------------------------------------------------------

describe('emptyVault', () => {
  test('has zero entries', () => {
    assert.deepStrictEqual(listEntries(emptyVault()), []);
    assert.equal(Object.keys(emptyVault().entries).length, 0);
  });

  test('entries has no prototype, so a plain object cannot masquerade as an inherited key', () => {
    assert.equal(Object.getPrototypeOf(emptyVault().entries), null);
  });
});
