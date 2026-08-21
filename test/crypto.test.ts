/**
 * Node t2 — passphrase encryption envelope (scrypt + AES-256-GCM).
 *
 * Scenario map (see brief):
 *   t2-s1  round-trip fidelity
 *   t2-s2  wrong passphrase -> WrongPassphraseError, exit code, non-committal message
 *   t2-s3  flipped ciphertext byte -> WrongPassphraseError, no plaintext returned
 *   t2-s4  envelope uniqueness across seals of identical input
 *   t2-s5  malformed / wrong-shaped envelopes -> VaultCorruptError, exit code
 *   t2-s6  kdf block shape (name, n, r, p) and 16-byte saltB64
 *   t2-a1  the sealed work factor cannot be weakened by a caller
 *   t2-a2  an oversized kdf.n cannot force a multi-gigabyte allocation
 *   t2-a3  a failed open does not leak the passphrase or the plaintext
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  cipher,
  seal,
  open,
  validateKdfParams,
  WrongPassphraseError,
  VaultCorruptError,
  VaultError,
  KDF_PARAMS,
  KEY_LEN,
  SALT_LEN,
  NONCE_LEN,
  ENVELOPE_VERSION,
  type EncryptedEnvelope,
} from '../src/crypto.ts';

const PASSPHRASE = 'correct horse battery staple';
const AUTH_TAG_LEN = 16;

/**
 * `seal` takes bytes, not text. Most of these tests only need *some* payload,
 * so this spells the encoding step once rather than at every call site; the
 * tests that care about byte fidelity build their Buffers by hand instead.
 */
function bytes(text: string): Buffer {
  return Buffer.from(text, 'utf8');
}

/**
 * A sealed `EncryptedEnvelope` is readonly, which is right for production
 * callers but exactly what these tests need to defeat: forging a damaged
 * vault means writing to those fields. Cloning through JSON hands back a
 * deeply mutable copy, so tampering stays local to one test and needs no
 * casts at each site.
 */
type Mutable<T> = T extends object ? { -readonly [K in keyof T]: Mutable<T[K]> } : T;
type MutableEnvelope = Mutable<EncryptedEnvelope>;

function clone(envelope: EncryptedEnvelope): MutableEnvelope {
  return JSON.parse(JSON.stringify(envelope)) as MutableEnvelope;
}

// ---------------------------------------------------------------------------
// t2-s1 — round-trip fidelity
// ---------------------------------------------------------------------------

describe('t2-s1 round-trip fidelity', () => {
  test('seal then open returns the original bytes', async () => {
    const plaintext = bytes('hunter2\nsecond line');
    const envelope = await seal(plaintext, PASSPHRASE);
    assert.ok((await open(envelope, PASSPHRASE)).equals(plaintext));
  });

  test('open returns a Buffer, not a string', async () => {
    const opened = await open(await seal(bytes('payload'), PASSPHRASE), PASSPHRASE);
    assert.ok(Buffer.isBuffer(opened), `open must return a Buffer, got ${typeof opened}`);
  });

  test('round-trips arbitrary binary bytes, not just text', async () => {
    // The bytes that a string round-trip would destroy: NUL, and three that
    // are not valid UTF-8 on their own. Decoding these to a string and back
    // yields ef bf bd (U+FFFD) for each, so a text-shaped API cannot pass this.
    const plaintext = Buffer.from([0x00, 0xff, 0xfe, 0x80]);
    const envelope = await seal(plaintext, PASSPHRASE);
    const opened = await open(envelope, PASSPHRASE);

    assert.ok(
      opened.equals(plaintext),
      `expected ${plaintext.toString('hex')}, got ${opened.toString('hex')}`,
    );
  });

  test('round-trips every byte value from 0x00 to 0xff', async () => {
    const plaintext = Buffer.from(Array.from({ length: 256 }, (_, i) => i));
    const envelope = await seal(plaintext, PASSPHRASE);
    assert.ok((await open(envelope, PASSPHRASE)).equals(plaintext));
  });

  test('round-trips at the production KDF cost', async () => {
    const plaintext = bytes(JSON.stringify({ entries: [{ name: 'github', secret: 's3cret' }] }));
    const envelope = await seal(plaintext, PASSPHRASE);
    assert.equal(envelope.kdf.n, KDF_PARAMS.n);
    assert.ok((await open(envelope, PASSPHRASE)).equals(plaintext));
  });

  // DoD: 0 bytes, 1 byte and 1 MiB must all round-trip byte-identically.
  test('round-trips an empty payload (0 bytes)', async () => {
    const envelope = await seal(Buffer.alloc(0), PASSPHRASE);
    const opened = await open(envelope, PASSPHRASE);
    assert.ok(Buffer.isBuffer(opened));
    assert.equal(opened.length, 0);
    assert.ok(opened.equals(Buffer.alloc(0)));
  });

  test('round-trips a single byte (1 byte)', async () => {
    const plaintext = Buffer.from([0x42]);
    const envelope = await seal(plaintext, PASSPHRASE);
    const opened = await open(envelope, PASSPHRASE);
    assert.equal(opened.length, 1);
    assert.ok(opened.equals(plaintext));
  });

  test('round-trips a full mebibyte (1 MiB)', async () => {
    const plaintext = Buffer.from(Array.from({ length: 1024 * 1024 }, (_, i) => i % 256));
    const envelope = await seal(plaintext, PASSPHRASE);
    const opened = await open(envelope, PASSPHRASE);
    assert.equal(opened.length, 1024 * 1024);
    assert.ok(opened.equals(plaintext));
  });

  test('round-trips multi-byte UTF-8 without mangling it', async () => {
    // The NUL is written as an escape on purpose: a raw one in the source
    // makes git treat this file as binary and the diffs unreadable.
    const plaintext = bytes('pässwörd — 🔐 — 密码 — \u0000 — 🔑');
    const envelope = await seal(plaintext, PASSPHRASE);
    const opened = await open(envelope, PASSPHRASE);
    assert.ok(opened.equals(plaintext));
    assert.equal(opened.toString('utf8'), plaintext.toString('utf8'));
  });

  test('round-trips a payload larger than one AES block', async () => {
    const plaintext = bytes('x'.repeat(200_000));
    const envelope = await seal(plaintext, PASSPHRASE);
    assert.ok((await open(envelope, PASSPHRASE)).equals(plaintext));
  });

  test('round-trips a passphrase containing multi-byte characters', async () => {
    const passphrase = 'trådløs-🔑-密';
    const envelope = await seal(bytes('payload'), passphrase);
    assert.ok((await open(envelope, passphrase)).equals(bytes('payload')));
  });

  test('survives a JSON serialisation cycle, as the vault file will', async () => {
    const plaintext = bytes('persisted through disk');
    const envelope = await seal(plaintext, PASSPHRASE);
    const reloaded = JSON.parse(JSON.stringify(envelope)) as EncryptedEnvelope;
    assert.ok((await open(reloaded, PASSPHRASE)).equals(plaintext));
  });

  test('does not mutate the caller\'s plaintext buffer', async () => {
    const plaintext = bytes('caller still owns this');
    const copy = Buffer.from(plaintext);
    await seal(plaintext, PASSPHRASE);
    assert.ok(plaintext.equals(copy), 'seal must not write through the buffer it was handed');
  });

  test('the envelope never contains the plaintext or the passphrase', async () => {
    const plaintext = bytes('DISTINCTIVE-PLAINTEXT-MARKER');
    const envelope = await seal(plaintext, 'DISTINCTIVE-PASSPHRASE-MARKER');
    const serialised = JSON.stringify(envelope);
    assert.doesNotMatch(serialised, /DISTINCTIVE-PLAINTEXT-MARKER/);
    assert.doesNotMatch(serialised, /DISTINCTIVE-PASSPHRASE-MARKER/);
  });
});

// ---------------------------------------------------------------------------
// t2-s2 — wrong passphrase
// ---------------------------------------------------------------------------

describe('t2-s2 wrong passphrase', () => {
  test('open with a different passphrase throws WrongPassphraseError', async () => {
    const envelope = await seal(bytes('secret'), PASSPHRASE);
    await assert.rejects(
      () => open(envelope, 'not the passphrase'),
      (error: unknown) => {
        assert.ok(error instanceof WrongPassphraseError, `expected WrongPassphraseError, got ${error}`);
        return true;
      },
    );
  });

  test('WrongPassphraseError carries the documented exit code', async () => {
    const envelope = await seal(bytes('secret'), PASSPHRASE);
    const error = await open(envelope, 'nope').then(
      () => assert.fail('open should have rejected'),
      (e: unknown) => e as WrongPassphraseError,
    );
    assert.equal(error.exitCode, 2);
    assert.equal(error.code, 'WRONG_PASSPHRASE');
  });

  test('the message contains neither "right" nor "wrong"', async () => {
    const envelope = await seal(bytes('secret'), PASSPHRASE);
    const error = await open(envelope, 'nope').then(
      () => assert.fail('open should have rejected'),
      (e: unknown) => e as WrongPassphraseError,
    );
    const message = error.message.toLowerCase();
    assert.ok(message.length > 0, 'the error must carry a message');
    assert.ok(!message.includes('right'), `message must not contain "right": ${error.message}`);
    assert.ok(!message.includes('wrong'), `message must not contain "wrong": ${error.message}`);
  });

  test('a near-miss passphrase is rejected just like any other', async () => {
    const envelope = await seal(bytes('secret'), PASSPHRASE);
    await assert.rejects(() => open(envelope, PASSPHRASE + ' '), WrongPassphraseError);
    await assert.rejects(() => open(envelope, PASSPHRASE.toUpperCase()), WrongPassphraseError);
    await assert.rejects(() => open(envelope, ''), WrongPassphraseError);
  });

  test('an in-range cost factor cannot be edited without detection', async () => {
    // kdf.n feeds directly into key derivation, so editing it — even to
    // another value the range check accepts — derives a different key and
    // the authentication tag no longer verifies.
    const envelope = await seal(bytes('secret'), PASSPHRASE);
    const tampered = clone(envelope);
    tampered.kdf.n = 32768;

    await assert.rejects(() => open(tampered, PASSPHRASE), WrongPassphraseError);
  });

  test('a tampered salt derives a different key and fails authentication', async () => {
    const envelope = await seal(bytes('secret'), PASSPHRASE);
    const tampered = clone(envelope);
    tampered.saltB64 = Buffer.alloc(SALT_LEN, 0x42).toString('base64');

    await assert.rejects(() => open(tampered, PASSPHRASE), WrongPassphraseError);
  });
});

// ---------------------------------------------------------------------------
// t2-s3 — a flipped ciphertext byte
// ---------------------------------------------------------------------------

describe('t2-s3 a flipped ciphertext byte', () => {
  test('flipping one byte of the ciphertext is caught by the auth tag, not returned as plaintext', async () => {
    const envelope = await seal(bytes('secret payload'), PASSPHRASE);
    const tampered = clone(envelope);
    const raw = Buffer.from(tampered.ciphertextB64, 'base64');
    assert.ok(raw.length > 0, 'precondition: there is a byte to flip');
    raw.writeUInt8(raw.readUInt8(0) ^ 0x01, 0);
    tampered.ciphertextB64 = raw.toString('base64');

    let plaintext: Buffer | undefined;
    await assert.rejects(
      () => open(tampered, PASSPHRASE).then((p) => { plaintext = p; }),
      WrongPassphraseError,
    );
    assert.equal(plaintext, undefined, 'no plaintext must be returned on a failed open');
  });

  test('flipping a byte inside the appended auth tag is also caught', async () => {
    const envelope = await seal(bytes('secret payload'), PASSPHRASE);
    const tampered = clone(envelope);
    const raw = Buffer.from(tampered.ciphertextB64, 'base64');
    raw.writeUInt8(raw.readUInt8(raw.length - 1) ^ 0x01, raw.length - 1);
    tampered.ciphertextB64 = raw.toString('base64');

    await assert.rejects(() => open(tampered, PASSPHRASE), WrongPassphraseError);
  });
});

// ---------------------------------------------------------------------------
// t2-s4 — envelope uniqueness
// ---------------------------------------------------------------------------

describe('t2-s4 envelope uniqueness', () => {
  test('sealing the same plaintext twice yields a fresh saltB64, nonceB64 and ciphertextB64', async () => {
    const plaintext = 'identical input';
    const a = await seal(bytes(plaintext), PASSPHRASE);
    const b = await seal(bytes(plaintext), PASSPHRASE);

    assert.notEqual(a.saltB64, b.saltB64, 'saltB64 must be regenerated per seal');
    assert.notEqual(a.nonceB64, b.nonceB64, 'nonceB64 must be regenerated per seal');
    assert.notEqual(a.ciphertextB64, b.ciphertextB64, 'ciphertextB64 must not repeat');
  });

  test('both independently sealed envelopes still open', async () => {
    const plaintext = bytes('identical input');
    const a = await seal(plaintext, PASSPHRASE);
    const b = await seal(plaintext, PASSPHRASE);
    assert.ok((await open(a, PASSPHRASE)).equals(plaintext));
    assert.ok((await open(b, PASSPHRASE)).equals(plaintext));
  });

  test('salts and nonces are unique across many seals', async () => {
    const salts = new Set<string>();
    const nonces = new Set<string>();
    const rounds = 24;
    for (let i = 0; i < rounds; i++) {
      const envelope = await seal(bytes('same'), PASSPHRASE);
      salts.add(envelope.saltB64);
      nonces.add(envelope.nonceB64);
    }
    assert.equal(salts.size, rounds, 'every seal must draw a distinct salt');
    assert.equal(nonces.size, rounds, 'every seal must draw a distinct nonce');
  });
});

// ---------------------------------------------------------------------------
// t2-s5 — malformed / wrong-version envelopes
// ---------------------------------------------------------------------------

describe('t2-s5 malformed envelope handling', () => {
  test('VaultCorruptError carries the documented exit code', async () => {
    const error = await open({} as unknown as EncryptedEnvelope, PASSPHRASE).then(
      () => assert.fail('open should have rejected'),
      (e: unknown) => e as VaultCorruptError,
    );
    assert.ok(error instanceof VaultCorruptError);
    assert.equal(error.exitCode, 3);
    assert.equal(error.code, 'VAULT_CORRUPT');
  });

  const structurallyInvalid: Array<[string, unknown]> = [
    ['null', null],
    ['undefined', undefined],
    ['a string', 'not an envelope'],
    ['a number', 42],
    ['an array', []],
    ['an empty object', {}],
  ];

  for (const [label, value] of structurallyInvalid) {
    test(`rejects ${label} as a corrupt vault`, async () => {
      await assert.rejects(() => open(value as unknown as EncryptedEnvelope, PASSPHRASE), VaultCorruptError);
    });
  }

  test('rejects an envelope with version 2', async () => {
    const envelope = clone(await seal(bytes('payload'), PASSPHRASE));
    envelope.version = 2 as MutableEnvelope['version'];
    const error = await open(envelope, PASSPHRASE).then(
      () => assert.fail('open should have rejected'),
      (e: unknown) => e,
    );
    assert.ok(error instanceof VaultCorruptError);
    assert.equal((error as VaultCorruptError).exitCode, 3);
  });

  test('rejects an envelope declaring cipher "aes-128-cbc"', async () => {
    const envelope = clone(await seal(bytes('payload'), PASSPHRASE));
    (envelope as unknown as { cipher: string }).cipher = 'aes-128-cbc';
    const error = await open(envelope, PASSPHRASE).then(
      () => assert.fail('open should have rejected'),
      (e: unknown) => e,
    );
    assert.ok(error instanceof VaultCorruptError);
    assert.equal((error as VaultCorruptError).exitCode, 3);
  });

  test('rejects an 8-byte nonce', async () => {
    const envelope = clone(await seal(bytes('payload'), PASSPHRASE));
    envelope.nonceB64 = Buffer.alloc(8).toString('base64');
    const error = await open(envelope, PASSPHRASE).then(
      () => assert.fail('open should have rejected'),
      (e: unknown) => e,
    );
    assert.ok(error instanceof VaultCorruptError);
    assert.equal((error as VaultCorruptError).exitCode, 3);
  });

  test('rejects a non-base64 ciphertext', async () => {
    const envelope = clone(await seal(bytes('payload'), PASSPHRASE));
    envelope.ciphertextB64 = 'not!valid!base64!!!!!!!!';
    const error = await open(envelope, PASSPHRASE).then(
      () => assert.fail('open should have rejected'),
      (e: unknown) => e,
    );
    assert.ok(error instanceof VaultCorruptError);
    assert.equal((error as VaultCorruptError).exitCode, 3);
  });

  test('rejects an envelope missing each required field in turn', async () => {
    const good = await seal(bytes('payload'), PASSPHRASE);
    type PartialEnvelope = Omit<Partial<MutableEnvelope>, 'kdf'> & {
      kdf?: Partial<MutableEnvelope['kdf']>;
    };
    const paths: Array<[string, () => PartialEnvelope]> = [
      ['version', () => { const e: PartialEnvelope = clone(good); delete e.version; return e; }],
      ['cipher', () => { const e: PartialEnvelope = clone(good); delete e.cipher; return e; }],
      ['kdf', () => { const e: PartialEnvelope = clone(good); delete e.kdf; return e; }],
      ['kdf.n', () => { const e: PartialEnvelope = clone(good); delete e.kdf?.n; return e; }],
      ['kdf.name', () => { const e: PartialEnvelope = clone(good); delete e.kdf?.name; return e; }],
      ['saltB64', () => { const e: PartialEnvelope = clone(good); delete e.saltB64; return e; }],
      ['nonceB64', () => { const e: PartialEnvelope = clone(good); delete e.nonceB64; return e; }],
      ['ciphertextB64', () => { const e: PartialEnvelope = clone(good); delete e.ciphertextB64; return e; }],
    ];

    for (const [label, build] of paths) {
      await assert.rejects(
        () => open(build() as unknown as EncryptedEnvelope, PASSPHRASE),
        VaultCorruptError,
        `missing ${label} should be a corrupt vault`,
      );
    }
  });

  test('rejects an unknown KDF name rather than guessing', async () => {
    const envelope = clone(await seal(bytes('payload'), PASSPHRASE));
    (envelope.kdf as { name: string }).name = 'pbkdf2';
    await assert.rejects(() => open(envelope, PASSPHRASE), VaultCorruptError);
  });

  test('rejects a saltB64 of the wrong length', async () => {
    const envelope = clone(await seal(bytes('payload'), PASSPHRASE));
    envelope.saltB64 = Buffer.alloc(8).toString('base64');
    await assert.rejects(() => open(envelope, PASSPHRASE), VaultCorruptError);
  });

  test('rejects a ciphertextB64 too short to hold an auth tag', async () => {
    const envelope = clone(await seal(bytes('payload'), PASSPHRASE));
    envelope.ciphertextB64 = Buffer.alloc(4).toString('base64');
    await assert.rejects(() => open(envelope, PASSPHRASE), VaultCorruptError);
  });

  test('rejects fields that are not strings', async () => {
    const envelope = clone(await seal(bytes('payload'), PASSPHRASE));
    (envelope as unknown as { ciphertextB64: unknown }).ciphertextB64 = { length: 1 };
    await assert.rejects(() => open(envelope, PASSPHRASE), VaultCorruptError);
  });

  test('rejects stray characters that a lenient decoder would silently drop', async () => {
    // Buffer.from(s, 'base64') discards unrecognised characters, so this
    // decodes to a perfectly well-sized 16-byte salt and slips past any
    // length check. Only a strict decode rejects it.
    const envelope = clone(await seal(bytes('payload'), PASSPHRASE));
    const canonical = envelope.saltB64;
    envelope.saltB64 = `${canonical.slice(0, 4)}!${canonical.slice(4)}`;
    assert.equal(
      Buffer.from(envelope.saltB64, 'base64').length,
      16,
      'precondition: the tampered salt must still decode to 16 bytes',
    );

    await assert.rejects(() => open(envelope, PASSPHRASE), VaultCorruptError);
  });

  test('rejects stray characters in the ciphertext, which has no fixed length check', async () => {
    const envelope = clone(await seal(bytes('payload'), PASSPHRASE));
    const canonical = envelope.ciphertextB64;
    envelope.ciphertextB64 = `${canonical.slice(0, 2)}\n \t${canonical.slice(2)}`;
    assert.ok(
      Buffer.from(envelope.ciphertextB64, 'base64').equals(Buffer.from(canonical, 'base64')),
      'precondition: a lenient decoder sees these as identical',
    );

    await assert.rejects(() => open(envelope, PASSPHRASE), VaultCorruptError);
  });

  test('does not echo an unbounded hostile value into the error message', async () => {
    const envelope = clone(await seal(bytes('payload'), PASSPHRASE));
    (envelope.kdf as { name: string }).name = 'X'.repeat(100_000);

    const error = await open(envelope, PASSPHRASE).then(
      () => assert.fail('open should have rejected'),
      (e: unknown) => e as VaultCorruptError,
    );
    assert.ok(error instanceof VaultCorruptError);
    assert.ok(
      error.message.length < 500,
      `error message was ${error.message.length} chars; a vault file must not choose its own length`,
    );
  });

  test('strips control characters before quoting a value back to the terminal', async () => {
    const envelope = clone(await seal(bytes('payload'), PASSPHRASE));
    // A vault file that tries to repaint the terminal it is reported on.
    (envelope.kdf as { name: string }).name = '\u001b[2J\u001b[31mscrypt';

    const error = await open(envelope, PASSPHRASE).then(
      () => assert.fail('open should have rejected'),
      (e: unknown) => e as VaultCorruptError,
    );
    assert.ok(error instanceof VaultCorruptError);
    assert.doesNotMatch(error.message, /\u001b/, 'escape sequences must not survive into the message');
    // eslint-disable-next-line no-control-regex
    assert.doesNotMatch(error.message, /[\u0000-\u001f\u007f-\u009f]/);
  });

  test('rejects base64url and whitespace-padded encodings rather than reinterpreting them', async () => {
    for (const variant of ['AQEBAQEBAQEBAQEBAQEBAQ', 'AQEBAQEBAQEBAQEBAQEBAQ ==', '_QEBAQEBAQEBAQEBAQEBAQ==']) {
      const envelope = clone(await seal(bytes('payload'), PASSPHRASE));
      envelope.saltB64 = variant;
      await assert.rejects(
        () => open(envelope, PASSPHRASE),
        VaultCorruptError,
        `salt ${JSON.stringify(variant)} should be rejected`,
      );
    }
  });

  test('a corrupt envelope is never confused with a passphrase failure', async () => {
    const envelope = clone(await seal(bytes('payload'), PASSPHRASE));
    envelope.saltB64 = Buffer.alloc(4).toString('base64');
    const error = await open(envelope, PASSPHRASE).then(
      () => assert.fail('open should have rejected'),
      (e: unknown) => e,
    );
    assert.ok(error instanceof VaultCorruptError);
    assert.ok(!(error instanceof WrongPassphraseError));
  });

  test('seal reports a bad argument as a caller bug, not a damaged vault', async () => {
    // A TypeError, deliberately: VaultCorruptError means the file is bad, and
    // saying that here would send someone hunting for damage that is not there.
    for (const call of [
      () => seal(undefined as unknown as Buffer, PASSPHRASE),
      // A string is not bytes. Silently encoding it would guess at an encoding
      // the caller never named, and lose the byte-exactness open() promises.
      () => seal('payload' as unknown as Buffer, PASSPHRASE),
      () => seal(new Uint8Array([1, 2, 3]) as unknown as Buffer, PASSPHRASE),
      () => seal(bytes('payload'), undefined as unknown as string),
      () => open({} as EncryptedEnvelope, undefined as unknown as string),
    ]) {
      const error = await call().then(
        () => assert.fail('should have rejected'),
        (e: unknown) => e,
      );
      assert.ok(error instanceof TypeError, `expected TypeError, got ${error}`);
      assert.ok(!(error instanceof VaultCorruptError));
    }
  });
});

// ---------------------------------------------------------------------------
// t2-s6 — kdf block shape and KDF parameter validation
// ---------------------------------------------------------------------------

describe('t2-s6 kdf block shape and parameter validation', () => {
  test('the kdf block records scrypt with the specified cost parameters', async () => {
    const envelope = await seal(bytes('payload'), PASSPHRASE);

    assert.equal(envelope.version, ENVELOPE_VERSION);
    assert.equal(envelope.kdf.name, 'scrypt');
    assert.equal(envelope.kdf.n, 131072);
    assert.equal(envelope.kdf.r, 8);
    assert.equal(envelope.kdf.p, 1);
  });

  test('saltB64 decodes to exactly 16 bytes of fresh randomness', async () => {
    const envelope = await seal(bytes('payload'), PASSPHRASE);
    const salt = Buffer.from(envelope.saltB64, 'base64');

    assert.equal(typeof envelope.saltB64, 'string');
    assert.equal(salt.length, 16);
    assert.equal(salt.toString('base64'), envelope.saltB64, 'saltB64 must be canonical base64');
    assert.notEqual(salt.toString('hex'), '0'.repeat(32), 'salt must not be all zeroes');
  });

  test('the kdf block carries exactly the documented keys', async () => {
    const envelope = await seal(bytes('payload'), PASSPHRASE);
    assert.deepEqual(Object.keys(envelope.kdf).sort(), ['n', 'name', 'p', 'r']);
  });

  test('the envelope carries exactly the documented top-level keys', async () => {
    const envelope = await seal(bytes('payload'), PASSPHRASE);
    assert.deepEqual(
      Object.keys(envelope).sort(),
      ['cipher', 'ciphertextB64', 'kdf', 'nonceB64', 'saltB64', 'version'],
    );
  });

  test('cipher is the plain algorithm string, and nonceB64 decodes to 12 bytes', async () => {
    const envelope = await seal(bytes('payload'), PASSPHRASE);

    assert.equal(envelope.cipher, 'aes-256-gcm');
    assert.equal(Buffer.from(envelope.nonceB64, 'base64').length, NONCE_LEN);
  });

  test('ciphertextB64 decodes to the plaintext length plus a 16-byte auth tag', async () => {
    const plaintext = bytes('a payload of known length');
    const envelope = await seal(plaintext, PASSPHRASE);
    const combined = Buffer.from(envelope.ciphertextB64, 'base64');
    assert.equal(combined.length, plaintext.length + AUTH_TAG_LEN);
  });

  test('KDF_PARAMS is the published default and is itself in range', () => {
    assert.equal(KDF_PARAMS.name, 'scrypt');
    assert.equal(KDF_PARAMS.n, 131072);
    assert.equal(KDF_PARAMS.r, 8);
    assert.equal(KDF_PARAMS.p, 1);
    assert.equal(KEY_LEN, 32);
    assert.equal(SALT_LEN, 16);
    assert.equal(NONCE_LEN, 12);
    assert.doesNotThrow(() => validateKdfParams(KDF_PARAMS));
  });

  test('the envelope is plain JSON-serialisable data, not a class instance', async () => {
    const envelope = await seal(bytes('payload'), PASSPHRASE);
    assert.equal(Object.getPrototypeOf(envelope), Object.prototype);
    assert.deepEqual(JSON.parse(JSON.stringify(envelope)), envelope);
  });

  const base = { name: 'scrypt' as const, n: 131072, r: 8, p: 1 };

  const rejected: Array<[string, Record<string, unknown>]> = [
    ['n below the floor', { ...base, n: 1024 }],
    // 2^14 is a real scrypt cost, and a real vault file could name it. It is
    // still half the floor the spec sets, so it is a downgrade, not a choice.
    ['n one step below the floor', { ...base, n: 16384 }],
    ['n of zero', { ...base, n: 0 }],
    ['negative n', { ...base, n: -131072 }],
    ['n above the ceiling', { ...base, n: 2 ** 30 }],
    ['n that is not a power of two', { ...base, n: 131073 }],
    ['n that is not an integer', { ...base, n: 131072.5 }],
    ['n that is NaN', { ...base, n: Number.NaN }],
    ['n that is Infinity', { ...base, n: Number.POSITIVE_INFINITY }],
    ['n given as a string', { ...base, n: '131072' }],
    ['r of zero', { ...base, r: 0 }],
    // r and p are fixed by the spec at 8 and 1. Anything else is a different
    // scheme wearing the same name, and lowering either is a cheaper crack.
    ['r of one', { ...base, r: 1 }],
    ['r of sixteen', { ...base, r: 16 }],
    ['r above the ceiling', { ...base, r: 1024 }],
    ['r given as a string', { ...base, r: '8' }],
    ['p of zero', { ...base, p: 0 }],
    ['p of four', { ...base, p: 4 }],
    ['p above the ceiling', { ...base, p: 1024 }],
    ['p given as a string', { ...base, p: '1' }],
    // r is pinned at 8, so only n can push the working set over the budget.
    ['a combination that exceeds the memory budget', { ...base, n: 2 ** 20, r: 8 }],
    ['an unsupported kdf.name', { ...base, name: 'pbkdf2' }],
    ['a missing kdf.name', { n: 131072, r: 8, p: 1 }],
  ];

  for (const [label, params] of rejected) {
    test(`validateKdfParams rejects ${label}`, () => {
      assert.throws(
        () => validateKdfParams(params),
        (error: unknown) => {
          assert.ok(error instanceof VaultCorruptError, `expected VaultCorruptError, got ${error}`);
          return true;
        },
      );
    });
  }

  test('validateKdfParams accepts the in-range parameters the vault actually uses', () => {
    assert.doesNotThrow(() => validateKdfParams(base));
    // The floor itself is acceptable — an older vault sealed at 2^15 must
    // still open. One step below it is not; see the rejection table above.
    assert.doesNotThrow(() => validateKdfParams({ ...base, n: 32768 }));
  });

  test('open rejects hostile KDF parameters without attempting the derivation', async () => {
    // n = 2^24 with r = 8 would demand ~17 GiB and many seconds of work.
    // Validation must reject it up front, so this returns effectively instantly.
    const envelope = clone(await seal(bytes('payload'), PASSPHRASE));
    envelope.kdf.n = 2 ** 24;

    const started = process.hrtime.bigint();
    const error = await open(envelope, PASSPHRASE).then(
      () => assert.fail('open should have rejected'),
      (e: unknown) => e,
    );
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

    assert.ok(error instanceof VaultCorruptError, `expected VaultCorruptError, got ${error}`);
    assert.equal((error as VaultCorruptError).code, 'VAULT_CORRUPT');
    assert.ok(
      elapsedMs < 1000,
      `rejection took ${elapsedMs.toFixed(1)}ms; a derivation was almost certainly attempted`,
    );
  });

  test('open rejects a weakened cost factor rather than deriving cheaply', async () => {
    const envelope = clone(await seal(bytes('payload'), PASSPHRASE));
    envelope.kdf.n = 2;
    await assert.rejects(() => open(envelope, PASSPHRASE), VaultCorruptError);
  });
});

// ---------------------------------------------------------------------------
// t2-a2 — a hostile n cannot force a multi-gigabyte scrypt allocation
// ---------------------------------------------------------------------------

describe('t2-a2 an oversized kdf.n cannot trigger a multi-gigabyte allocation', () => {
  test('rejects kdf.n = 1073741824 in well under 50ms, before scrypt ever runs', async () => {
    // scrypt's working set is 128 * N * r bytes. At r = 8 this N would ask for
    // roughly 1 TiB — validation must refuse it synchronously, not attempt it
    // and fail slowly, or an attacker who can overwrite the vault file gets to
    // pick our memory usage.
    const envelope = clone(await seal(bytes('payload'), PASSPHRASE));
    envelope.kdf.n = 1073741824;

    const started = process.hrtime.bigint();
    const error = await open(envelope, PASSPHRASE).then(
      () => assert.fail('open should have rejected'),
      (e: unknown) => e,
    );
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

    assert.ok(error instanceof VaultCorruptError, `expected VaultCorruptError, got ${error}`);
    assert.ok(
      elapsedMs < 50,
      `rejection took ${elapsedMs.toFixed(1)}ms; scrypt was almost certainly invoked`,
    );
  });
});

// ---------------------------------------------------------------------------
// t2-a3 — a failed open never leaks the passphrase or the plaintext
// ---------------------------------------------------------------------------

describe('t2-a3 a failed open does not leak secrets through the error', () => {
  const SENTINEL_PASSPHRASE = 'SENTINEL-PASS';
  const SENTINEL_PLAINTEXT = bytes('SENTINEL-SECRET');

  function assertNoSecrets(error: unknown, label: string): void {
    // The exact channel a crash reporter or an uncaught-exception handler
    // would use: JSON.stringify for a logged object, .stack for the trace
    // printed to the terminal.
    const serialised = `${JSON.stringify(error)} ${(error as Error).stack ?? ''}`;
    assert.ok(!serialised.includes('SENTINEL-PASS'), `${label}: leaked the passphrase`);
    assert.ok(!serialised.includes('SENTINEL-SECRET'), `${label}: leaked the plaintext`);
  }

  test('a wrong-passphrase failure serialises to neither secret', async () => {
    const envelope = await seal(SENTINEL_PLAINTEXT, SENTINEL_PASSPHRASE);
    const error = await open(envelope, 'a different passphrase entirely').then(
      () => assert.fail('open should have rejected'),
      (e: unknown) => e,
    );
    assertNoSecrets(error, 'WrongPassphraseError');
  });

  test('a tampered-ciphertext failure serialises to neither secret', async () => {
    const envelope = clone(await seal(SENTINEL_PLAINTEXT, SENTINEL_PASSPHRASE));
    const raw = Buffer.from(envelope.ciphertextB64, 'base64');
    raw.writeUInt8(raw.readUInt8(0) ^ 0x01, 0);
    envelope.ciphertextB64 = raw.toString('base64');

    const error = await open(envelope, SENTINEL_PASSPHRASE).then(
      () => assert.fail('open should have rejected'),
      (e: unknown) => e,
    );
    assertNoSecrets(error, 'tampered ciphertext');
  });

  test('a corrupt-envelope failure serialises to neither secret', async () => {
    const envelope = clone(await seal(SENTINEL_PLAINTEXT, SENTINEL_PASSPHRASE));
    envelope.kdf.n = 1073741824;

    const error = await open(envelope, SENTINEL_PASSPHRASE).then(
      () => assert.fail('open should have rejected'),
      (e: unknown) => e,
    );
    assertNoSecrets(error, 'VaultCorruptError');
  });
});

// ---------------------------------------------------------------------------
// t2-a1 — a caller cannot talk seal() into a weaker work factor
// ---------------------------------------------------------------------------

describe('t2-a1 the sealed work factor is not negotiable', () => {
  /**
   * seal() writes n = 131072, r = 8, p = 1 and nothing else. The danger this
   * guards is not a malicious caller — it is an ordinary one: a `--kdf-n`
   * flag, a config file, a re-seal that copies the params out of the envelope
   * it just opened. Any of those, forwarded into an options argument, would
   * quietly produce a vault that is cheaper to crack offline, and every other
   * test in this file would still pass.
   */
  const smuggled: Array<[string, unknown]> = [
    ['a kdf block', { kdf: { n: 16384, r: 1, p: 1 } }],
    ['a lone weakened n', { kdf: { n: 1024 } }],
    ['bare cost factors', { n: 16384, r: 1, p: 1 }],
    ['an envelope-shaped copy of a weaker vault', { kdf: { name: 'scrypt', n: 2, r: 1, p: 1 } }],
  ];

  for (const [label, options] of smuggled) {
    test(`ignores ${label} passed as a third argument`, async () => {
      // The cast is the point: TypeScript already refuses this, but a plain
      // JavaScript caller, or an `any` from a config loader, does not.
      const smuggle = seal as unknown as (
        plaintext: Buffer,
        passphrase: string,
        options?: unknown,
      ) => Promise<EncryptedEnvelope>;

      const envelope = await smuggle(bytes('payload'), PASSPHRASE, options);

      assert.equal(envelope.kdf.n, 131072, `n was weakened by ${label}`);
      assert.equal(envelope.kdf.r, 8, `r was weakened by ${label}`);
      assert.equal(envelope.kdf.p, 1, `p was weakened by ${label}`);
      assert.equal(envelope.kdf.name, 'scrypt');
    });
  }

  test('every seal in a batch writes the identical, full-strength cost', async () => {
    const envelopes = await Promise.all([
      seal(bytes('a'), PASSPHRASE),
      seal(bytes('b'), PASSPHRASE),
      seal(bytes('c'), PASSPHRASE),
    ]);
    for (const envelope of envelopes) {
      assert.deepEqual(
        { n: envelope.kdf.n, r: envelope.kdf.r, p: envelope.kdf.p },
        { n: 131072, r: 8, p: 1 },
      );
    }
  });
});

// ---------------------------------------------------------------------------
// Cipher interface conformance
// ---------------------------------------------------------------------------

describe('Cipher conformance', () => {
  test('the default export object exposes seal and open', () => {
    assert.equal(typeof cipher.seal, 'function');
    assert.equal(typeof cipher.open, 'function');
  });

  test('the exported object round-trips through its own methods', async () => {
    const envelope = await cipher.seal(bytes('via the interface'), PASSPHRASE);
    assert.ok((await cipher.open(envelope, PASSPHRASE)).equals(bytes('via the interface')));
  });

  test('both error types descend from VaultError and from Error', async () => {
    const envelope = await seal(bytes('payload'), PASSPHRASE);
    const wrong = await open(envelope, 'nope').catch((e: unknown) => e);
    const corrupt = await open({} as EncryptedEnvelope, PASSPHRASE).catch((e: unknown) => e);

    for (const error of [wrong, corrupt]) {
      assert.ok(error instanceof VaultError);
      assert.ok(error instanceof Error);
      assert.equal(typeof (error as VaultError).exitCode, 'number');
      assert.equal(typeof (error as VaultError).name, 'string');
    }
    assert.equal((wrong as Error).name, 'WrongPassphraseError');
    assert.equal((corrupt as Error).name, 'VaultCorruptError');
  });
});
