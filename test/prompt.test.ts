/**
 * Node t5 — terminal passphrase and secret input (no echo, no argv).
 *
 * Scenario map (see brief):
 *   t5-s1  hidden read in TTY mode resolves with what was typed; output gets
 *          only the prompt and a trailing newline
 *   t5-s2  backspace during a hidden read drops the previous character
 *   t5-s3  Ctrl-C during a hidden read rejects with AbortedError, exit 130
 *   t5-s4  non-TTY hidden read: one piped line, raw mode never touched
 *   t5-s5  readNewPassphrase: mismatched confirmation -> PassphraseMismatchError
 *   t5-s6  readNewPassphrase: too-short passphrase -> WeakPassphraseError
 *   t5-s7  readSecret({ fromStdin: true }) reads to EOF, strips one newline
 *   t5-a1  hidden input never reaches the output stream (shoulder-surf/record)
 *   t5-a2  raw mode is restored even when the input stream errors mid-read
 *   t5-a3  a hidden read rejects at the 4096-character cap instead of
 *          buffering an unbounded stream
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough, Readable, Writable } from 'node:stream';

import {
  readHidden,
  readNewPassphrase,
  readSecret,
  AbortedError,
  PassphraseMismatchError,
  WeakPassphraseError,
  InputTooLongError,
  VaultError,
  MAX_HIDDEN_INPUT_LENGTH,
} from '../src/prompt.ts';

// ---------------------------------------------------------------------------
// Test doubles
// ---------------------------------------------------------------------------

/** A `Writable` that records every chunk written to it as text, nothing else. */
function makeOutput() {
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
 * A `PassThrough` standing in for `process.stdin`, with a `setRawMode` spy in
 * the same shape a real `tty.ReadStream` exposes: a function that records
 * `isRaw` and every call it received, so a test can assert both what mode the
 * terminal ended up in and the exact sequence of transitions.
 */
function makeInput(isTTY: boolean) {
  const stream = new PassThrough();
  const rawModeCalls: boolean[] = [];
  return Object.assign(stream, {
    isTTY,
    isRaw: false,
    rawModeCalls,
    setRawMode(mode: boolean) {
      rawModeCalls.push(mode);
      this.isRaw = mode;
      return this;
    },
  });
}

function deps(input: ReturnType<typeof makeInput>, output: ReturnType<typeof makeOutput>) {
  return { input, output, isTTY: input.isTTY };
}

async function rejection(promise: Promise<unknown>): Promise<unknown> {
  return promise.then(
    (value) => assert.fail(`expected a rejection, resolved with ${JSON.stringify(value)}`),
    (error: unknown) => error,
  );
}

// ---------------------------------------------------------------------------
// t5-s1 — hidden read resolves with what was typed, output gets only the prompt
// ---------------------------------------------------------------------------

describe('t5-s1 readHidden in TTY mode', () => {
  test('resolves to the typed characters; output is exactly the prompt plus one newline', async () => {
    const input = makeInput(true);
    const output = makeOutput();

    const promise = readHidden('Passphrase: ', deps(input, output));
    for (const byte of ['s', '3', 'c', 'r', 'e', 't', '\n']) {
      input.write(byte);
    }

    const result = await promise;
    assert.equal(result, 's3cret');
    assert.equal(output.text(), 'Passphrase: \n');
  });
});

// ---------------------------------------------------------------------------
// t5-s2 — backspace
// ---------------------------------------------------------------------------

describe('t5-s2 backspace during a hidden read', () => {
  test("'abc\\x7fd\\n' resolves to 'abd'", async () => {
    const input = makeInput(true);
    const output = makeOutput();

    const promise = readHidden('Passphrase: ', deps(input, output));
    for (const byte of ['a', 'b', 'c', '\x7f', 'd', '\n']) {
      input.write(byte);
    }

    assert.equal(await promise, 'abd');
  });

  test('0x08 also erases the previous character', async () => {
    const input = makeInput(true);
    const output = makeOutput();

    const promise = readHidden('Passphrase: ', deps(input, output));
    input.write('ab\bc\n');

    assert.equal(await promise, 'ac');
  });

  test('backspace on an empty buffer is a no-op, not a throw', async () => {
    const input = makeInput(true);
    const output = makeOutput();

    const promise = readHidden('Passphrase: ', deps(input, output));
    input.write('\x7f\x7fok\n');

    assert.equal(await promise, 'ok');
  });
});

// ---------------------------------------------------------------------------
// t5-s3 — Ctrl-C
// ---------------------------------------------------------------------------

describe('t5-s3 Ctrl-C during a hidden read', () => {
  test('rejects with AbortedError (exit 130) and restores raw mode first', async () => {
    const input = makeInput(true);
    const output = makeOutput();

    const promise = readHidden('Passphrase: ', deps(input, output));
    input.write('partial');
    input.write(Buffer.from([0x03]));

    const error = (await rejection(promise)) as AbortedError;
    assert.ok(error instanceof AbortedError, `expected AbortedError, got ${error}`);
    assert.ok(error instanceof VaultError);
    assert.equal(error.exitCode, 130);
    assert.equal(input.rawModeCalls.at(-1), false);
  });
});

// ---------------------------------------------------------------------------
// t5-s4 — non-TTY hidden read
// ---------------------------------------------------------------------------

describe('t5-s4 readHidden in non-TTY mode', () => {
  test('reads one piped line and never touches raw mode', async () => {
    const input = makeInput(false);
    const output = makeOutput();

    const promise = readHidden('Passphrase: ', deps(input, output));
    input.write('piped-pass\n');

    assert.equal(await promise, 'piped-pass');
    assert.equal(input.rawModeCalls.length, 0);
  });

  test('a longer non-TTY line still round-trips exactly', async () => {
    const input = makeInput(false);
    const output = makeOutput();

    const promise = readHidden('Passphrase: ', deps(input, output));
    input.write('hunter2hunter2\n');

    assert.equal(await promise, 'hunter2hunter2');
  });
});

// ---------------------------------------------------------------------------
// t5-s5 — readNewPassphrase mismatch
// ---------------------------------------------------------------------------

describe('t5-s5 readNewPassphrase mismatch', () => {
  test('rejects with PassphraseMismatchError; prompts each shown once; message leaks neither value', async () => {
    const input = makeInput(true);
    const output = makeOutput();

    const promise = readNewPassphrase(deps(input, output));
    input.write('alpha1234\n');
    input.write('alpha4321\n');

    const error = (await rejection(promise)) as PassphraseMismatchError;
    assert.ok(error instanceof PassphraseMismatchError, `expected PassphraseMismatchError, got ${error}`);
    assert.equal(error.exitCode, 1);
    assert.doesNotMatch(error.message, /alpha1234/);
    assert.doesNotMatch(error.message, /alpha4321/);

    const text = output.text();
    assert.equal((text.match(/New passphrase: /g) ?? []).length, 1);
    assert.equal((text.match(/Confirm passphrase: /g) ?? []).length, 1);
  });
});

// ---------------------------------------------------------------------------
// t5-s6 — readNewPassphrase weak passphrase
// ---------------------------------------------------------------------------

describe('t5-s6 readNewPassphrase weak passphrase', () => {
  test('rejects with WeakPassphraseError stating the 8-character minimum, without asking to confirm', async () => {
    const input = makeInput(true);
    const output = makeOutput();

    const promise = readNewPassphrase(deps(input, output));
    input.write('short12\n');

    const error = (await rejection(promise)) as WeakPassphraseError;
    assert.ok(error instanceof WeakPassphraseError, `expected WeakPassphraseError, got ${error}`);
    assert.equal(error.exitCode, 1);
    assert.match(error.message, /8/);

    // Fails fast: never even asks the user to confirm an already-invalid passphrase.
    assert.doesNotMatch(output.text(), /Confirm passphrase: /);
  });

  test('a NUL byte in the passphrase is also rejected as weak', async () => {
    const input = makeInput(true);
    const output = makeOutput();

    const promise = readNewPassphrase(deps(input, output));
    input.write('abcdefg\u0000h\n');

    const error = (await rejection(promise)) as WeakPassphraseError;
    assert.ok(error instanceof WeakPassphraseError);
  });
});

describe('readNewPassphrase in non-TTY mode (supplementary — Steps 3)', () => {
  test('reads a single line and skips confirmation entirely', async () => {
    const input = makeInput(false);
    const output = makeOutput();

    const promise = readNewPassphrase(deps(input, output));
    input.write('a-fine-passphrase\n');

    assert.equal(await promise, 'a-fine-passphrase');
  });

  test('still enforces the strength check when piped', async () => {
    const input = makeInput(false);
    const output = makeOutput();

    const promise = readNewPassphrase(deps(input, output));
    input.write('short\n');

    const error = await rejection(promise);
    assert.ok(error instanceof WeakPassphraseError);
  });
});

// ---------------------------------------------------------------------------
// t5-s7 — readSecret from stdin
// ---------------------------------------------------------------------------

describe('t5-s7 readSecret({ fromStdin: true })', () => {
  test('reads to EOF and strips exactly one trailing newline', async () => {
    const input = makeInput(false);
    const output = makeOutput();

    const promise = readSecret(deps(input, output), { fromStdin: true });
    input.end('line one\nline two\n');

    assert.equal(await promise, 'line one\nline two');
  });

  test('a secret with no trailing newline round-trips unchanged', async () => {
    const input = makeInput(false);
    const output = makeOutput();

    const promise = readSecret(deps(input, output), { fromStdin: true });
    input.end('no-trailing-newline');

    assert.equal(await promise, 'no-trailing-newline');
  });

  test('readSecret without fromStdin delegates to a hidden "Secret: " prompt', async () => {
    const input = makeInput(true);
    const output = makeOutput();

    const promise = readSecret(deps(input, output));
    input.write('s3cret\n');

    assert.equal(await promise, 's3cret');
    assert.equal(output.text(), 'Secret: \n');
  });
});

// ---------------------------------------------------------------------------
// t5-a1 — hidden input never reaches the output stream
// ---------------------------------------------------------------------------

describe('t5-a1 shoulder-surf / terminal-recording resistance', () => {
  test('a captured output stream contains zero characters of the typed passphrase', async () => {
    const input = makeInput(true);
    const output = makeOutput();
    const sentinel = 'SENTINEL-PASS';

    const promise = readHidden('Passphrase: ', deps(input, output));
    input.write(`${sentinel}\n`);

    await promise;
    assert.doesNotMatch(output.text(), new RegExp(sentinel));

    // The fake `output` never echoes typed input regardless of raw-mode
    // state, so the assertion above holds even if raw mode were never
    // entered. What actually suppresses echo on a real terminal is entering
    // raw mode before reading and leaving it before returning -- assert that
    // sequence explicitly so a build that drops `setRawMode` fails here.
    assert.deepEqual(input.rawModeCalls, [true, false]);
  });
});

// ---------------------------------------------------------------------------
// t5-a2 — raw mode restored even when the stream errors
// ---------------------------------------------------------------------------

describe('t5-a2 raw mode restored on stream error', () => {
  test('setRawMode(false) has been called by the time the rejection propagates', async () => {
    const input = makeInput(true);
    const output = makeOutput();

    const promise = readHidden('Passphrase: ', deps(input, output));
    input.write('abc');
    input.destroy(new Error('stream exploded'));

    await rejection(promise);
    assert.equal(input.rawModeCalls.at(-1), false);
  });
});

// ---------------------------------------------------------------------------
// t5-a3 — capped instead of buffering an unbounded stream
// ---------------------------------------------------------------------------

describe('t5-a3 unbounded input is capped, not buffered', () => {
  /**
   * A `Readable` that manufactures data on demand rather than holding it all
   * up front, standing in for a process piping far more than 4096 bytes with
   * no newline. `produced` lets the test prove readHidden stopped pulling
   * long before anything close to 10 MiB was generated.
   */
  class DripFeed extends Readable {
    produced = 0;

    override _read(): void {
      this.produced += 1024;
      this.push(Buffer.alloc(1024, 'a'));
    }
  }

  test('rejects once the 4096-character cap is passed, without draining the stream', async () => {
    const input = Object.assign(new DripFeed(), { isTTY: false });
    const output = makeOutput();

    const promise = readHidden('Secret: ', { input, output, isTTY: false });

    const error = (await rejection(promise)) as InputTooLongError;
    assert.ok(error instanceof InputTooLongError, `expected InputTooLongError, got ${error}`);
    assert.equal(error.exitCode, 1);

    // Ten MiB would be 10 * 1024 * 1024 bytes; this stays orders of magnitude
    // below that, proving the cap trips well before the stream is drained.
    assert.ok(
      input.produced < 1024 * 1024,
      `expected far fewer than 1 MiB pulled from the stream, got ${input.produced}`,
    );
    assert.ok(input.produced >= MAX_HIDDEN_INPUT_LENGTH);
  });
});
