/**
 * Terminal passphrase and secret input: read a line from a stream without
 * ever echoing it back, and without ever accepting it as a command-line
 * argument (argv is world-readable via `/proc/<pid>/cmdline` and shell
 * history; a prompt is neither).
 *
 * Every function here takes its `input`/`output`/`isTTY` as an explicit
 * dependency rather than reaching for `process.stdin`/`process.stdout`
 * itself. That is what makes it possible to drive a hidden read from a test
 * with a plain `PassThrough`, and it is also what makes piped stdin work:
 * the caller decides once, from `process.stdin.isTTY`, which mode applies,
 * and everything below just follows it.
 *
 * `src/types.ts` carries the shared `VaultError` base and its exit-code
 * table. The errors this module adds (`AbortedError`, `PassphraseMismatchError`,
 * `WeakPassphraseError`, `InputTooLongError`) are not part of that file --
 * this node owns only `src/prompt.ts` and `test/prompt.test.ts` -- so they
 * are declared here, extending the shared base, rather than in `types.ts`.
 * They follow its existing exit-code convention: 130 for a Ctrl-C abort
 * (standard shell convention: 128 + SIGINT's signal number 2), 1 for
 * everything else here, since each is the caller's input failing to qualify.
 */
import { StringDecoder } from 'node:string_decoder';
import { VaultError } from "./types.js";
export { VaultError };
// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------
/** The user cancelled a hidden read with Ctrl-C (0x03). */
export class AbortedError extends VaultError {
    code = 'ABORTED';
    exitCode = 130;
    constructor(message = 'aborted') {
        super(message);
    }
}
/**
 * `readNewPassphrase`'s two reads did not agree.
 *
 * The default message deliberately never interpolates either typed value --
 * this error is exactly the kind of thing a caller might let bubble up to a
 * terminal or a log, and neither passphrase belongs there.
 */
export class PassphraseMismatchError extends VaultError {
    code = 'PASSPHRASE_MISMATCH';
    exitCode = 1;
    constructor(message = 'passphrases did not match') {
        super(message);
    }
}
/** A new passphrase is too short, or contains a NUL byte. */
export class WeakPassphraseError extends VaultError {
    code = 'WEAK_PASSPHRASE';
    exitCode = 1;
    constructor(message) {
        super(message);
    }
}
/** A single hidden read exceeded `MAX_HIDDEN_INPUT_LENGTH` characters. */
export class InputTooLongError extends VaultError {
    code = 'INPUT_TOO_LONG';
    exitCode = 1;
    constructor(message = `input exceeds the ${MAX_HIDDEN_INPUT_LENGTH}-character limit`) {
        super(message);
    }
}
/**
 * A read that never terminates (no `\n`, no EOF) must still fail rather than
 * grow forever -- this is the bound that turns "pipe gigabytes with no
 * newline into a hidden prompt" from an unbounded allocation into a fast,
 * cheap rejection. 4096 characters comfortably exceeds any real passphrase
 * or credential.
 */
export const MAX_HIDDEN_INPUT_LENGTH = 4096;
const MIN_PASSPHRASE_LENGTH = 8;
const readerState = new WeakMap();
function getReaderState(input) {
    let state = readerState.get(input);
    if (!state) {
        state = {
            queue: '',
            pos: 0,
            // destroyOnReturn: false -- a prompt that resolves without reaching
            // EOF must leave `input` intact for the next prompt to read from.
            iter: input.iterator({ destroyOnReturn: false }),
            decoder: new StringDecoder('utf8'),
        };
        readerState.set(input, state);
    }
    return state;
}
function toBuffer(value) {
    return Buffer.isBuffer(value) ? value : Buffer.from(String(value), 'utf8');
}
/** The next decoded character from `input`, or `null` at EOF. */
async function nextChar(input) {
    const state = getReaderState(input);
    while (state.pos >= state.queue.length) {
        const { value, done } = await state.iter.next();
        if (done) {
            return null;
        }
        state.queue = state.decoder.write(toBuffer(value));
        state.pos = 0;
    }
    const ch = state.queue.charAt(state.pos);
    state.pos += 1;
    return ch;
}
// ---------------------------------------------------------------------------
// readHidden
// ---------------------------------------------------------------------------
/**
 * Read one line from `input` without ever echoing it to `output`.
 *
 * In TTY mode this puts `input` into raw mode so keystrokes never reach the
 * terminal's own line-editing/echo layer, interprets backspace itself, and
 * treats Ctrl-C as cancellation. Raw mode is always restored to whatever it
 * was before this call, and exactly one newline is written to `output`, even
 * when the read is aborted or the stream errors.
 *
 * In non-TTY mode `input` is a pipe, not a terminal -- there is no echo to
 * suppress and no raw mode to enter -- so this just reads one line.
 */
export function readHidden(promptText, { input, output, isTTY }) {
    return isTTY ? readHiddenTTY(promptText, input, output) : readLinePiped(input);
}
async function readHiddenTTY(promptText, input, output) {
    output.write(promptText);
    const rawInput = input;
    const previousRaw = Boolean(rawInput.isRaw);
    let buffer = '';
    try {
        rawInput.setRawMode?.(true);
        for (;;) {
            const ch = await nextChar(input);
            if (ch === null || ch === '\r' || ch === '\n') {
                return buffer;
            }
            const code = ch.codePointAt(0) ?? 0;
            if (code === 0x03) {
                throw new AbortedError();
            }
            if (code === 0x7f || code === 0x08) {
                buffer = buffer.slice(0, -1);
                continue;
            }
            buffer += ch;
            if (buffer.length > MAX_HIDDEN_INPUT_LENGTH) {
                throw new InputTooLongError();
            }
        }
    }
    finally {
        rawInput.setRawMode?.(previousRaw);
        output.write('\n');
    }
}
async function readLinePiped(input) {
    let buffer = '';
    for (;;) {
        const ch = await nextChar(input);
        if (ch === null || ch === '\n') {
            return buffer;
        }
        buffer += ch;
        if (buffer.length > MAX_HIDDEN_INPUT_LENGTH) {
            throw new InputTooLongError();
        }
    }
}
// ---------------------------------------------------------------------------
// readNewPassphrase
// ---------------------------------------------------------------------------
/**
 * Prompt for a new passphrase and, in TTY mode, a confirmation.
 *
 * The strength check runs immediately after the first read and before the
 * confirmation prompt: there is no reason to make a user re-type a
 * passphrase that is already going to be rejected. In non-TTY mode there is
 * no second keystroke stream to confirm against -- confirmation exists to
 * catch a mistyped keystroke, which cannot happen when the value was piped
 * in verbatim -- so only one line is read.
 */
export async function readNewPassphrase(deps) {
    const first = await readHidden('New passphrase: ', deps);
    assertPassphraseStrength(first);
    if (!deps.isTTY) {
        return first;
    }
    const confirmation = await readHidden('Confirm passphrase: ', deps);
    if (confirmation !== first) {
        throw new PassphraseMismatchError();
    }
    return first;
}
function assertPassphraseStrength(passphrase) {
    if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
        throw new WeakPassphraseError(`passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters long`);
    }
    if (passphrase.includes('\u0000')) {
        throw new WeakPassphraseError('passphrase must not contain a NUL byte');
    }
}
// ---------------------------------------------------------------------------
// readSecret
// ---------------------------------------------------------------------------
/**
 * Read the secret to store.
 *
 * `fromStdin` reads the entire stream to EOF rather than stopping at the
 * first newline, so a multi-line credential (a PEM key, say) redirected from
 * a file survives intact; exactly one trailing newline is stripped, since
 * that is what a shell redirect or `printf` typically appends and it is not
 * part of the secret. It is deliberately not subject to
 * `MAX_HIDDEN_INPUT_LENGTH` -- that cap exists to bound an interactive
 * keystroke read with no natural end, not a redirect whose end is EOF.
 * Otherwise this is an ordinary hidden read.
 */
export async function readSecret(deps, { fromStdin = false } = {}) {
    if (fromStdin) {
        return readAllToEof(deps.input);
    }
    return readHidden('Secret: ', deps);
}
async function readAllToEof(input) {
    const state = getReaderState(input);
    const parts = [];
    if (state.pos < state.queue.length) {
        parts.push(state.queue.slice(state.pos));
        state.pos = state.queue.length;
    }
    for (;;) {
        const { value, done } = await state.iter.next();
        if (done) {
            break;
        }
        parts.push(state.decoder.write(toBuffer(value)));
    }
    parts.push(state.decoder.end());
    const text = parts.join('');
    return text.endsWith('\n') ? text.slice(0, -1) : text;
}
