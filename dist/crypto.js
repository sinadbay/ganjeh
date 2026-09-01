/**
 * Passphrase encryption envelope: scrypt key derivation + AES-256-GCM.
 *
 * The vault file on disk is one `EncryptedEnvelope`, serialised as JSON. It is
 * fully self-describing: everything needed to derive the key again — bar the
 * passphrase — travels with the ciphertext.
 *
 * Two rules drive the shape of this module.
 *
 * 1. The envelope is untrusted input. It arrives from a file an attacker may
 *    have edited. Every field is validated for type, length and range before
 *    it reaches a cryptographic primitive; in particular the KDF cost factors
 *    are checked *before* any derivation is attempted, so a hostile file
 *    cannot turn `open` into a memory bomb, and cannot quietly weaken the
 *    work factor either.
 *
 * 2. Failures do not leak an oracle. Structural damage and an unusable
 *    passphrase are distinct error *types*, because the CLI needs to tell a
 *    user with a typo apart from a user with a damaged file. But the message
 *    on an authentication failure stays non-committal: a tampered ciphertext
 *    and a mistyped passphrase are indistinguishable to AES-GCM, and the text
 *    must not claim otherwise.
 */
import { createCipheriv, createDecipheriv, randomBytes, scrypt } from 'node:crypto';
// The shared error taxonomy and types now live in one module. They are
// re-exported here so this module's public surface is unchanged for every
// caller and test that imported them from this file.
import { VaultError, WrongPassphraseError, VaultCorruptError, } from "./types.js";
export { VaultError, WrongPassphraseError, VaultCorruptError, };
// ---------------------------------------------------------------------------
// Envelope format
// ---------------------------------------------------------------------------
export const ENVELOPE_VERSION = 1;
const CIPHER_ALGORITHM = 'aes-256-gcm';
// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------
/**
 * The one, non-negotiable cost factor this build writes. `seal` builds its
 * KDF block from this and nothing else — never from a caller argument, never
 * by copying the block out of an envelope being re-sealed.
 */
export const KDF_PARAMS = { name: 'scrypt', n: 131072, r: 8, p: 1 };
export const KEY_LEN = 32;
export const SALT_LEN = 16;
export const NONCE_LEN = 12;
const AUTH_TAG_LEN = 16;
/**
 * Accepted cost factors for a vault file.
 *
 * The floor matters as much as the ceiling: a file claiming n = 2 would derive
 * instantly and be trivial to crack offline, so we refuse to open it at all
 * rather than hand back plaintext that was never meaningfully protected. The
 * floor is 2^15 — half what we write, which leaves room for a vault sealed by
 * an older build without accepting a cost the spec never permitted.
 *
 * `r` and `p` are not a range. The spec fixes them at 8 and 1, and a file
 * naming anything else is either damaged or an attacker asking for a weaker
 * derivation; r = 1 alone cuts the work, and the memory, by a factor of eight.
 * Accepting a range here would be accepting a downgrade.
 */
const MIN_N = 32768; //  2^15
const MAX_N = 1_048_576; //  2^20
const REQUIRED_R = 8;
const REQUIRED_P = 1;
/** Cap on how much of an untrusted value is quoted back in an error message. */
const MAX_ECHOED_VALUE_CHARS = 40;
/**
 * scrypt's working set is 128 * N * r bytes. Node's default `maxmem` is 32
 * MiB, below what the production cost factor needs (128 MiB), so this grants
 * a budget with headroom while still capping what a hostile `n` can demand.
 * Note this is tighter than the raw [MIN_N, MAX_N] range alone would allow at
 * r = 8 — n = MAX_N would ask for 1 GiB, over this budget — so this check
 * rejects some in-range-looking values that the range check alone would not.
 * That is intentional: it is an additional safeguard, not a relaxation of the
 * spec's floor or ceiling.
 */
const MAX_KDF_MEMORY_BYTES = 256 * 1024 * 1024;
// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Untrusted-input helpers
// ---------------------------------------------------------------------------
function isPlainRecord(value) {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function readField(source, key) {
    // Own properties only, so an inherited or prototype-injected value can never
    // stand in for a field the file failed to supply.
    return Object.hasOwn(source, key) ? source[key] : undefined;
}
/**
 * Render an untrusted value for an error message.
 *
 * These messages end up on a terminal. A vault file can name its algorithm
 * with a megabyte of text, or with ANSI escape sequences that rewrite what the
 * user sees, so the value is stripped of control characters and capped before
 * it is quoted back.
 */
function describeUntrusted(value) {
    if (typeof value !== 'string') {
        return typeof value === 'number' || typeof value === 'boolean' || value === null
            ? String(value)
            : Object.prototype.toString.call(value);
    }
    // eslint-disable-next-line no-control-regex
    const printable = value.replace(/[\u0000-\u001f\u007f-\u009f]/g, '?');
    const clipped = printable.length > MAX_ECHOED_VALUE_CHARS
        ? `${printable.slice(0, MAX_ECHOED_VALUE_CHARS)}...`
        : printable;
    return JSON.stringify(clipped);
}
function requireString(source, key, where) {
    const value = readField(source, key);
    if (typeof value !== 'string') {
        throw new VaultCorruptError(`${where}.${key} must be a string`);
    }
    return value;
}
/** Canonical, padded base64 and nothing else — no whitespace, no base64url. */
const CANONICAL_BASE64 = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
/**
 * Decode base64 strictly.
 *
 * `Buffer.from(s, 'base64')` silently discards anything it does not recognise,
 * so stray characters vanish and the result still looks well-formed — a salt
 * with a `!` spliced into it decodes to the same 16 bytes and sails past a
 * length check. The shape is therefore checked before decoding, not inferred
 * from the decoded output.
 */
function decodeBase64(value, expectedBytes, where) {
    if (!CANONICAL_BASE64.test(value)) {
        throw new VaultCorruptError(`${where} is not valid base64`);
    }
    const decoded = Buffer.from(value, 'base64');
    if (expectedBytes !== null) {
        if (decoded.length !== expectedBytes) {
            throw new VaultCorruptError(`${where} must decode to ${expectedBytes} bytes, got ${decoded.length}`);
        }
        // The alphabet is right and the length is right, but the final quantum can
        // still carry bits that no encoder would emit. Re-encoding is cheap on
        // these fixed-size fields, and it pins them to exactly one representation.
        if (decoded.toString('base64') !== value) {
            throw new VaultCorruptError(`${where} is not canonically encoded`);
        }
    }
    return decoded;
}
// ---------------------------------------------------------------------------
// KDF parameter validation
// ---------------------------------------------------------------------------
/**
 * Validate a KDF block from an untrusted envelope.
 *
 * Every call path into scrypt goes through here first — this is the gate that
 * keeps a hostile cost factor from ever reaching the primitive. Throws
 * `VaultCorruptError` on anything out of range, and does so synchronously, so
 * a caller measuring wall-clock time can see that scrypt was never invoked.
 */
export function validateKdfParams(input) {
    if (!isPlainRecord(input)) {
        throw new VaultCorruptError('kdf block must be an object');
    }
    const name = readField(input, 'name');
    if (name !== 'scrypt') {
        throw new VaultCorruptError(`unsupported kdf.name ${describeUntrusted(name)}; expected "scrypt"`);
    }
    const n = readField(input, 'n');
    if (typeof n !== 'number' || !Number.isInteger(n) || n < MIN_N || n > MAX_N) {
        throw new VaultCorruptError(`kdf.n must be an integer between ${MIN_N} and ${MAX_N}, got ${describeUntrusted(n)}`);
    }
    // scrypt itself requires this; checking it here keeps the rejection a plain
    // arithmetic comparison rather than a round trip through the primitive.
    if ((n & (n - 1)) !== 0) {
        throw new VaultCorruptError(`kdf.n must be a power of two, got ${n}`);
    }
    const r = readField(input, 'r');
    if (r !== REQUIRED_R) {
        throw new VaultCorruptError(`kdf.r must be exactly ${REQUIRED_R}, got ${describeUntrusted(r)}`);
    }
    const p = readField(input, 'p');
    if (p !== REQUIRED_P) {
        throw new VaultCorruptError(`kdf.p must be exactly ${REQUIRED_P}, got ${describeUntrusted(p)}`);
    }
    // Each factor is individually in range, but the product still has to fit.
    const memoryBytes = 128 * n * r;
    if (memoryBytes > MAX_KDF_MEMORY_BYTES) {
        throw new VaultCorruptError(`kdf parameters would need ${Math.round(memoryBytes / 1024 / 1024)} MiB, ` +
            `over the ${MAX_KDF_MEMORY_BYTES / 1024 / 1024} MiB budget`);
    }
    return { name, n, r, p };
}
// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------
/**
 * Derive the AES key for `saltB64` under `params`.
 *
 * `params` is untrusted whenever this is called from `open` — it may be
 * whatever an attacker wrote into the envelope's `kdf` block. It is
 * range-checked here before scrypt is invoked, so a hostile cost factor is
 * rejected synchronously rather than attempted and left to fail slowly (or
 * not fail at all, and simply cost far more than the spec allows).
 */
function deriveKey(passphrase, saltB64, params) {
    const validated = validateKdfParams(params);
    const salt = decodeBase64(saltB64, SALT_LEN, 'saltB64');
    return new Promise((resolve, reject) => {
        scrypt(Buffer.from(passphrase, 'utf8'), salt, KEY_LEN, {
            N: validated.n,
            r: validated.r,
            p: validated.p,
            maxmem: MAX_KDF_MEMORY_BYTES,
        }, (error, key) => {
            if (error) {
                // Unreachable for validated parameters; surfaced rather than
                // swallowed so a future range change cannot fail silently.
                reject(new VaultCorruptError(`key derivation failed: ${error.message}`));
                return;
            }
            resolve(key);
        });
    });
}
/** Overwrite derived key material once we are done with it. */
function wipe(buffer) {
    buffer.fill(0);
}
// ---------------------------------------------------------------------------
// seal / open
// ---------------------------------------------------------------------------
/**
 * Encrypt `plaintext` under `passphrase` and return a self-describing envelope.
 *
 * The work factor is not a parameter, and that is the whole point. A caller
 * cannot ask for a cheaper one, because in practice the caller is a CLI flag,
 * a config file, or a re-seal copying the params out of the envelope it just
 * opened — and every one of those is a route by which a vault silently becomes
 * cheaper to crack offline while every other test still passes. There is no
 * options argument to forward such a value into. If the cost ever has to
 * change, it changes here, in `KDF_PARAMS`, for everyone at once.
 */
export async function seal(plaintext, passphrase) {
    // A caller bug, not a damaged file: say so with the ordinary JS error rather
    // than sending someone off to inspect a vault that is perfectly intact.
    if (!Buffer.isBuffer(plaintext)) {
        throw new TypeError('seal(): plaintext must be a Buffer');
    }
    if (typeof passphrase !== 'string') {
        throw new TypeError('seal(): passphrase must be a string');
    }
    const saltB64 = randomBytes(SALT_LEN).toString('base64');
    const key = await deriveKey(passphrase, saltB64, KDF_PARAMS);
    try {
        // A fresh 96-bit nonce per seal. Combined with the fresh salt, the key is
        // new every time too, so nonce reuse would need two simultaneous failures.
        const nonce = randomBytes(NONCE_LEN);
        const aes = createCipheriv(CIPHER_ALGORITHM, key, nonce, { authTagLength: AUTH_TAG_LEN });
        const ciphertext = Buffer.concat([aes.update(plaintext), aes.final()]);
        const authTag = aes.getAuthTag();
        return {
            version: ENVELOPE_VERSION,
            cipher: CIPHER_ALGORITHM,
            kdf: { name: KDF_PARAMS.name, n: KDF_PARAMS.n, r: KDF_PARAMS.r, p: KDF_PARAMS.p },
            saltB64,
            nonceB64: nonce.toString('base64'),
            // The auth tag travels appended to the ciphertext, not as a field of
            // its own — `open` splits the last AUTH_TAG_LEN bytes back off.
            ciphertextB64: Buffer.concat([ciphertext, authTag]).toString('base64'),
        };
    }
    finally {
        wipe(key);
    }
}
/**
 * Decrypt an envelope and return the exact bytes that were sealed.
 *
 * `envelope` is untrusted: it is whatever was on disk. Nothing here assumes it
 * came from `seal`.
 */
export async function open(envelope, passphrase) {
    if (typeof passphrase !== 'string') {
        throw new TypeError('open(): passphrase must be a string');
    }
    if (!isPlainRecord(envelope)) {
        throw new VaultCorruptError('envelope must be an object');
    }
    const version = readField(envelope, 'version');
    if (version !== ENVELOPE_VERSION) {
        throw new VaultCorruptError(`unsupported envelope version ${describeUntrusted(version)}; this build reads version ${ENVELOPE_VERSION}`);
    }
    const cipherName = readField(envelope, 'cipher');
    if (cipherName !== CIPHER_ALGORITHM) {
        throw new VaultCorruptError(`unsupported cipher ${describeUntrusted(cipherName)}; expected ${JSON.stringify(CIPHER_ALGORITHM)}`);
    }
    // Range-check the cost factors before anything expensive happens.
    const kdf = readField(envelope, 'kdf');
    validateKdfParams(kdf);
    const nonceB64 = requireString(envelope, 'nonceB64', 'envelope');
    const ciphertextB64 = requireString(envelope, 'ciphertextB64', 'envelope');
    const saltB64 = requireString(envelope, 'saltB64', 'envelope');
    const nonce = decodeBase64(nonceB64, NONCE_LEN, 'nonceB64');
    const combined = decodeBase64(ciphertextB64, null, 'ciphertextB64');
    if (combined.length < AUTH_TAG_LEN) {
        throw new VaultCorruptError(`ciphertextB64 must decode to at least ${AUTH_TAG_LEN} bytes, got ${combined.length}`);
    }
    const ciphertext = combined.subarray(0, combined.length - AUTH_TAG_LEN);
    const authTag = combined.subarray(combined.length - AUTH_TAG_LEN);
    const key = await deriveKey(passphrase, saltB64, kdf);
    try {
        const aes = createDecipheriv(CIPHER_ALGORITHM, key, nonce, { authTagLength: AUTH_TAG_LEN });
        aes.setAuthTag(authTag);
        try {
            // Bytes out, exactly as they went in. Decoding here would be lossy for
            // anything that is not valid UTF-8, and this layer has no business
            // deciding that a vault's contents are text.
            return Buffer.concat([aes.update(ciphertext), aes.final()]);
        }
        catch {
            // GCM rejected the tag. Whether that is a typo or a tampered file is not
            // knowable here, and the message must not pretend otherwise.
            throw new WrongPassphraseError();
        }
    }
    finally {
        wipe(key);
    }
}
/** The `Cipher` this node provides to the rest of the vault. */
export const cipher = { seal, open };
export default cipher;
