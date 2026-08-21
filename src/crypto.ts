/**
 * Passphrase encryption envelope: scrypt key derivation + AES-256-GCM.
 *
 * The vault file on disk is one `Envelope`, serialised as JSON. It is fully
 * self-describing: everything needed to derive the key again — bar the
 * passphrase — travels with the ciphertext.
 *
 * Two rules drive the shape of this module.
 *
 * 1. The envelope is untrusted input. It arrives from a file an attacker may
 *    have edited. Every field is validated for type, length and range before
 *    it reaches a cryptographic primitive; in particular the KDF cost factors
 *    are checked *before* any derivation is attempted, so a hostile file
 *    cannot turn `vault open` into a memory bomb, and cannot quietly weaken
 *    the work factor either.
 *
 * 2. Failures do not leak an oracle. Structural damage and an unusable
 *    passphrase are distinct error *types*, because the CLI needs to tell a
 *    user with a typo apart from a user with a damaged file. But the message
 *    on an authentication failure stays non-committal: a tampered ciphertext
 *    and a mistyped passphrase are indistinguishable to AES-GCM, and the text
 *    must not claim otherwise.
 */

import { createCipheriv, createDecipheriv, randomBytes, scrypt } from 'node:crypto';

// ---------------------------------------------------------------------------
// Envelope format
// ---------------------------------------------------------------------------

export const ENVELOPE_VERSION = 1 as const;

export interface KdfBlock {
  readonly algorithm: 'scrypt';
  readonly n: number;
  readonly r: number;
  readonly p: number;
  readonly keyLength: number;
  /** base64, exactly `SALT_BYTES` bytes once decoded */
  readonly salt: string;
}

export interface CipherBlock {
  readonly algorithm: 'aes-256-gcm';
  /** base64, exactly `IV_BYTES` bytes once decoded */
  readonly iv: string;
  /** base64, exactly `AUTH_TAG_BYTES` bytes once decoded */
  readonly authTag: string;
  /** base64 */
  readonly ciphertext: string;
}

export interface Envelope {
  version: typeof ENVELOPE_VERSION;
  kdf: KdfBlock;
  cipher: CipherBlock;
}

export interface SealOptions {
  /** Override the KDF cost. Overrides are validated exactly like a file's. */
  readonly kdf?: Partial<Pick<KdfBlock, 'n' | 'r' | 'p'>>;
}

/**
 * The contract this module fulfils. Once `src/types.ts` lands with the shared
 * `Cipher` interface, this local declaration should be deleted and the type
 * imported from there instead; the shapes are structurally identical, so the
 * exported `cipher` object will satisfy it unchanged.
 */
export interface Cipher {
  seal(plaintext: string, passphrase: string, options?: SealOptions): Promise<Envelope>;
  open(envelope: Envelope, passphrase: string): Promise<string>;
}

// ---------------------------------------------------------------------------
// Parameters
// ---------------------------------------------------------------------------

export const DEFAULT_KDF = {
  algorithm: 'scrypt',
  n: 131072,
  r: 8,
  p: 1,
  keyLength: 32,
  saltBytes: 16,
} as const;

const CIPHER_ALGORITHM = 'aes-256-gcm' as const;
const SALT_BYTES = DEFAULT_KDF.saltBytes;
const KEY_BYTES = DEFAULT_KDF.keyLength;
/** GCM's native nonce size. Anything else forces a slower, weaker GHASH path. */
const IV_BYTES = 12;
const AUTH_TAG_BYTES = 16;

/**
 * Accepted range for cost factors read out of a vault file.
 *
 * The floor matters as much as the ceiling: a file claiming n = 2 would derive
 * instantly and be trivial to crack offline, so we refuse to open it at all
 * rather than hand back plaintext that was never meaningfully protected.
 */
const MIN_N = 16384; //  2^14
const MAX_N = 1_048_576; //  2^20
const MIN_R = 1;
const MAX_R = 32;
const MIN_P = 1;
const MAX_P = 16;

/** scrypt's working set is 128 * N * r bytes. Cap it so a file cannot OOM us. */
const MAX_KDF_MEMORY_BYTES = 256 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

export abstract class VaultError extends Error {
  abstract readonly code: string;
  abstract readonly exitCode: number;

  protected constructor(message: string) {
    super(message);
    this.name = new.target.name;
    Error.captureStackTrace?.(this, new.target);
  }
}

/**
 * Authentication failed. The passphrase does not derive a key that opens this
 * envelope — which also happens when the ciphertext has been altered. The
 * message deliberately commits to neither explanation.
 */
export class WrongPassphraseError extends VaultError {
  readonly code = 'WRONG_PASSPHRASE';
  readonly exitCode = 3;

  constructor(
    message = 'Unable to decrypt the vault: the passphrase does not match, or the contents have been altered.',
  ) {
    super(message);
  }
}

/** The envelope is not a well-formed, in-range vault. */
export class VaultCorruptError extends VaultError {
  readonly code = 'VAULT_CORRUPT';
  readonly exitCode = 4;

  constructor(detail: string) {
    super(`Vault file is not readable: ${detail}`);
  }
}

// ---------------------------------------------------------------------------
// Untrusted-input helpers
// ---------------------------------------------------------------------------

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readField(source: Record<string, unknown>, key: string): unknown {
  // Own properties only, so an inherited or prototype-injected value can never
  // stand in for a field the file failed to supply.
  return Object.hasOwn(source, key) ? source[key] : undefined;
}

function requireString(source: Record<string, unknown>, key: string, where: string): string {
  const value = readField(source, key);
  if (typeof value !== 'string') {
    throw new VaultCorruptError(`${where}.${key} must be a string`);
  }
  return value;
}

/**
 * Decode base64 strictly.
 *
 * `Buffer.from(s, 'base64')` silently discards anything it does not recognise,
 * so `"!!!!"` decodes to an empty buffer rather than failing. Round-tripping
 * the result back to base64 and demanding an exact match rejects input that
 * was only accepted by that leniency.
 */
function decodeBase64(value: string, expectedBytes: number | null, where: string): Buffer {
  const decoded = Buffer.from(value, 'base64');
  if (decoded.toString('base64') !== value) {
    throw new VaultCorruptError(`${where} is not valid base64`);
  }
  if (expectedBytes !== null && decoded.length !== expectedBytes) {
    throw new VaultCorruptError(
      `${where} must decode to ${expectedBytes} bytes, got ${decoded.length}`,
    );
  }
  return decoded;
}

function requireBoundedInteger(
  value: unknown,
  name: string,
  min: number,
  max: number,
): number {
  if (typeof value !== 'number' || !Number.isInteger(value)) {
    throw new VaultCorruptError(`kdf.${name} must be an integer`);
  }
  if (value < min || value > max) {
    throw new VaultCorruptError(`kdf.${name} must be between ${min} and ${max}, got ${value}`);
  }
  return value;
}

// ---------------------------------------------------------------------------
// KDF parameter validation
// ---------------------------------------------------------------------------

export interface ValidatedKdfParams {
  readonly algorithm: 'scrypt';
  readonly n: number;
  readonly r: number;
  readonly p: number;
  readonly keyLength: number;
  readonly salt: Buffer;
}

/**
 * Validate a KDF block from an untrusted envelope.
 *
 * Every call path into scrypt goes through here first — this is the gate that
 * keeps a hostile cost factor from ever reaching the primitive. Throws
 * `VaultCorruptError` on anything out of range.
 */
export function validateKdfParams(input: unknown): ValidatedKdfParams {
  if (!isPlainRecord(input)) {
    throw new VaultCorruptError('kdf block must be an object');
  }

  const algorithm = readField(input, 'algorithm');
  if (algorithm !== 'scrypt') {
    throw new VaultCorruptError(
      `unsupported kdf.algorithm ${JSON.stringify(algorithm)}; expected "scrypt"`,
    );
  }

  const n = requireBoundedInteger(readField(input, 'n'), 'n', MIN_N, MAX_N);
  if ((n & (n - 1)) !== 0) {
    throw new VaultCorruptError(`kdf.n must be a power of two, got ${n}`);
  }

  const r = requireBoundedInteger(readField(input, 'r'), 'r', MIN_R, MAX_R);
  const p = requireBoundedInteger(readField(input, 'p'), 'p', MIN_P, MAX_P);

  const keyLength = readField(input, 'keyLength');
  if (keyLength !== KEY_BYTES) {
    throw new VaultCorruptError(
      `kdf.keyLength must be ${KEY_BYTES} for ${CIPHER_ALGORITHM}, got ${String(keyLength)}`,
    );
  }

  // Each factor is individually in range, but the product still has to fit.
  const memoryBytes = 128 * n * r;
  if (memoryBytes > MAX_KDF_MEMORY_BYTES) {
    throw new VaultCorruptError(
      `kdf parameters would need ${Math.round(memoryBytes / 1024 / 1024)} MiB, ` +
        `over the ${MAX_KDF_MEMORY_BYTES / 1024 / 1024} MiB budget`,
    );
  }

  const salt = decodeBase64(requireString(input, 'salt', 'kdf'), SALT_BYTES, 'kdf.salt');

  return { algorithm, n, r, p, keyLength, salt };
}

// ---------------------------------------------------------------------------
// Key derivation
// ---------------------------------------------------------------------------

function deriveKey(passphrase: string, params: ValidatedKdfParams): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    scrypt(
      Buffer.from(passphrase, 'utf8'),
      params.salt,
      params.keyLength,
      {
        N: params.n,
        r: params.r,
        p: params.p,
        // Node's default maxmem is 32 MiB, below what the production cost
        // factor needs. Grant exactly the budget validation already enforced.
        maxmem: MAX_KDF_MEMORY_BYTES,
      },
      (error, key) => {
        if (error) {
          // Unreachable for validated parameters; surfaced rather than
          // swallowed so a future range change cannot fail silently.
          reject(new VaultCorruptError(`key derivation failed: ${error.message}`));
          return;
        }
        resolve(key as Buffer);
      },
    );
  });
}

/**
 * Bind the header to the ciphertext as GCM associated data.
 *
 * Without this an attacker could edit the cost factors, or the version, and
 * the tag would still verify — the header would be unauthenticated metadata.
 * Authenticating a canonical rendering of it means any in-range edit becomes
 * an authentication failure instead of a silent downgrade.
 */
function associatedData(version: number, kdf: ValidatedKdfParams): Buffer {
  return Buffer.from(
    JSON.stringify({
      version,
      algorithm: CIPHER_ALGORITHM,
      kdf: {
        algorithm: kdf.algorithm,
        n: kdf.n,
        r: kdf.r,
        p: kdf.p,
        keyLength: kdf.keyLength,
        salt: kdf.salt.toString('base64'),
      },
    }),
    'utf8',
  );
}

/** Overwrite derived key material once we are done with it. */
function wipe(buffer: Buffer): void {
  buffer.fill(0);
}

// ---------------------------------------------------------------------------
// seal / open
// ---------------------------------------------------------------------------

export async function seal(
  plaintext: string,
  passphrase: string,
  options: SealOptions = {},
): Promise<Envelope> {
  if (typeof plaintext !== 'string') {
    throw new VaultCorruptError('plaintext must be a string');
  }
  if (typeof passphrase !== 'string') {
    throw new VaultCorruptError('passphrase must be a string');
  }

  const salt = randomBytes(SALT_BYTES);
  const params = validateKdfParams({
    algorithm: DEFAULT_KDF.algorithm,
    n: options.kdf?.n ?? DEFAULT_KDF.n,
    r: options.kdf?.r ?? DEFAULT_KDF.r,
    p: options.kdf?.p ?? DEFAULT_KDF.p,
    keyLength: DEFAULT_KDF.keyLength,
    salt: salt.toString('base64'),
  });

  const key = await deriveKey(passphrase, params);
  try {
    // A fresh 96-bit nonce per seal. Combined with the fresh salt, the key is
    // new every time too, so nonce reuse would need two simultaneous failures.
    const iv = randomBytes(IV_BYTES);
    const aes = createCipheriv(CIPHER_ALGORITHM, key, iv, { authTagLength: AUTH_TAG_BYTES });
    aes.setAAD(associatedData(ENVELOPE_VERSION, params));

    const ciphertext = Buffer.concat([aes.update(plaintext, 'utf8'), aes.final()]);
    const authTag = aes.getAuthTag();

    return {
      version: ENVELOPE_VERSION,
      kdf: {
        algorithm: params.algorithm,
        n: params.n,
        r: params.r,
        p: params.p,
        keyLength: params.keyLength,
        salt: params.salt.toString('base64'),
      },
      cipher: {
        algorithm: CIPHER_ALGORITHM,
        iv: iv.toString('base64'),
        authTag: authTag.toString('base64'),
        ciphertext: ciphertext.toString('base64'),
      },
    };
  } finally {
    wipe(key);
  }
}

export async function open(envelope: Envelope, passphrase: string): Promise<string> {
  if (typeof passphrase !== 'string') {
    throw new VaultCorruptError('passphrase must be a string');
  }
  if (!isPlainRecord(envelope)) {
    throw new VaultCorruptError('envelope must be an object');
  }

  const version = readField(envelope, 'version');
  if (version !== ENVELOPE_VERSION) {
    throw new VaultCorruptError(
      `unsupported envelope version ${String(version)}; this build reads version ${ENVELOPE_VERSION}`,
    );
  }

  // Range-check the cost factors before anything expensive happens.
  const params = validateKdfParams(readField(envelope, 'kdf'));

  const cipherBlock = readField(envelope, 'cipher');
  if (!isPlainRecord(cipherBlock)) {
    throw new VaultCorruptError('cipher block must be an object');
  }
  if (readField(cipherBlock, 'algorithm') !== CIPHER_ALGORITHM) {
    throw new VaultCorruptError(
      `unsupported cipher.algorithm ${JSON.stringify(readField(cipherBlock, 'algorithm'))}; ` +
        `expected ${JSON.stringify(CIPHER_ALGORITHM)}`,
    );
  }

  const iv = decodeBase64(requireString(cipherBlock, 'iv', 'cipher'), IV_BYTES, 'cipher.iv');
  const authTag = decodeBase64(
    requireString(cipherBlock, 'authTag', 'cipher'),
    AUTH_TAG_BYTES,
    'cipher.authTag',
  );
  const ciphertext = decodeBase64(
    requireString(cipherBlock, 'ciphertext', 'cipher'),
    null,
    'cipher.ciphertext',
  );

  const key = await deriveKey(passphrase, params);
  try {
    const aes = createDecipheriv(CIPHER_ALGORITHM, key, iv, { authTagLength: AUTH_TAG_BYTES });
    aes.setAAD(associatedData(ENVELOPE_VERSION, params));
    aes.setAuthTag(authTag);

    let plaintext: Buffer;
    try {
      plaintext = Buffer.concat([aes.update(ciphertext), aes.final()]);
    } catch {
      // GCM rejected the tag. Whether that is a typo or a tampered file is not
      // knowable here, and the message must not pretend otherwise.
      throw new WrongPassphraseError();
    }

    return plaintext.toString('utf8');
  } finally {
    wipe(key);
  }
}

/** The `Cipher` this node provides to the rest of the vault. */
export const cipher: Cipher = { seal, open };

export default cipher;
