/**
 * Vault data model: the plaintext document a vault file decrypts to, and the
 * pure operations (`addEntry`, `getEntry`, `listEntries`) that act on it.
 *
 * This module is deliberately pure -- no I/O, no crypto. `encodeVault` and
 * `decodeVault` convert between that document and the bytes the cipher layer
 * seals and opens; everything else here transforms one `VaultData` into
 * another without ever mutating the one it was given.
 *
 * `src/types.ts` -- described in this node's brief as an already-landed
 * prerequisite carrying the shared `VaultData`/`VaultEntry` types and error
 * taxonomy -- does not exist anywhere in this repository's history: not on
 * `main`, not on `develop`, not on any node branch. The sibling crypto and
 * store nodes hit the same gap and worked around it the same way this module
 * does: declaring local stand-ins with the shapes and exit codes the brief
 * specifies (see `src/crypto.ts` and `src/store.ts`). `VaultCorruptError`
 * below intentionally matches their shape (same message prefix, same exit
 * code 3) so the three can be reconciled into one shared definition once a
 * real `src/types.ts` lands.
 *
 * `decodeVault` treats its input as hostile: it may be bytes a corrupted file
 * produced, or a document an attacker crafted to be imported. Every field is
 * type-checked before use, the document size is bounded before it is parsed,
 * and every entry key is run through `assertValidName` -- the same grammar
 * `addEntry` enforces on the write path -- so a key containing control bytes,
 * ANSI escapes, a ".." segment, or one of the reserved prototype-pollution
 * names (`__proto__`, `constructor`, `prototype`) cannot reach `entries`
 * either by being written or by being decoded from a crafted document.
 */

// ---------------------------------------------------------------------------
// Errors (local stand-in for src/types.ts -- see module comment above)
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

/** The plaintext document is not well-formed, or exceeds the size bound. */
export class VaultCorruptError extends VaultError {
  readonly code = 'VAULT_CORRUPT';
  readonly exitCode = 3;

  constructor(detail: string) {
    super(`Vault file is not readable: ${detail}`);
  }
}

/** An entry name does not satisfy the allowed name grammar. */
export class InvalidNameError extends VaultError {
  readonly code = 'INVALID_NAME';
  readonly exitCode = 1;

  constructor(name: string) {
    super(
      `invalid entry name ${describeUntrusted(name)}: names must match ` +
        `${NAME_PATTERN} (1-128 characters, no ".." segments, and not the ` +
        `reserved name "__proto__", "constructor" or "prototype")`,
    );
  }
}

/** A secret is empty or exceeds the maximum stored size. */
export class InvalidSecretError extends VaultError {
  readonly code = 'INVALID_SECRET';
  readonly exitCode = 1;

  constructor(message: string) {
    super(message);
  }
}

/** `addEntry` was called for a name that already exists without `overwrite`. */
export class EntryExistsError extends VaultError {
  readonly code = 'ENTRY_EXISTS';
  readonly exitCode = 5;

  constructor(name: string) {
    super(`entry "${name}" already exists (use --force to overwrite)`);
  }
}

/**
 * `getEntry` was called for a name that is not in the vault.
 *
 * Unlike `EntryExistsError`, `name` here has not necessarily passed
 * `assertValidName` -- `getEntry` accepts any lookup key and simply reports
 * absence, so a caller can reach this constructor with a name containing
 * control characters or ANSI escapes. `describeUntrusted` keeps those out of
 * the message this becomes once caught and printed.
 */
export class EntryNotFoundError extends VaultError {
  readonly code = 'ENTRY_NOT_FOUND';
  readonly exitCode = 4;

  constructor(name: string) {
    super(`entry ${describeUntrusted(name)} not found`);
  }
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface VaultEntry {
  readonly secret: string;
  readonly createdAt: string;
  readonly updatedAt: string;
}

export interface VaultData {
  readonly entries: Record<string, VaultEntry>;
}

export interface AddEntryOptions {
  readonly overwrite?: boolean;
  readonly now?: () => string;
}

// ---------------------------------------------------------------------------
// Untrusted-input helpers
// ---------------------------------------------------------------------------

/** Cap on how much of an untrusted value is quoted back in an error message. */
const MAX_ECHOED_VALUE_CHARS = 60;

/**
 * Render an untrusted string for an error message.
 *
 * Entry names are exactly the kind of value this guards against: a name is
 * rejected precisely because it may contain control characters or ANSI
 * escape sequences, so quoting it back verbatim would hand the same payload
 * to whatever prints the error -- a terminal, a log file. Control characters
 * are replaced and the result is capped before it is quoted.
 */
function describeUntrusted(value: string): string {
  const text = typeof value === 'string' ? value : String(value);
  // eslint-disable-next-line no-control-regex
  const printable = text.replace(/[\u0000-\u001f\u007f-\u009f]/g, '?');
  const clipped =
    printable.length > MAX_ECHOED_VALUE_CHARS
      ? `${printable.slice(0, MAX_ECHOED_VALUE_CHARS)}...`
      : printable;
  return JSON.stringify(clipped);
}

function isPlainRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

// ---------------------------------------------------------------------------
// Name and secret validation
// ---------------------------------------------------------------------------

const NAME_PATTERN = /^[A-Za-z0-9._@/-]{1,128}$/;

/**
 * Property names that would let an entry act as (or masquerade as) an
 * `Object.prototype` vector if it were ever placed on a prototype-carrying
 * object. `addEntry`'s own `entries` record -- and `decodeVault`'s -- are
 * built on `Object.create(null)`, which already denies these keys their
 * special meaning there, but both the write and the read path refuse the
 * name outright rather than relying on that alone: an entry named
 * `__proto__` that `addEntry` accepted would be a document `decodeVault`
 * could never read back, since it applies the same grammar. Rejecting it at
 * the source keeps the write and read paths in agreement.
 */
const FORBIDDEN_ENTRY_KEYS = new Set(['__proto__', 'constructor', 'prototype']);

/** Bytes, not characters -- a UTF-8 secret near the limit must be measured, not counted. */
const MAX_SECRET_BYTES = 8192;

/**
 * Validate an entry name.
 *
 * The character class alone would accept a name like "../escape" -- every
 * character in it (`.`, `/`, letters) is in the allowed set. Path segments
 * are rejected on top of the class check because an entry name that reads as
 * a directory-traversal attempt has no legitimate reason to exist here, even
 * though this build stores everything in a single JSON document rather than
 * one file per entry. The character class alone would also accept
 * "__proto__", "constructor" and "prototype" -- ordinary identifier-looking
 * strings -- so those are rejected by name on top of the class check too.
 *
 * `decodeVault` runs every entry key from an untrusted document through this
 * same function, so it is also the gate that keeps control bytes, ANSI
 * escapes and oversized names out of `listEntries` output for a vault that
 * was decoded rather than built up through `addEntry`.
 */
export function assertValidName(name: string): void {
  const value = typeof name === 'string' ? name : '';
  if (!NAME_PATTERN.test(value) || value.includes('..') || FORBIDDEN_ENTRY_KEYS.has(value)) {
    throw new InvalidNameError(name);
  }
}

function assertValidSecret(secret: string): void {
  if (typeof secret !== 'string') {
    throw new TypeError('addEntry(): secret must be a string');
  }
  const byteLength = Buffer.byteLength(secret, 'utf8');
  if (byteLength === 0) {
    throw new InvalidSecretError(`secret must not be empty (limit is ${MAX_SECRET_BYTES} bytes)`);
  }
  if (byteLength > MAX_SECRET_BYTES) {
    throw new InvalidSecretError(
      `secret is ${byteLength} bytes, over the ${MAX_SECRET_BYTES} byte limit`,
    );
  }
}

// ---------------------------------------------------------------------------
// Construction and queries
// ---------------------------------------------------------------------------

export function emptyVault(): VaultData {
  return { entries: Object.create(null) as Record<string, VaultEntry> };
}

/**
 * Add or overwrite an entry, returning a new `VaultData`.
 *
 * `data` is never mutated: a fresh `entries` record is built from `data`'s
 * own keys plus the new one, so the caller's object -- and every entry object
 * it holds -- is exactly as it was before this call, even when this call
 * throws partway through validation.
 */
export function addEntry(
  data: VaultData,
  name: string,
  secret: string,
  { overwrite = false, now = () => new Date().toISOString() }: AddEntryOptions = {},
): VaultData {
  assertValidName(name);
  assertValidSecret(secret);

  const existing = Object.hasOwn(data.entries, name) ? data.entries[name] : undefined;
  if (existing !== undefined && !overwrite) {
    throw new EntryExistsError(name);
  }

  const timestamp = now();
  const entry: VaultEntry = {
    secret,
    createdAt: existing !== undefined ? existing.createdAt : timestamp,
    updatedAt: timestamp,
  };

  const entries: Record<string, VaultEntry> = Object.create(null);
  for (const key of Object.keys(data.entries)) {
    entries[key] = data.entries[key];
  }
  entries[name] = entry;

  return { entries };
}

export function getEntry(data: VaultData, name: string): string {
  const entry = Object.hasOwn(data.entries, name) ? data.entries[name] : undefined;
  if (entry === undefined) {
    throw new EntryNotFoundError(name);
  }
  return entry.secret;
}

/** Names in plain lexicographic (UTF-16 code unit) order -- no locale collation. */
export function listEntries(data: VaultData): string[] {
  return Object.keys(data.entries).sort();
}

// ---------------------------------------------------------------------------
// Codec
// ---------------------------------------------------------------------------

/**
 * Documents over this size are refused before `JSON.parse` ever sees them.
 * A corrupted or hostile vault file should fail fast and cheaply, not hand
 * an unbounded string to the parser on every `vault` invocation.
 */
const MAX_DOCUMENT_BYTES = 5 * 1024 * 1024;

export function encodeVault(data: VaultData): Buffer {
  return Buffer.from(JSON.stringify(data), 'utf8');
}

export function decodeVault(buf: Buffer): VaultData {
  if (buf.length > MAX_DOCUMENT_BYTES) {
    throw new VaultCorruptError(
      `document is ${buf.length} bytes, over the ${MAX_DOCUMENT_BYTES} byte limit`,
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(buf.toString('utf8'));
  } catch {
    throw new VaultCorruptError('not valid JSON');
  }

  if (!isPlainRecord(parsed)) {
    throw new VaultCorruptError('document must be a JSON object');
  }

  const entriesRaw = Object.hasOwn(parsed, 'entries') ? parsed.entries : undefined;
  if (!isPlainRecord(entriesRaw)) {
    throw new VaultCorruptError('document must have an "entries" object');
  }

  const entries: Record<string, VaultEntry> = Object.create(null);
  for (const key of Object.keys(entriesRaw)) {
    try {
      assertValidName(key);
    } catch (err) {
      if (err instanceof InvalidNameError) {
        throw new VaultCorruptError(`entry name ${describeUntrusted(key)} is not a valid entry name`);
      }
      throw err;
    }
    entries[key] = decodeEntry(entriesRaw[key], key);
  }

  return { entries };
}

function decodeEntry(value: unknown, key: string): VaultEntry {
  if (!isPlainRecord(value)) {
    throw new VaultCorruptError(`entry ${JSON.stringify(key)} must be an object`);
  }

  const secret = Object.hasOwn(value, 'secret') ? value.secret : undefined;
  const createdAt = Object.hasOwn(value, 'createdAt') ? value.createdAt : undefined;
  const updatedAt = Object.hasOwn(value, 'updatedAt') ? value.updatedAt : undefined;

  if (typeof secret !== 'string') {
    throw new VaultCorruptError(`entry ${JSON.stringify(key)}.secret must be a string`);
  }
  if (typeof createdAt !== 'string') {
    throw new VaultCorruptError(`entry ${JSON.stringify(key)}.createdAt must be a string`);
  }
  if (typeof updatedAt !== 'string') {
    throw new VaultCorruptError(`entry ${JSON.stringify(key)}.updatedAt must be a string`);
  }

  return { secret, createdAt, updatedAt };
}
