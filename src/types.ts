/**
 * Shared vocabulary: the error taxonomy and the types more than one module
 * needs.
 *
 * This module was described in the roadmap as landing first, and did not. Each
 * of `crypto.ts`, `store.ts` and `vault.ts` therefore declared its own
 * stand-in, and each said in a comment that it was a stand-in for this file.
 * They agreed — the three `VaultError` base classes were identical, and the two
 * `VaultCorruptError`s were identical — but agreement maintained by hand across
 * three files is a coincidence with an expiry date, and `instanceof` does not
 * hold across them: a `VaultCorruptError` thrown by the store is not the one
 * `vault.ts` exports, so a caller that catches the wrong class catches nothing.
 *
 * Reconciled here without a behaviour change. Every class keeps its exact code,
 * exit code and message text, so existing tests continue to describe the same
 * program.
 *
 * Exit codes are a public interface — they are what a shell script branches on
 * — so they are allocated here in one place rather than per module:
 *
 * | code | meaning                                          |
 * |------|--------------------------------------------------|
 * |  1   | the caller's input was not valid                  |
 * |  2   | the passphrase did not open the vault             |
 * |  3   | the vault file is unreadable or unsafe to write   |
 * |  4   | the requested entry does not exist                |
 * |  5   | the entry exists and overwrite was not requested  |
 * |  6   | there is no vault file at the resolved path       |
 */

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
export function describeUntrusted(value: string): string {
  const text = typeof value === 'string' ? value : String(value);
  // eslint-disable-next-line no-control-regex
  const printable = text.replace(/[\u0000-\u001f\u007f-\u009f]/g, '?');
  const clipped =
    printable.length > MAX_ECHOED_VALUE_CHARS
      ? `${printable.slice(0, MAX_ECHOED_VALUE_CHARS)}...`
      : printable;
  return JSON.stringify(clipped);
}

/** The entry-name grammar, shared by the write path and the read path. */
export const NAME_PATTERN = /^[A-Za-z0-9._@/-]{1,128}$/;

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
  readonly exitCode = 2;

  constructor(
    message = 'passphrase incorrect, or the vault file has been modified',
  ) {
    super(message);
  }
}

/** The envelope or plaintext document is not well-formed, or is out of range. */
export class VaultCorruptError extends VaultError {
  readonly code = 'VAULT_CORRUPT';
  readonly exitCode = 3;

  constructor(detail: string) {
    super(`Vault file is not readable: ${detail}`);
  }
}

/** The vault file does not exist at the resolved path. */
export class VaultNotFoundError extends VaultError {
  readonly code = 'VAULT_NOT_FOUND';
  readonly exitCode = 6;

  constructor(filePath: string) {
    super(`Vault file not found: ${filePath}`);
  }
}

/** The target path exists and is a symlink; refuse to write through it. */
export class UnsafeVaultPathError extends VaultError {
  readonly code = 'UNSAFE_VAULT_PATH';
  readonly exitCode = 3;

  constructor(filePath: string) {
    super(`Refusing to write through a symlink: ${filePath}`);
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
