/**
 * Encrypted vault file store: where the single vault file lives on disk, how
 * it is read, and how it is replaced without ever leaving a partial or
 * world-readable copy behind.
 *
 * `src/types.ts` -- described in this node's brief as an already-landed
 * prerequisite carrying the shared `VaultStore` interface, `EncryptedEnvelope`
 * type and error taxonomy (`VaultNotFoundError`, `VaultCorruptError`, etc.) --
 * does not exist anywhere in this repository's history: not on `main`, not on
 * `develop`, not on any node branch. The sibling crypto node hit the same gap
 * and worked around it the same way this module does: declaring local
 * stand-ins with the shapes and exit codes the brief specifies. See the PR
 * description for what reconciling the two will need once a real
 * `src/types.ts` lands.
 *
 * This module does not import or depend on the cipher. `load`/`save` treat
 * the envelope as an opaque JSON value with a numeric `version` field; deep
 * validation of its shape is the cipher layer's job, not this one's.
 */

import path from 'node:path';
import { randomBytes } from 'node:crypto';
import * as nodeFsPromises from 'node:fs/promises';

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

/** The vault file does not exist at the resolved path. */
export class VaultNotFoundError extends VaultError {
  readonly code = 'VAULT_NOT_FOUND';
  readonly exitCode = 6;

  constructor(filePath: string) {
    super(`Vault file not found: ${filePath}`);
  }
}

/** The vault file exists but is not well-formed JSON, or not an envelope shape. */
export class VaultCorruptError extends VaultError {
  readonly code = 'VAULT_CORRUPT';
  readonly exitCode = 3;

  constructor(detail: string) {
    super(`Vault file is not readable: ${detail}`);
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

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/**
 * The vault file's on-disk shape, as far as this module cares: a plain JSON
 * object with a numeric `version`. Everything else is the cipher's contract
 * to validate, so it is left untyped here rather than duplicating (and
 * risking drifting from) the real envelope shape.
 */
export interface EncryptedEnvelope {
  readonly version: number;
  readonly [field: string]: unknown;
}

export interface VaultStore {
  load(): Promise<EncryptedEnvelope>;
  save(envelope: EncryptedEnvelope): Promise<void>;
  exists(): Promise<boolean>;
}

interface FileHandleLike {
  writeFile(data: string): Promise<void>;
  sync(): Promise<void>;
  close(): Promise<void>;
}

interface StatLike {
  isSymbolicLink(): boolean;
  isFile(): boolean;
}

export interface FsDeps {
  readFile(filePath: string, encoding: 'utf8'): Promise<string>;
  mkdir(dirPath: string, options: { recursive: true; mode: number }): Promise<string | undefined>;
  chmod(targetPath: string, mode: number): Promise<void>;
  lstat(targetPath: string): Promise<StatLike>;
  stat(targetPath: string): Promise<StatLike>;
  open(targetPath: string, flags: string, mode: number): Promise<FileHandleLike>;
  rename(oldPath: string, newPath: string): Promise<void>;
  unlink(targetPath: string): Promise<void>;
}

export interface StoreDeps {
  fs: FsDeps;
}

const defaultDeps: StoreDeps = { fs: nodeFsPromises as unknown as FsDeps };

function isErrnoException(err: unknown): err is NodeJS.ErrnoException {
  return err instanceof Error && 'code' in err;
}

function isEncryptedEnvelopeShape(value: unknown): value is EncryptedEnvelope {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    typeof (value as Record<string, unknown>).version === 'number'
  );
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

export function createStore(filePath: string, deps: StoreDeps = defaultDeps): VaultStore {
  // A caller bug, not a damaged vault: `save` chmods the parent directory
  // unconditionally (see below), and resolving a relative path against
  // whatever the current working directory happens to be would silently
  // tighten permissions on an unrelated directory instead of the vault's own.
  if (!path.isAbsolute(filePath)) {
    throw new TypeError(`createStore(): filePath must be an absolute path, got ${JSON.stringify(filePath)}`);
  }

  const { fs } = deps;
  const dir = path.dirname(filePath);

  async function load(): Promise<EncryptedEnvelope> {
    let raw: string;
    try {
      raw = await fs.readFile(filePath, 'utf8');
    } catch (err) {
      if (isErrnoException(err) && err.code === 'ENOENT') {
        throw new VaultNotFoundError(filePath);
      }
      throw err;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new VaultCorruptError(`${filePath}: not valid JSON`);
    }

    if (!isEncryptedEnvelopeShape(parsed)) {
      throw new VaultCorruptError(
        `${filePath}: expected an object with a numeric "version" field`,
      );
    }

    return parsed;
  }

  async function save(envelope: EncryptedEnvelope): Promise<void> {
    await fs.mkdir(dir, { recursive: true, mode: 0o700 });
    // `mkdir`'s mode only applies to directories it creates -- an already
    // existing, more permissive `~/.vault` (left by an older build, or made
    // by hand) would otherwise stay world-readable forever. Tighten it every
    // save so the invariant holds regardless of how the directory got there.
    await fs.chmod(dir, 0o700);

    let existing: StatLike | null;
    try {
      existing = await fs.lstat(filePath);
    } catch (err) {
      if (isErrnoException(err) && err.code === 'ENOENT') {
        existing = null;
      } else {
        throw err;
      }
    }
    if (existing !== null && existing.isSymbolicLink()) {
      throw new UnsafeVaultPathError(filePath);
    }

    const tmpPath = `${filePath}.tmp-${randomBytes(8).toString('hex')}`;
    let handle: FileHandleLike | null = null;
    try {
      handle = await fs.open(tmpPath, 'wx', 0o600);
      await handle.writeFile(JSON.stringify(envelope));
      await handle.sync();
      await handle.close();
      handle = null;
      await fs.rename(tmpPath, filePath);
    } catch (err) {
      if (handle !== null) {
        await handle.close().catch(() => {});
      }
      await fs.unlink(tmpPath).catch(() => {});
      throw err;
    }
  }

  async function exists(): Promise<boolean> {
    try {
      const stat = await fs.stat(filePath);
      return stat.isFile();
    } catch (err) {
      if (isErrnoException(err) && err.code === 'ENOENT') {
        return false;
      }
      throw err;
    }
  }

  return { load, save, exists };
}
