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
// The shared error taxonomy and types now live in one module. They are
// re-exported here so this module's public surface is unchanged for every
// caller and test that imported them from this file.
import { VaultError, VaultNotFoundError, VaultCorruptError, UnsafeVaultPathError, } from "./types.js";
export { VaultError, VaultNotFoundError, VaultCorruptError, UnsafeVaultPathError, };
const defaultDeps = { fs: nodeFsPromises };
function isErrnoException(err) {
    return err instanceof Error && 'code' in err;
}
function isEncryptedEnvelopeShape(value) {
    return (typeof value === 'object' &&
        value !== null &&
        !Array.isArray(value) &&
        typeof value.version === 'number');
}
// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------
export function createStore(filePath, deps = defaultDeps) {
    // A caller bug, not a damaged vault: `save` chmods the parent directory
    // unconditionally (see below), and resolving a relative path against
    // whatever the current working directory happens to be would silently
    // tighten permissions on an unrelated directory instead of the vault's own.
    if (!path.isAbsolute(filePath)) {
        throw new TypeError(`createStore(): filePath must be an absolute path, got ${JSON.stringify(filePath)}`);
    }
    const { fs } = deps;
    const dir = path.dirname(filePath);
    async function load() {
        let raw;
        try {
            raw = await fs.readFile(filePath, 'utf8');
        }
        catch (err) {
            if (isErrnoException(err) && err.code === 'ENOENT') {
                throw new VaultNotFoundError(filePath);
            }
            throw err;
        }
        let parsed;
        try {
            parsed = JSON.parse(raw);
        }
        catch {
            throw new VaultCorruptError(`${filePath}: not valid JSON`);
        }
        if (!isEncryptedEnvelopeShape(parsed)) {
            throw new VaultCorruptError(`${filePath}: expected an object with a numeric "version" field`);
        }
        return parsed;
    }
    async function save(envelope) {
        await fs.mkdir(dir, { recursive: true, mode: 0o700 });
        // `mkdir`'s mode only applies to directories it creates -- an already
        // existing, more permissive `~/.vault` (left by an older build, or made
        // by hand) would otherwise stay world-readable forever. Tighten it every
        // save so the invariant holds regardless of how the directory got there.
        await fs.chmod(dir, 0o700);
        let existing;
        try {
            existing = await fs.lstat(filePath);
        }
        catch (err) {
            if (isErrnoException(err) && err.code === 'ENOENT') {
                existing = null;
            }
            else {
                throw err;
            }
        }
        if (existing !== null && existing.isSymbolicLink()) {
            throw new UnsafeVaultPathError(filePath);
        }
        const tmpPath = `${filePath}.tmp-${randomBytes(8).toString('hex')}`;
        let handle = null;
        try {
            handle = await fs.open(tmpPath, 'wx', 0o600);
            await handle.writeFile(JSON.stringify(envelope));
            await handle.sync();
            await handle.close();
            handle = null;
            await fs.rename(tmpPath, filePath);
        }
        catch (err) {
            if (handle !== null) {
                await handle.close().catch(() => { });
            }
            await fs.unlink(tmpPath).catch(() => { });
            throw err;
        }
    }
    async function exists() {
        try {
            const stat = await fs.stat(filePath);
            return stat.isFile();
        }
        catch (err) {
            if (isErrnoException(err) && err.code === 'ENOENT') {
                return false;
            }
            throw err;
        }
    }
    return { load, save, exists };
}
