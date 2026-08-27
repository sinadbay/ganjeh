/**
 * The CLI surface: parse argv, resolve where the vault lives, prompt for the
 * passphrase, run one of add/get/list against it, and map every error to an
 * exit code. `src/bin/vault.ts` is the only caller in production; it hands
 * `run` the process's argv (minus the node/script prefix) and exits with
 * whatever `run` returns. Tests call `run` directly with a bare argument
 * array and inject fakes for `store`/`cipher`/`prompt`/`stdout`/`stderr` via
 * its second parameter, so no test here ever touches a real file, terminal
 * or process exit code.
 *
 * Argument parsing is hand-rolled rather than built on the `commander`
 * package the brief sketches this module against: `commander` is not a
 * dependency anywhere in this repository's history (`package.json` carries
 * no runtime dependencies at all, and `package.json`/`package-lock.json` are
 * outside this node's owned paths, so it cannot be added here). The parser
 * below is a strict allow-list per subcommand -- exactly the flags each one
 * accepts -- so an option like `--secret` or `--passphrase` is rejected the
 * same way `commander` would reject it: as an unknown option, exit code 1.
 *
 * There is deliberately no flag anywhere that accepts a secret or a
 * passphrase value: both are only ever read through `prompt`, which reads
 * from stdin and never from argv (see `src/prompt.ts`).
 */

import path from 'node:path';
import os from 'node:os';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import type { Writable } from 'node:stream';

import { VaultError, VaultNotFoundError } from './types.ts';
import { createStore } from './store.ts';
import type { VaultStore } from './store.ts';
import { cipher as realCipher } from './crypto.ts';
import type { Cipher, EncryptedEnvelope as CryptoEnvelope } from './crypto.ts';
import type { EncryptedEnvelope as StoreEnvelope } from './store.ts';
import { resolveVaultPath } from './paths.ts';
import { readHidden, readNewPassphrase, readSecret } from './prompt.ts';
import type { PromptDeps } from './prompt.ts';
import { runAdd } from './commands/add.ts';
import { runGet } from './commands/get.ts';
import { runList } from './commands/list.ts';

// ---------------------------------------------------------------------------
// The interface command handlers are injected with
// ---------------------------------------------------------------------------

export interface CommandPrompt {
  readHidden(promptText: string): Promise<string>;
  readNewPassphrase(): Promise<string>;
  readSecret(options?: { fromStdin?: boolean }): Promise<string>;
}

/**
 * `Cipher` shaped to the envelope type that actually flows through
 * `VaultStore` (`store.ts`'s own, loose `EncryptedEnvelope`), rather than
 * `crypto.ts`'s specific one -- see the note by `bridgedCipher` for why the
 * two are not the same type and which one command handlers need to see.
 */
export interface CommandCipher {
  seal(plaintext: Buffer, passphrase: string): Promise<StoreEnvelope>;
  open(envelope: StoreEnvelope, passphrase: string): Promise<Buffer>;
}

/** What `src/commands/*.ts` see. */
export interface CommandDeps {
  readonly store: VaultStore;
  readonly cipher: CommandCipher;
  readonly prompt: CommandPrompt;
}

// ---------------------------------------------------------------------------
// store.ts and crypto.ts each declare their own EncryptedEnvelope
// ---------------------------------------------------------------------------

/**
 * `store.ts` and `crypto.ts` were both written against a `src/types.ts` that,
 * at the time, did not exist (see their module comments). Each declared its
 * own stand-in `EncryptedEnvelope` -- `store.ts`'s is loose (`{ version:
 * number, [field: string]: unknown }`, since the store treats the envelope
 * as an opaque JSON value); `crypto.ts`'s is the exact sealed shape (`cipher`,
 * `kdf`, `saltB64`, ...). `types.ts` has since landed, but it does not export
 * `EncryptedEnvelope` at all, so the two were never reconciled into one
 * shared type the way the error classes were.
 *
 * The two are not structurally compatible in the direction this module needs
 * (`store.load()`'s loose result does not statically satisfy `cipher.open`'s
 * specific parameter). Neither `store.ts` nor `crypto.ts` is in this node's
 * owned paths, so the real fix -- one shared `EncryptedEnvelope` in
 * `types.ts` -- belongs to whoever reconciles those two modules, not here.
 * `cipher.open` already treats its input as fully untrusted and validates
 * every field at runtime regardless of what the caller's static type
 * claimed, so `bridgedCipher`'s cast changes nothing about safety; it only
 * tells the compiler what is already true of the JSON value at runtime. This
 * is the only place in this node that casts between the two envelope types --
 * every command handler deals exclusively in `store.ts`'s `EncryptedEnvelope`,
 * via `CommandCipher` above.
 */
function bridgedCipher(cipher: Cipher): CommandCipher {
  return {
    seal: async (plaintext, passphrase) => {
      const envelope = await cipher.seal(plaintext, passphrase);
      return envelope as unknown as StoreEnvelope;
    },
    open: (envelope, passphrase) => cipher.open(envelope as unknown as CryptoEnvelope, passphrase),
  };
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/** A malformed invocation: an unknown command, an unknown flag, a missing argument. */
class CliUsageError extends VaultError {
  readonly code = 'CLI_USAGE';
  readonly exitCode = 1;

  constructor(message: string) {
    super(message);
  }
}

// ---------------------------------------------------------------------------
// Argument parsing
// ---------------------------------------------------------------------------

interface FlagSpec {
  readonly name: string;
  readonly hasValue: boolean;
}

interface ParsedFlags {
  readonly positionals: readonly string[];
  readonly flags: Readonly<Record<string, string | boolean>>;
}

/**
 * A strict allow-list parser: any `-`-prefixed token not named in `specs` is
 * an unknown option, full stop. This is what keeps `--secret`/`--passphrase`
 * out of `add` (t6-a1, t6-s8) without needing a shared "known secret-shaped
 * flag name" list -- every command only recognises the exact flags it is
 * given here, so a flag has to be added to `specs` before it is accepted
 * anywhere.
 */
function parseFlags(tokens: readonly string[], specs: readonly FlagSpec[]): ParsedFlags {
  const specByFlag = new Map(specs.map((spec) => [spec.name, spec] as const));
  const positionals: string[] = [];
  const flags: Record<string, string | boolean> = {};

  let i = 0;
  while (i < tokens.length) {
    const token = tokens[i];
    if (token === undefined) {
      break;
    }
    if (token.startsWith('-')) {
      const spec = specByFlag.get(token);
      if (!spec) {
        throw new CliUsageError(`unknown option '${token}'`);
      }
      if (spec.hasValue) {
        const value = tokens[i + 1];
        if (value === undefined) {
          throw new CliUsageError(`option '${token}' requires a value`);
        }
        flags[spec.name] = value;
        i += 2;
      } else {
        flags[spec.name] = true;
        i += 1;
      }
    } else {
      positionals.push(token);
      i += 1;
    }
  }

  return { positionals, flags };
}

function requireSingleName(positionals: readonly string[], command: string): string {
  const name = positionals[0];
  if (name === undefined) {
    throw new CliUsageError(`missing required argument 'name' for '${command}'`);
  }
  if (positionals.length > 1) {
    throw new CliUsageError(`unexpected argument '${positionals[1]}'`);
  }
  return name;
}

function flagString(flags: Readonly<Record<string, string | boolean>>, name: string): string | undefined {
  const value = flags[name];
  return typeof value === 'string' ? value : undefined;
}

interface AddParsed {
  readonly command: 'add';
  readonly name: string;
  readonly force: boolean;
  readonly stdin: boolean;
  readonly file: string | undefined;
}

interface GetParsed {
  readonly command: 'get';
  readonly name: string;
  readonly file: string | undefined;
}

interface ListParsed {
  readonly command: 'list';
  readonly file: string | undefined;
}

type CommandParsed = AddParsed | GetParsed | ListParsed;

function parseCommand(args: readonly string[]): CommandParsed {
  const command = args[0];
  const rest = args.slice(1);

  if (command === 'add') {
    const { positionals, flags } = parseFlags(rest, [
      { name: '--force', hasValue: false },
      { name: '--stdin', hasValue: false },
      { name: '--file', hasValue: true },
    ]);
    return {
      command: 'add',
      name: requireSingleName(positionals, 'add'),
      force: flags['--force'] === true,
      stdin: flags['--stdin'] === true,
      file: flagString(flags, '--file'),
    };
  }

  if (command === 'get') {
    const { positionals, flags } = parseFlags(rest, [{ name: '--file', hasValue: true }]);
    return {
      command: 'get',
      name: requireSingleName(positionals, 'get'),
      file: flagString(flags, '--file'),
    };
  }

  if (command === 'list') {
    const { positionals, flags } = parseFlags(rest, [{ name: '--file', hasValue: true }]);
    if (positionals.length > 0) {
      throw new CliUsageError(`unexpected argument '${positionals[0]}'`);
    }
    return { command: 'list', file: flagString(flags, '--file') };
  }

  if (command === undefined) {
    throw new CliUsageError('missing command (expected one of: add, get, list)');
  }
  throw new CliUsageError(`unknown command '${command}'`);
}

// ---------------------------------------------------------------------------
// Help / version
// ---------------------------------------------------------------------------

function getPackageVersion(): string {
  const pkgPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'package.json');
  const pkg = JSON.parse(readFileSync(pkgPath, 'utf8')) as { readonly version: string };
  return pkg.version;
}

function helpText(): string {
  return [
    'Usage: vault <command> [options]',
    '',
    'Commands:',
    '  add <name> [--force] [--stdin] [--file <path>]  add or overwrite a secret',
    '  get <name> [--file <path>]                       print a secret to stdout',
    '  list [--file <path>]                             list stored secret names',
    '',
    'Options:',
    '  -V, --version   print the version number',
    '  -h, --help      print this help message',
    '',
  ].join('\n');
}

// ---------------------------------------------------------------------------
// Dependency composition
// ---------------------------------------------------------------------------

export interface RunDeps {
  readonly store: VaultStore;
  readonly cipher: CommandCipher;
  readonly prompt: CommandPrompt;
  readonly stdout: Writable;
  readonly stderr: Writable;
  readonly env: NodeJS.ProcessEnv;
  readonly homedir: string;
  readonly isTTY: boolean;
}

function realPrompt(promptDeps: PromptDeps): CommandPrompt {
  return {
    readHidden: (text) => readHidden(text, promptDeps),
    readNewPassphrase: () => readNewPassphrase(promptDeps),
    readSecret: (options) => readSecret(promptDeps, options),
  };
}

function buildRunDeps(fileOption: string | undefined, overrides: Partial<RunDeps>): RunDeps {
  const env = overrides.env ?? process.env;
  const homedir = overrides.homedir ?? os.homedir();
  const isTTY = overrides.isTTY ?? Boolean(process.stdin.isTTY);
  const stdout = overrides.stdout ?? process.stdout;
  const stderr = overrides.stderr ?? process.stderr;

  const filePath = fileOption !== undefined ? path.resolve(fileOption) : resolveVaultPath({ env, homedir });
  const store = overrides.store ?? createStore(filePath);
  const cipher = overrides.cipher ?? bridgedCipher(realCipher);
  const prompt = overrides.prompt ?? realPrompt({ input: process.stdin, output: stderr, isTTY });

  return { store, cipher, prompt, stdout, stderr, env, homedir, isTTY };
}

// ---------------------------------------------------------------------------
// Central error handling
// ---------------------------------------------------------------------------

function isEaccesError(err: unknown): err is NodeJS.ErrnoException {
  return err instanceof Error && 'code' in err && (err as NodeJS.ErrnoException).code === 'EACCES';
}

function writeDebugStack(err: Error, stderr: Writable): void {
  if (process.env.VAULT_DEBUG === '1') {
    stderr.write(`${err.stack ?? err.message}\n`);
  }
}

function handleError(err: unknown, stderr: Writable): number {
  // `store.load()` throwing "no vault at this path" is the one case the
  // brief asks for a message beyond the shared taxonomy's own text (t6-s5,
  // and the `list`-against-a-missing-vault line of the DoD): both commands
  // land here through the same `VaultNotFoundError`, so the friendlier
  // message -- and the "run vault add first" hint -- lives in one place.
  if (err instanceof VaultNotFoundError) {
    stderr.write('vault: no vault found; run "vault add" first to create one\n');
    return err.exitCode;
  }
  if (err instanceof VaultError) {
    stderr.write(`vault: ${err.message}\n`);
    return err.exitCode;
  }
  if (isEaccesError(err)) {
    stderr.write('vault: permission denied\n');
    writeDebugStack(err, stderr);
    return 1;
  }
  stderr.write('vault: an unexpected error occurred\n');
  if (err instanceof Error) {
    writeDebugStack(err, stderr);
  }
  return 1;
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

/**
 * Run one CLI invocation and return the process exit code; never throws.
 *
 * `args` is the *bare* argument list (no `node`/script-path prefix) --
 * `src/bin/vault.ts` passes `process.argv.slice(2)`. `overrides` lets a test
 * replace `store`/`cipher`/`prompt`/`stdout`/`stderr`/`env`/`homedir`/`isTTY`
 * with fakes; anything not overridden is built from the real process.
 */
export async function run(args: readonly string[], overrides: Partial<RunDeps> = {}): Promise<number> {
  const stdout = overrides.stdout ?? process.stdout;
  const stderr = overrides.stderr ?? process.stderr;

  try {
    if (args[0] === '--version' || args[0] === '-V') {
      stdout.write(`${getPackageVersion()}\n`);
      return 0;
    }
    if (args[0] === '--help' || args[0] === '-h') {
      stdout.write(helpText());
      return 0;
    }

    const parsed = parseCommand(args);
    const deps = buildRunDeps(parsed.file, overrides);

    if (parsed.command === 'add') {
      await runAdd(parsed.name, { force: parsed.force, stdin: parsed.stdin }, deps);
      deps.stderr.write(`added "${parsed.name}"\n`);
      return 0;
    }

    if (parsed.command === 'get') {
      const secret = await runGet(parsed.name, deps);
      deps.stdout.write(`${secret}\n`);
      return 0;
    }

    const names = await runList(deps);
    if (names.length === 0) {
      deps.stderr.write('vault is empty\n');
    } else {
      for (const name of names) {
        deps.stdout.write(`${name}\n`);
      }
    }
    return 0;
  } catch (err) {
    return handleError(err, stderr);
  }
}
