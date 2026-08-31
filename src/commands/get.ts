/**
 * `vault get`: decrypt the vault and return one entry's secret.
 *
 * `assertValidName` runs before any prompt or I/O. A lookup name is
 * attacker-controlled input (see t6-a3: a path-traversal-looking name, or one
 * carrying an ANSI escape), and `vault.getEntry` alone does not reject it --
 * it is designed to accept any lookup key and simply report absence. Since a
 * name can never become a filesystem path here (the vault is one JSON file;
 * `store`/`cipher` never see `name` at all), rejecting it early is not about
 * stopping a traversal that could otherwise happen -- it is about failing
 * fast, before a passphrase prompt or a decrypt, on input that was never a
 * legal entry name to begin with.
 */

import type { CommandDeps } from '../cli.ts';
import { assertValidName, decodeVault, getEntry } from '../vault.ts';

export async function runGet(name: string, deps: CommandDeps): Promise<string> {
  assertValidName(name);

  const passphrase = await deps.prompt.readHidden('Passphrase: ');
  const envelope = await deps.store.load();
  const plaintext = await deps.cipher.open(envelope, passphrase);
  const vault = decodeVault(plaintext);

  return getEntry(vault, name);
}
