/** `vault list`: decrypt the vault and return every entry name, sorted. */

import type { CommandDeps } from '../cli.ts';
import { decodeVault, listEntries } from '../vault.ts';

export async function runList(deps: CommandDeps): Promise<string[]> {
  const passphrase = await deps.prompt.readHidden('Passphrase: ');
  const envelope = await deps.store.load();
  const plaintext = await deps.cipher.open(envelope, passphrase);
  const vault = decodeVault(plaintext);

  return listEntries(vault);
}
