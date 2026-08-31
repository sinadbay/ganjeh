/**
 * `vault add`: create or overwrite one entry.
 *
 * Whether a new passphrase is set (vault does not exist yet) or an existing
 * one is checked (vault exists) is decided here, before anything is read or
 * decrypted -- see the brief's step-by-step description of `add`. Everything
 * below only ever talks to `deps.store`/`deps.cipher`/`deps.prompt`, never to
 * a real file or terminal directly, so a test can inject fakes for all three
 * and assert on them without touching disk or stdin.
 */

import type { CommandDeps } from '../cli.ts';
import { addEntry, decodeVault, emptyVault, encodeVault } from '../vault.ts';
import type { VaultData } from '../vault.ts';

export interface AddOptions {
  readonly force: boolean;
  readonly stdin: boolean;
}

export async function runAdd(name: string, options: AddOptions, deps: CommandDeps): Promise<void> {
  let passphrase: string;
  let vault: VaultData;

  if (await deps.store.exists()) {
    passphrase = await deps.prompt.readHidden('Passphrase: ');
    const envelope = await deps.store.load();
    const plaintext = await deps.cipher.open(envelope, passphrase);
    vault = decodeVault(plaintext);
  } else {
    passphrase = await deps.prompt.readNewPassphrase();
    vault = emptyVault();
  }

  const secret = await deps.prompt.readSecret({ fromStdin: options.stdin });
  const updated = addEntry(vault, name, secret, { overwrite: options.force });

  const plaintext = encodeVault(updated);
  const envelope = await deps.cipher.seal(plaintext, passphrase);
  await deps.store.save(envelope);
}
