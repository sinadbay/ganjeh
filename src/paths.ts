import path from 'node:path';

export interface ResolveVaultPathOptions {
  readonly env: NodeJS.ProcessEnv;
  readonly homedir: string;
}

/**
 * `VAULT_FILE`, when set to a non-empty value, is resolved against the
 * process's current working directory (`path.resolve`'s ordinary behaviour),
 * not against `homedir` -- a relative override is relative to where the CLI
 * was invoked, not to the default vault location it's overriding.
 */
export function resolveVaultPath({ env, homedir }: ResolveVaultPathOptions): string {
  const override = env.VAULT_FILE;
  if (override) {
    return path.resolve(override);
  }
  return path.join(homedir, '.vault', 'vault.json');
}
