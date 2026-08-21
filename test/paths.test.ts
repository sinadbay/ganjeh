/**
 * Node t3 — vault path resolution.
 *
 * Scenario map (see brief):
 *   t3-s7  VAULT_FILE set (relative or absolute) resolves to an absolute path;
 *          unset falls back to <homedir>/.vault/vault.json
 */

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import path from 'node:path';

import { resolveVaultPath } from '../src/paths.ts';

describe('t3-s7 resolveVaultPath', () => {
  test('VAULT_FILE unset falls back to <homedir>/.vault/vault.json', () => {
    const result = resolveVaultPath({ env: {}, homedir: '/home/dev' });
    assert.equal(result, '/home/dev/.vault/vault.json');
  });

  test('VAULT_FILE set to a relative path resolves against cwd, not homedir', () => {
    const result = resolveVaultPath({ env: { VAULT_FILE: 'sub/v.json' }, homedir: '/home/dev' });
    assert.equal(result, path.resolve('sub/v.json'));
    assert.notEqual(result, '/home/dev/sub/v.json');
  });

  test('VAULT_FILE set to an absolute path is returned unchanged', () => {
    const absolute = path.resolve('/some/absolute/vault.json');
    const result = resolveVaultPath({ env: { VAULT_FILE: absolute }, homedir: '/home/dev' });
    assert.equal(result, absolute);
  });

  test('VAULT_FILE set to an empty string is treated as unset', () => {
    const result = resolveVaultPath({ env: { VAULT_FILE: '' }, homedir: '/home/dev' });
    assert.equal(result, '/home/dev/.vault/vault.json');
  });

  test('the result is always absolute', () => {
    const withEnv = resolveVaultPath({ env: { VAULT_FILE: 'x.json' }, homedir: '/home/dev' });
    const withoutEnv = resolveVaultPath({ env: {}, homedir: '/home/dev' });
    assert.ok(path.isAbsolute(withEnv));
    assert.ok(path.isAbsolute(withoutEnv));
  });
});
