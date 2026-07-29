#!/usr/bin/env node
// Refuse to build in a clone where the version-bump hook is not active.
//
// .git/hooks is not versioned, so committing the hook does not activate it. Without this
// check a fresh clone would silently produce builds whose version never moves — exactly the
// state this gate exists to prevent.
//
// ESM (package.json has "type": "module"), so this file uses import, not require.

import { execFileSync } from 'node:child_process';

const EXPECTED = 'scripts/hooks';

let configured = '';
try {
  configured = execFileSync('git', ['config', '--get', 'core.hooksPath'], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'ignore'],
  }).trim();
} catch {
  configured = '';
}

if (configured !== EXPECTED) {
  console.error('[prebuild] ERROR: version-bump hook is not active in this clone.');
  console.error(`[prebuild] core.hooksPath is ${configured === '' ? '(unset)' : configured}, expected ${EXPECTED}.`);
  console.error('[prebuild]');
  console.error('[prebuild] Building now would produce an artifact whose version never moves,');
  console.error('[prebuild] making the deployed build unidentifiable. Activate the hook first:');
  console.error('[prebuild]');
  console.error(`[prebuild]   git config core.hooksPath ${EXPECTED}`);
  console.error('[prebuild]');
  process.exit(1);
}
