#!/usr/bin/env node
/**
 * The installed entry point. `run` takes the bare argument list -- not the
 * full `process.argv` -- so the node executable path and this script's own
 * path are sliced off here, once, before anything else sees argv.
 */

import { run } from '../cli.ts';

const exitCode = await run(process.argv.slice(2));
process.exit(exitCode);
