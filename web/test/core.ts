// Loads the wasm core synchronously for tests.
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import * as core from '../pkg/otpx.js';

core.initSync({ module: readFileSync(join(import.meta.dir, '..', 'pkg', 'otpx_bg.wasm')) });

export { core };
