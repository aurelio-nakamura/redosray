'use strict';
// Runs a single regex match in isolation so the parent can time it and
// terminate it if it hangs (catastrophic backtracking cannot be interrupted
// cooperatively, so isolation in a worker is the only safe way to measure it).
const { parentPort, workerData } = require('node:worker_threads');
const { source, flags, input } = workerData;
const re = new RegExp(source, flags);
const t0 = process.hrtime.bigint();
const matched = re.test(input);
const t1 = process.hrtime.bigint();
parentPort.postMessage({ matched, ns: Number(t1 - t0) });
