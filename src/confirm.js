'use strict';
const path = require('node:path');
const { Worker } = require('node:worker_threads');

const WORKER = path.join(__dirname, 'worker.js');

/**
 * Run one regex match against `input` in an isolated worker, timing it and
 * killing it if it exceeds `timeoutMs`. A timeout is itself the signal that the
 * regex catastrophically backtracks on that input.
 * @returns {Promise<{timedOut:boolean, ms:number, matched:boolean}>}
 */
function timeMatch(source, flags, input, timeoutMs) {
  return new Promise((resolve) => {
    const w = new Worker(WORKER, { workerData: { source, flags, input } });
    const start = Date.now();
    const timer = setTimeout(() => {
      w.terminate();
      resolve({ timedOut: true, ms: Date.now() - start, matched: false });
    }, timeoutMs);
    w.once('message', (m) => {
      clearTimeout(timer);
      w.terminate();
      resolve({ timedOut: false, ms: m.ns / 1e6, matched: m.matched });
    });
    w.once('error', () => {
      clearTimeout(timer);
      resolve({ timedOut: false, ms: Date.now() - start, matched: false, error: true });
    });
  });
}

/**
 * Dynamically CONFIRM a ReDoS by feeding the regex an attack string of growing
 * size and watching for super-linear blow-up. Returns the smallest input that
 * pushed match time past `timeoutMs` (the shareable "proof"), or null if the
 * regex stayed fast at every size (no confirmed vulnerability).
 *
 * @param attack {{prefix?:string, pump:string, suffix?:string}}
 */
async function confirm(source, flags, attack, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 1000;
  const maxPumps = opts.maxPumps ?? 100000;
  const prefix = attack.prefix ?? '';
  const suffix = attack.suffix ?? '';
  const samples = [];
  // Grow geometrically so exponential blow-up is caught in a handful of steps
  // and polynomial blow-up within a few dozen.
  for (let n = 10; n <= maxPumps; n = Math.ceil(n * 1.6)) {
    const input = prefix + attack.pump.repeat(n) + suffix;
    const r = await timeMatch(source, flags, input, timeoutMs);
    samples.push({ pumps: n, length: input.length, ms: r.ms, timedOut: r.timedOut });
    if (r.timedOut) {
      return {
        vulnerable: true,
        proof: { input, pumps: n, length: input.length, timeoutMs },
        samples,
      };
    }
  }
  return { vulnerable: false, samples };
}

module.exports = { timeMatch, confirm };
