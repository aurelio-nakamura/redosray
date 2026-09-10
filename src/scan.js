'use strict';
const { findCandidates } = require('./analyze');
const { confirm } = require('./confirm');

const CLASS_BY_KIND = {
  'nested-quantifier': 'exponential',
  'ambiguous-alternation': 'exponential',
  'sequential-quantifier': 'polynomial',
};

/**
 * Statically find candidate ReDoS shapes in a regex, then DYNAMICALLY confirm
 * each by measuring a real hang in an isolated worker. Returns the first
 * confirmed vulnerability (with a shareable proof), or a not-vulnerable result.
 *
 * @param {string} source  regex source (no slashes)
 * @param {string} flags   regex flags (e.g. 'i')
 * @param {object} opts    { timeoutMs, maxPumps }
 */
async function scanRegex(source, flags = '', opts = {}) {
  const candidates = findCandidates(source);
  if (candidates.length === 0) {
    return { source, flags, vulnerable: false, candidates: 0, checked: 0 };
  }
  // Exponential candidates need only a few pumps; polynomial needs more.
  let checked = 0;
  for (const attack of candidates) {
    const isPoly = CLASS_BY_KIND[attack.kind] === 'polynomial';
    const runOpts = {
      timeoutMs: opts.timeoutMs ?? 1000,
      maxPumps: opts.maxPumps ?? (isPoly ? 100000 : 5000),
    };
    checked++;
    const res = await confirm(source, flags, attack, runOpts);
    if (res.vulnerable) {
      return {
        source,
        flags,
        vulnerable: true,
        kind: attack.kind,
        complexity: CLASS_BY_KIND[attack.kind] || 'unknown',
        matchedShape: attack.matchedShape,
        proof: res.proof,
        samples: res.samples,
        candidates: candidates.length,
        checked,
      };
    }
  }
  return { source, flags, vulnerable: false, candidates: candidates.length, checked };
}

module.exports = { scanRegex };
