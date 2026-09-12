'use strict';
// Safe-rewrite suggester (Node).
//
// Thin wrapper over src/fixcore.js (the pure, browser-shareable core). This file
// adds the ONE thing the core deliberately leaves out: a real, DYNAMIC confirmation
// that the candidate rewrite no longer hangs — measured in an isolated worker, the
// same way the CLI confirms the original vulnerability. So a `verified: true` fix is
// always (a) differentially equivalent to the original AND (b) a measured non-hang;
// never a static guess. The browser bundle reuses fixcore + its own Web Worker to
// make the identical guarantee in the playground.

const { verifiedRewrite, STRATEGY_NOTES } = require('./fixcore');
const { scanRegex } = require('./scan');

/**
 * Suggest a fix for a (candidate) ReDoS regex.
 * @param {string} source  regex source (no slashes)
 * @param {string} flags   regex flags
 * @param {string} [kind]  detected vulnerability family (for the strategy note)
 * @returns {Promise<{ rewrite?: string, verified: boolean, kind?: string, note: string,
 *             capturesChanged?: boolean }>}
 *   - If `rewrite` is present, it is DIFFERENTIALLY VERIFIED equivalent AND a
 *     dynamically-measured non-hang.
 *   - Otherwise `note` is a labelled strategy suggestion (not a proof).
 */
async function suggestFix(source, flags = '', kind) {
  const cand = verifiedRewrite(source, flags);
  if (cand) {
    let clean = false;
    try {
      const scan = await scanRegex(cand.rewrite, flags, { timeoutMs: 800 });
      clean = !scan.vulnerable;
    } catch { clean = false; }
    if (clean) {
      return {
        rewrite: cand.rewrite,
        verified: true,
        kind: kind || 'nested-quantifier',
        note: cand.note,
        capturesChanged: cand.capturesChanged,
      };
    }
  }
  const note = (kind && STRATEGY_NOTES[kind]) || STRATEGY_NOTES['nested-quantifier'];
  return { verified: false, kind, note };
}

module.exports = { suggestFix };
