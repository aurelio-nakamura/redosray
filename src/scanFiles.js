'use strict';

const fs = require('fs');
const path = require('path');
const { extractFromText, languageForPath } = require('./extract');
const { scanRegex } = require('./scan');

const DEFAULT_IGNORE = new Set([
  'node_modules', '.git', 'dist', 'build', 'out', 'coverage',
  '.next', '.nuxt', '.venv', 'venv', '__pycache__', 'vendor',
  '.cache', 'target', '.svelte-kit',
]);

function isScannable(p) {
  return languageForPath(p) !== null;
}

/**
 * Recursively collect scannable source files under a set of roots.
 */
function collectFiles(roots, { ignore = DEFAULT_IGNORE, maxBytes = 2_000_000 } = {}) {
  const files = [];
  const seen = new Set();
  const stack = Array.isArray(roots) ? [...roots] : [roots];
  while (stack.length) {
    const cur = stack.pop();
    let st;
    try { st = fs.statSync(cur); } catch { continue; }
    if (st.isDirectory()) {
      const base = path.basename(cur);
      if (ignore.has(base)) continue;
      let entries;
      try { entries = fs.readdirSync(cur); } catch { continue; }
      for (const e of entries) stack.push(path.join(cur, e));
    } else if (st.isFile()) {
      if (!isScannable(cur)) continue;
      if (st.size > maxBytes) continue;
      const real = fs.realpathSync(cur);
      if (seen.has(real)) continue;
      seen.add(real);
      files.push(cur);
    }
  }
  files.sort();
  return files;
}

/**
 * Deduplicate regex literals by (source+flags) so we confirm each distinct
 * pattern only once (dynamic confirmation is the expensive step), while still
 * reporting every location the pattern appears.
 */
function dedupeRegexes(perFile) {
  const map = new Map();
  for (const { file, regexes } of perFile) {
    for (const r of regexes) {
      const key = r.source + '\u0000' + r.flags;
      if (!map.has(key)) map.set(key, { source: r.source, flags: r.flags, locations: [] });
      map.get(key).locations.push({ file, line: r.line, column: r.column, raw: r.raw, kind: r.kind });
    }
  }
  return [...map.values()];
}

/**
 * Scan one or more files/directories for ReDoS-vulnerable regexes, confirming
 * each dynamically. Returns a structured report.
 *
 * @param {string|string[]} roots  file or directory paths
 * @param {object} opts { timeoutMs, ignore, onProgress }
 */
async function scanPaths(roots, opts = {}) {
  const files = collectFiles(roots, opts);
  const perFile = [];
  for (const file of files) {
    let text;
    try { text = fs.readFileSync(file, 'utf8'); } catch { continue; }
    // skip minified files: huge single lines yield garbage extractions
    if (isLikelyMinified(text)) continue;
    const regexes = extractFromText(text, file);
    if (regexes.length) perFile.push({ file, regexes });
  }

  const distinct = dedupeRegexes(perFile);
  const findings = [];
  let confirmed = 0;
  let idx = 0;
  for (const d of distinct) {
    idx++;
    if (opts.onProgress) opts.onProgress({ index: idx, total: distinct.length, source: d.source });
    let res;
    try {
      res = await scanRegex(d.source, d.flags, { timeoutMs: opts.timeoutMs ?? 1000 });
    } catch (e) {
      continue; // invalid regex source we couldn't compile; skip silently
    }
    if (res.vulnerable) {
      confirmed++;
      findings.push({
        source: d.source,
        flags: d.flags,
        complexity: res.complexity,
        kind: res.kind,
        matchedShape: res.matchedShape,
        proof: res.proof,
        samples: res.samples,
        locations: d.locations,
      });
    }
  }

  // Order findings: exponential first, then by number of locations.
  findings.sort((a, b) => {
    if (a.complexity !== b.complexity) return a.complexity === 'exponential' ? -1 : 1;
    return b.locations.length - a.locations.length;
  });

  return {
    filesScanned: files.length,
    filesWithRegex: perFile.length,
    distinctRegexes: distinct.length,
    vulnerable: confirmed,
    findings,
  };
}

function isLikelyMinified(text) {
  if (text.length < 5000) return false;
  const lines = text.split('\n');
  const avg = text.length / lines.length;
  return avg > 2000;
}

module.exports = { scanPaths, collectFiles, DEFAULT_IGNORE };
