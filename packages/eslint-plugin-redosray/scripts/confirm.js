'use strict';
// Out-of-process ReDoS confirmation runner.
//
// ESLint rules are synchronous, but proving a regex actually hangs requires
// running it against a growing attack string in an *isolated, killable* context
// (a catastrophic match cannot be interrupted cooperatively). So the lint rule
// spawns this script with execFileSync: it runs redosray's full dynamic
// confirmation (which itself isolates each match in a worker) and prints the
// verdict as JSON on stdout. The parent's execFileSync timeout is a final
// safety cap on top of redosray's per-match timeout.
//
// argv: <source> <flags> <timeoutMs>

function loadRedosray() {
  try {
    return require('redosray');
  } catch (_) {
    // Local/dev fallback: resolve the sibling package in the monorepo.
    const path = require('node:path');
    return require(path.join(__dirname, '..', '..', '..', 'src', 'index.js'));
  }
}

async function main() {
  const source = process.argv[2];
  const flags = process.argv[3] || '';
  const timeoutMs = Number(process.argv[4]) || 1000;
  const { scanRegex, suggestFix } = loadRedosray();

  const res = await scanRegex(source, flags, { timeoutMs });
  if (res && res.vulnerable) {
    try {
      res.fix = await suggestFix(source, flags, res.kind);
    } catch (_) {
      /* fix is best-effort; a missing fix never blocks the finding */
    }
  }
  process.stdout.write(JSON.stringify(res));
}

main().catch((err) => {
  process.stderr.write(String((err && err.stack) || err));
  process.exit(1);
});
