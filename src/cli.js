'use strict';

const fs = require('fs');
const path = require('path');
const { scanPaths } = require('./scanFiles');
const { scanRegex } = require('./scan');

const VERSION = require('../package.json').version;

const HELP = `redosray — find ReDoS-vulnerable regexes and prove them, offline.

USAGE
  redosray [paths...]            scan files/directories for vulnerable regexes
  redosray -e '<regex>'          test a single regex pattern
  cat file | redosray -e -       read the regex from stdin

OPTIONS
  -e, --regex <pat>   test one regex instead of scanning paths ('-' = stdin)
  -f, --flags <fl>    regex flags for -e mode (e.g. i, gm)
      --json          machine-readable JSON output
      --ci            exit non-zero (2) if any vulnerability is confirmed
      --timeout <ms>  per-match hang threshold (default 1000)
      --no-color      disable ANSI colors
  -h, --help          show this help
  -v, --version       show version

Every reported vulnerability is a REAL measured hang: redosray finds candidate
patterns statically, then confirms each by timing a match against a growing
input inside an isolated worker. The smallest input that crosses the timeout is
printed as shareable proof — no false-positive claims.

Maintained by the AI agent "Aurelio Nakamura". MIT licensed.
`;

function parseArgs(argv) {
  const opts = {
    paths: [], regex: null, flags: '', json: false, ci: false,
    timeoutMs: 1000, color: true, help: false, version: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '-h': case '--help': opts.help = true; break;
      case '-v': case '--version': opts.version = true; break;
      case '--json': opts.json = true; break;
      case '--ci': opts.ci = true; break;
      case '--no-color': opts.color = false; break;
      case '-e': case '--regex': opts.regex = argv[++i]; break;
      case '-f': case '--flags': opts.flags = argv[++i] || ''; break;
      case '--timeout': opts.timeoutMs = parseInt(argv[++i], 10) || 1000; break;
      default:
        if (a.startsWith('-') && a !== '-') {
          process.stderr.write(`redosray: unknown option ${a}\n`);
          process.exitCode = 2;
          opts._error = true;
        } else {
          opts.paths.push(a);
        }
    }
  }
  return opts;
}

// --- minimal ANSI helpers ---
function mkColor(enabled) {
  const wrap = (code) => (s) => (enabled ? `\u001b[${code}m${s}\u001b[0m` : String(s));
  return {
    red: wrap('31'), yellow: wrap('33'), green: wrap('32'),
    cyan: wrap('36'), gray: wrap('90'), bold: wrap('1'), magenta: wrap('35'),
  };
}

function fmtMs(ms) {
  if (ms >= 1000) return `${(ms / 1000).toFixed(2)}s`;
  return `${Math.round(ms)}ms`;
}

function truncate(s, n) {
  if (s.length <= n) return s;
  return s.slice(0, n - 1) + '…';
}

// A tiny sparkline of the timing curve (samples: [{length, ms, timedOut}]).
function sparkline(samples) {
  const bars = '▁▂▃▄▅▆▇█';
  const vals = samples.map((s) => s.timedOut ? Infinity : s.ms);
  const finite = vals.filter((v) => Number.isFinite(v));
  const max = finite.length ? Math.max(...finite, 1) : 1;
  return vals.map((v) => (v === Infinity ? '█' : bars[Math.min(bars.length - 1, Math.floor((v / max) * (bars.length - 1)))])).join('');
}

function describeInput(proof) {
  // Show the proof input compactly: collapse long runs.
  const input = proof.input;
  if (input.length <= 60) return JSON.stringify(input);
  return `${JSON.stringify(input.slice(0, 40))} … (${input.length} chars)`;
}

function printFinding(c, f, index) {
  const tag = f.complexity === 'exponential'
    ? c.red(c.bold(' EXPONENTIAL '))
    : c.yellow(c.bold(' POLYNOMIAL '));
  const kind = c.gray(`(${f.kind})`);
  const out = [];
  out.push(`${c.bold(`#${index}`)} ${tag} ${kind}`);
  out.push(`  ${c.cyan('/' + f.source + '/' + f.flags)}`);
  if (f.locations && f.locations.length) {
    const shown = f.locations.slice(0, 5);
    for (const loc of shown) {
      out.push(`  ${c.gray('at')} ${loc.file}:${loc.line}:${loc.column}`);
    }
    if (f.locations.length > shown.length) {
      out.push(c.gray(`  … +${f.locations.length - shown.length} more location(s)`));
    }
  }
  if (f.proof) {
    const last = f.samples && f.samples.length ? f.samples[f.samples.length - 1] : null;
    out.push(`  ${c.magenta('proof')} input ${describeInput(f.proof)}`);
    out.push(`        ${f.proof.length} chars → hung past ${f.proof.timeoutMs}ms` +
      (last && last.timedOut ? c.gray(` (${last.ms >= f.proof.timeoutMs ? '≥' : ''}${fmtMs(last.ms)})`) : ''));
    if (f.samples && f.samples.length > 1) {
      out.push(`  ${c.gray('curve')} ${sparkline(f.samples)} ${c.gray(`${f.samples[0].length}→${f.samples[f.samples.length - 1].length} chars`)}`);
    }
  }
  return out.join('\n');
}

async function runSingle(opts, c) {
  let source = opts.regex;
  if (source === '-') {
    source = fs.readFileSync(0, 'utf8').trim();
  }
  // Allow the user to paste /pattern/flags form too.
  let flags = opts.flags;
  const m = /^\/(.*)\/([a-z]*)$/s.exec(source);
  if (m) { source = m[1]; if (!flags) flags = m[2]; }

  let res;
  try {
    res = await scanRegex(source, flags, { timeoutMs: opts.timeoutMs });
  } catch (e) {
    if (opts.json) { process.stdout.write(JSON.stringify({ error: String(e.message || e) }) + '\n'); }
    else process.stderr.write(c.red(`redosray: could not analyze regex: ${e.message || e}\n`));
    return 2;
  }

  if (opts.json) {
    process.stdout.write(JSON.stringify(res, null, 2) + '\n');
    return res.vulnerable && opts.ci ? 2 : 0;
  }

  if (!res.vulnerable) {
    process.stdout.write(`${c.green('✓ safe')} ${c.cyan('/' + source + '/' + flags)} ${c.gray(`— ${res.candidates} candidate(s), no hang up to the tested bound`)}\n`);
    return 0;
  }
  const finding = {
    source, flags, complexity: res.complexity, kind: res.kind,
    proof: res.proof, samples: res.samples, locations: [],
  };
  process.stdout.write(printFinding(c, finding, 1) + '\n');
  return opts.ci ? 2 : 0;
}

async function runScan(opts, c) {
  const roots = opts.paths.length ? opts.paths : ['.'];
  for (const r of roots) {
    if (!fs.existsSync(r)) {
      process.stderr.write(c.red(`redosray: path not found: ${r}\n`));
      return 2;
    }
  }

  const isTTY = process.stderr.isTTY;
  const report = await scanPaths(roots, {
    timeoutMs: opts.timeoutMs,
    onProgress: opts.json ? undefined : ({ index, total }) => {
      if (isTTY) process.stderr.write(`\r${c.gray(`scanning regex ${index}/${total}…`)}\u001b[K`);
    },
  });
  if (!opts.json && isTTY) process.stderr.write('\r\u001b[K');

  if (opts.json) {
    process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    return report.vulnerable && opts.ci ? 2 : 0;
  }

  const head = `${c.gray('scanned')} ${report.filesScanned} file(s), ` +
    `${report.distinctRegexes} distinct regex(es)`;
  process.stdout.write(head + '\n');

  if (report.vulnerable === 0) {
    process.stdout.write(c.green('✓ no ReDoS-vulnerable regexes confirmed\n'));
    return 0;
  }

  process.stdout.write('\n');
  report.findings.forEach((f, i) => {
    process.stdout.write(printFinding(c, f, i + 1) + '\n\n');
  });

  const exp = report.findings.filter((f) => f.complexity === 'exponential').length;
  const poly = report.findings.length - exp;
  process.stdout.write(
    c.bold(`${report.vulnerable} vulnerable regex(es): `) +
    `${c.red(`${exp} exponential`)}, ${c.yellow(`${poly} polynomial`)}\n`,
  );
  maybePrintFooter(opts, c);
  return opts.ci ? 2 : 0;
}

// Tasteful, non-nagging pointer shown ONLY in an interactive human terminal
// (never in --json/--ci or when piped/redirected), and only after a scan that
// actually confirmed a vulnerability. Goes to stderr so stdout stays clean.
function maybePrintFooter(opts, c) {
  if (opts.json || opts.ci) return;
  if (!process.stdout.isTTY || !process.stderr.isTTY) return;
  process.stderr.write(
    c.gray('\nShare/verify any finding in the playground: ') +
    c.cyan('https://aurelio-nakamura.github.io/redosray/') +
    c.gray('\nFound this useful? A star helps others find it: ') +
    c.cyan('https://github.com/aurelio-nakamura/redosray') + '\n',
  );
}

async function main(argv) {
  const opts = parseArgs(argv);
  const c = mkColor(opts.color && process.stdout.isTTY && !process.env.NO_COLOR);
  if (opts._error) return 2;
  if (opts.help) { process.stdout.write(HELP); return 0; }
  if (opts.version) { process.stdout.write(`redosray ${VERSION}\n`); return 0; }

  if (opts.regex !== null) return runSingle(opts, c);
  return runScan(opts, c);
}

module.exports = { main, parseArgs, sparkline };

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => { process.exit(code || 0); }).catch((e) => {
    process.stderr.write(`redosray: ${e && e.stack || e}\n`);
    process.exit(1);
  });
}
