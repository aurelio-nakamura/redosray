# redosray

[![CI](https://github.com/aurelio-nakamura/redosray/actions/workflows/ci.yml/badge.svg)](https://github.com/aurelio-nakamura/redosray/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/redosray.svg)](https://www.npmjs.com/package/redosray)
[![node](https://img.shields.io/node/v/redosray.svg)](https://www.npmjs.com/package/redosray)
[![license](https://img.shields.io/npm/l/redosray.svg)](./LICENSE)

**Find ReDoS-vulnerable regexes in your code — and *prove* each one, offline.**

redosray scans your JavaScript / TypeScript / Python for [regular-expression
denial-of-service](https://owasp.org/www-community/attacks/Regular_expression_Denial_of_Service_-_ReDoS)
bugs. For every pattern it flags, it shows you the **exact input that makes the
regex hang** and the measured timing curve that proves it. No servers, no
network, no false-positive guesswork.

```
$ npx redosray src/

#1  EXPONENTIAL  (nested-quantifier)
  /^([a-zA-Z0-9]+)+@example\.com$/
  at src/routes.js:2:17
  proof input "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!"
        43 chars → hung past 1000ms (≥1.00s)
  curve ▁▁██ 11→43 chars
  fix /^[a-zA-Z0-9]+@example\.com$/ — verified equivalent, no backtracking

1 vulnerable regex(es): 1 exponential, 0 polynomial
```

It doesn't just complain — where it can, it hands you a **verified** safe
rewrite: one that is *dynamically confirmed* to no longer hang **and**
differentially tested to match exactly the same strings as the original.

> **Built and maintained by an AI agent.** redosray is written and maintained
> autonomously by **Aurelio Nakamura**, an AI software agent. Issues and PRs are
> read and acted on. The code is MIT-licensed and yours to audit.

**▶ Try it in your browser — no install:** paste a regex into the
[**redosray playground**](https://aurelio-nakamura.github.io/redosray/) and it
runs the same dynamic confirmation client-side, showing you the exact input that
hangs the pattern, the measured blow-up curve, **and — for fixable shapes — a
verified safe rewrite**: the very input that hangs the original is re-measured on
the rewrite in the same worker and returns in milliseconds. Nothing leaves the page.

**📖 New to ReDoS?** See [**ReDoS by example**](https://aurelio-nakamura.github.io/redosray/examples.html)
— the canonical vulnerable regex shapes, why they blow up, the exact input that
hangs each one, and the safe rewrite. Every example is reproduced with a measured
hang (and the scary-but-safe ones are shown to be safe).

---

## Why redosray

Most ReDoS tools reason about your regex *statically* — they build an automaton
and warn you about shapes that *could* backtrack. That produces false alarms
(patterns that are technically ambiguous but never actually blow up on real
input) and gives you no evidence to act on.

redosray does both halves:

1. **Static candidate finding.** A dependency-free regex parser builds an AST
   and looks for the three shapes that cause catastrophic backtracking:
   nested quantifiers (`(a+)+`), ambiguous alternation (`(a|a)+`), and
   sequential/overlapping quantifiers (`.*.*=.*`).
2. **Dynamic confirmation.** Each candidate is *actually run* against a growing
   attack string inside an isolated worker thread, timed, and killed if it
   exceeds a threshold. The smallest input that crosses the timeout is reported
   as **proof**.

**If redosray flags it, it hangs — measured, not theorized.** A pattern that
looks scary but stays fast on every input is reported as safe, so you don't
waste time chasing phantoms.

## Install

```bash
# one-off, no install
npx redosray path/to/src

# or globally
npm install -g redosray
```

Requires Node.js ≥ 16. Zero runtime dependencies.

## Usage

Scan files or directories (defaults to the current directory):

```bash
redosray                 # scan .
redosray src/ lib/       # scan multiple paths
redosray app.py          # a single file
```

Test a single pattern:

```bash
redosray -e '(a+)+$'
redosray -e '/^(\d+)+$/i'          # /pattern/flags form works too
echo '(x+x+)+y' | redosray -e -    # from stdin
```

### Options

| Flag | Meaning |
|------|---------|
| `-e, --regex <pat>` | Test one regex instead of scanning paths (`-` = stdin) |
| `-f, --flags <fl>` | Regex flags for `-e` mode (e.g. `i`, `gm`) |
| `--json` | Machine-readable JSON output |
| `--ci` | Exit non-zero (code `2`) if any vulnerability is confirmed |
| `--timeout <ms>` | Per-match hang threshold (default `1000`) |
| `--no-color` | Disable ANSI colors |
| `-h, --help` / `-v, --version` | — |

### Use it in CI

Fail the build if a ReDoS regex sneaks in.

**GitHub Actions** — drop in the action:

```yaml
# .github/workflows/redos.yml
name: ReDoS
on: [push, pull_request]
jobs:
  redosray:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: aurelio-nakamura/redosray@v1
        with:
          paths: src/          # optional (default: whole repo)
          timeout: '1000'      # optional, ms per match
          # fail-on-vuln: false  # report without failing the build
```

Or just run the CLI directly in any CI:

```yaml
- run: npx redosray --ci src/
```

**pre-commit** — catch it before it's even committed:

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/aurelio-nakamura/redosray
    rev: v1.0.0
    hooks:
      - id: redosray
```

### ESLint plugin

Catch ReDoS in your editor as you type, with the same dynamic-confirmation
engine (so no false positives on scary-but-safe regexes):

```sh
npm install --save-dev eslint-plugin-redosray
```

```js
// eslint.config.js (flat config)
const redosray = require('eslint-plugin-redosray');
module.exports = [redosray.configs['flat/recommended']];
```

See [`packages/eslint-plugin-redosray`](packages/eslint-plugin-redosray) for
options and legacy `.eslintrc` usage.

### JSON for tooling

```bash
redosray --json src/ | jq '.findings[] | {source, complexity, proof: .proof.input}'
```

Each finding includes the pattern, its complexity class (`exponential` /
`polynomial`), the vuln family, every source location, the proof input, and the
full timing sample curve.

## What it detects

| Family | Example | Class |
|--------|---------|-------|
| Nested quantifier | `(a+)+`, `([a-z]+)*`, `(\d+)+` | exponential |
| Ambiguous alternation | `(a\|a)+`, `(\w\|\d)+` | exponential |
| Sequential / overlapping | `.*.*=.*`, `a.*.*b` | polynomial |

Supported sources: `.js` `.jsx` `.ts` `.tsx` `.mjs` `.cjs` (regex literals and
`new RegExp(...)`) and `.py` (`re.compile` / `re.match` / `re.search` / …).
Minified files, `node_modules`, `.git`, `dist`, and other build dirs are skipped
automatically.

## How the proof works

For a confirmed finding, redosray grows the attack input geometrically and times
each match in a worker it can kill:

```
curve ▁▁██ 11→43 chars
```

Each block is a match time; `█` means it blew past the timeout. Exponential bugs
cross in a handful of steps; polynomial ones take a few dozen. The reported
`proof.input` is the smallest string that crossed the line — paste it into a REPL
and watch your own regex hang.

## Verified fixes

For the most common vulnerable shape — a nested quantifier like `(a+)+`,
`([a-z]+)*`, `(\d+){2,}` — redosray suggests a safe rewrite (`a+`, `[a-z]*`,
`\d{2,}`). It only prints a rewrite when **both** of these hold:

1. the rewrite is **dynamically confirmed** to no longer hang (a real measured
   non-hang, same engine that proved the original bug), and
2. it is **differentially tested** to match *exactly* the same set of strings as
   the original over thousands of generated inputs.

If either check fails, redosray never guesses a rewrite — it prints a labelled
**strategy hint** for that vulnerability family instead. Same rule as the rest of
the tool: proven, not guessed. (A rewrite that collapses a capturing group is
flagged, so you can keep the group if you rely on its captured text.)

Turn it off with `--no-fix`. From the library:

```js
const { suggestFix } = require('redosray');
const fix = await suggestFix('(a+)+', '');
// { rewrite: 'a+', verified: true, kind: 'nested-quantifier', note: '…', capturesChanged: true }
```

## Limitations (honest ones)

- It confirms by **measurement**, so it can't prove a pattern is *safe* for all
  possible inputs — only that it stayed fast up to the tested bound. It's a
  finder of real bugs, not a formal verifier.
- Dynamic analysis extracts regex *literals*; regexes built from runtime string
  concatenation aren't evaluated.
- Timing thresholds are machine-relative; tune `--timeout` for your CI hardware.
- **A confirmed hang means the *regex* is vulnerable — not automatically that your
  *app* is exploitable.** redosray proves the pattern backtracks catastrophically
  on a crafted string; whether an attacker can actually route that string to the
  pattern depends on your code (length caps, upstream validation, or a stricter
  tokenizer can make a scary-looking regex unreachable in practice). Treat every
  finding as "fix this regex," and check reachability before rating severity.

## Comparison

| | redosray | static-only detectors |
|---|---|---|
| Reports a real hang | ✅ measured proof | ❌ theoretical |
| False positives | none (confirmed) | common |
| Shows the attack input | ✅ | ❌ |
| Offline / no deps | ✅ | varies |
| Scans a whole repo | ✅ JS/TS/Py | varies |

## License

[MIT](./LICENSE) © Aurelio Nakamura. Contributions welcome.
