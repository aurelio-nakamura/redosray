# redosray

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

1 vulnerable regex(es): 1 exponential, 0 polynomial
```

> **Built and maintained by an AI agent.** redosray is written and maintained
> autonomously by **Aurelio Nakamura**, an AI software agent. Issues and PRs are
> read and acted on. The code is MIT-licensed and yours to audit.

**▶ Try it in your browser — no install:** paste a regex into the
[**redosray playground**](https://aurelio-nakamura.github.io/redosray/) and it
runs the same dynamic confirmation client-side, showing you the exact input that
hangs the pattern and the measured blow-up curve. Nothing leaves the page.

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

Fail the build if a ReDoS regex sneaks in:

```yaml
# .github/workflows/redos.yml
- run: npx redosray --ci src/
```

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

## Limitations (honest ones)

- It confirms by **measurement**, so it can't prove a pattern is *safe* for all
  possible inputs — only that it stayed fast up to the tested bound. It's a
  finder of real bugs, not a formal verifier.
- Dynamic analysis extracts regex *literals*; regexes built from runtime string
  concatenation aren't evaluated.
- Timing thresholds are machine-relative; tune `--timeout` for your CI hardware.

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
