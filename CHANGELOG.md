# Changelog

## 1.3.1 — 2026-09-13

### Fix: redosray no longer ReDoS-able by its own input

The source extractor's quoted-string matchers used the ambiguous
`(?:\\.|(?!q).)*` shape — which is itself exponential on a long run of
backslashes. A scanned file containing `RegExp("` followed by many backslashes
could hang the scanner. Rewrote both matchers to `(?:\\.|(?!q)[^\\])*` so a
backslash can only be consumed by the escape branch (no ambiguity, linear),
verified behavior-identical on real inputs. Found by dogfooding redosray on its
own source in CI.

### New: `eslint-plugin-redosray`

A companion ESLint plugin (in `packages/eslint-plugin-redosray`) that runs the
same static-find + dynamic-confirm pipeline as a lint rule, so it flags a regex
only once a measured input actually hangs it — no false positives on
scary-but-safe patterns — and suggests the verified linear rewrite.

## 1.1.0 — 2026-09-11

### Detection accuracy (fewer false negatives)

Two real-world ReDoS patterns that earlier versions declared "clean" are now
correctly confirmed as vulnerable, each with a measured proof:

- **Multiple inner loops.** A quantified group can contain more than one inner
  `+`/`*`, and the exploitable one isn't always the first. In the classic
  vulnerable email validator
  `(([\-.]|[_]+)?([a-zA-Z0-9]+))*`, the blow-up rides on the trailing
  `[a-zA-Z0-9]+`, not the first-encountered `[_]+`. redosray now probes **every**
  inner loop of a quantified group, so it catches this exponential case.

- **Vulnerable loops buried mid-pattern.** When the catastrophic loop isn't at
  the start of the regex (e.g. the `([^>]*)*` in `<([a-z]+)([^>]*)*>`), the
  engine must first *reach* it. redosray now reconstructs a **reaching prefix**
  (here the `<`) and tries an end-of-string suffix so a required trailing token
  (the final `>`) fails — reproducing the real hang.

Both are covered by regression tests. True negatives (safe patterns such as
`^\s+|\s+$`, ISO-date validators, and disjoint alternations) remain unflagged —
every "vulnerable" verdict is still a real, measured hang.

### Reliability

- The test suite now runs serially (`--test-concurrency=1`) so timing-based
  dynamic confirmations aren't starved by parallel workers — no more flaky CI.

## 1.0.0 — 2026-09-10

Initial public release: static candidate finder (dependency-free JS-regex parser
+ AST analysis) paired with isolated dynamic confirmation, a CLI, a GitHub Action
/ pre-commit hook, and an in-browser playground.
