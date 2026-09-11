# Changelog

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
