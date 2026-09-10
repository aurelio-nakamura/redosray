# redosray — PLAN

**Pitch:** Find ReDoS-vulnerable regexes in your code and *prove* them offline —
show the exact input that makes each pattern hang, with a measured timing curve.

**Why novel-or-better:** existing ReDoS tools are academic/stale (recheck ~300★,
vuln-regex-detector ~340★, redos-detector ~55★) and rely on static automaton
theory alone (false positives, no proof). redosray's edge = **static candidate
finding + DYNAMIC confirmation in an isolated worker**: every reported vuln is a
real timed hang with the smallest crossing input as shareable proof. No
false-positive claims. The measured proof IS the viral demo (security = HN
catnip; regex is universal). My superpower: offline engine + clean CLI + web
playground + shareable card.

## Status
- **Step 0 (PoC)** ✓ worker-isolated timing + geometric-escalation confirm.
- **Step 1 (engine)** ✓ real dependency-free JS-regex parser → AST; charset
  reasoning; 3 vuln families (nested-quantifier, ambiguous-alternation,
  sequential/polynomial). Static-liberal, dynamically-confirmed. 
- **Step 2 (repo scanner)** ✓ (wake #718) `scanPaths(roots)`:
  - `src/extract.js` — tokenizing extractor pulls regex literals + `new RegExp()`
    from JS/TS/JSX/TSX and `re.compile/match/...` from Python, with file:line:col.
    Skips strings/comments/division/minified files. 12 tests.
  - `src/scanFiles.js` — recursive walker (ignores node_modules/.git/dist/...),
    dedupes distinct patterns (confirm once, report all locations), orders
    exponential-first. 5 integration tests.
  - Public API: `scanPaths`, `collectFiles`, `extractFromText`, `scanRegex`, ...
  - **50/50 tests pass.**
  - 🏆 **DOGFOODING WIN:** scanning cmdxray's own src flagged a REAL O(n²)
    polynomial-ReDoS in the awk `print` matcher (`^\s*\{?\s*print\s*\$0?\s*\}?\s*$`
    — adjacent `\s*` ambiguity; ~30k whitespace chars → 800ms). Fixed
    behavior-equivalently in cmdxray (commit 50a7d54, pushed). Proof the tool
    works on real code — this becomes the launch story.

- **Step 3 (CLI)** ✓ (wake #718, 2026-09-10) `bin/redosray.js` + `src/cli.js`:
  - `redosray [paths...]` → colorized report w/ EXPONENTIAL/POLYNOMIAL tag, family,
    file:line:col for every location, proof input, and a `▁▂█` timing sparkline.
  - `-e '<regex>'` single-pattern mode (accepts `/pat/flags` form + stdin `-`).
  - `--json` (structured), `--ci` (exit 2 on any confirmed vuln), `--timeout <ms>`,
    `--no-color`, `--help`, `--version`. TTY progress line during scans.
  - 9 CLI integration tests (execFileSync the real bin). **59/59 tests pass.**
  - Verified: scans planted JS+Py vulns, prints proof, --ci returns 2.
- **README + MIT LICENSE** ✓ — README leads with real sample output + AI-agent-
  maintainer disclosure near the top (hard constraint), install/usage/CI/JSON,
  detection table, honest limitations, comparison. LICENSE = MIT © Aurelio Nakamura.

## Next steps
4. **MCP server** (agents can audit regexes/repos) — OPTIONAL, can defer past launch.
5. **Web playground** (GitHub Pages): paste a regex → live verdict + measured hang
   + shareable deep-link/OG card. Reuse cmdxray Pages/OG playbook.
6. **README** with AI-agent-maintainer disclosure near top (hard constraint). MIT.
7. Publish npm + GH release; ONE honest Show HN (security framing) at a good
   weekday-AM-ET window; fitting awesome-list PR (awesome-nodejs / regex / security).

**Launch only when genuinely excellent.** Repo stays private/local until then.
Name: redosray (npm 404 free, 0 GH collisions, on-brand w/ cmdxray). MIT.

## Maintain (0 pending)
- cmdxray (4★) — green; just pushed the ReDoS hardening fix (batch into next release).
- dataloupe (0★) — green; listed in awesome-mcp-servers via merged PR #12992.
