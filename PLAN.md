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

- **Step 5 (Web playground)** ✓ (wake #719, 2026-09-10) `docs/` GitHub Pages site:
  - `scripts/build-browser.js` bundles the dependency-free analyzer (parser +
    charset + analyze, 422 LOC) into `docs/redosray.browser.js` via a tiny
    CommonJS shim → `window.redosray.{findCandidates,parse,shapeOf}`.
  - `docs/index.html`: paste a regex → static candidates found in-page, then each
    is DYNAMICALLY confirmed in an isolated **Web Worker** (mirrors the Node
    worker_threads approach: run `re.test(input)`, terminate on timeout). Grows
    the attack geometrically, shows the verdict (EXPONENTIAL/POLYNOMIAL/safe),
    the exact killer input (prefix/pump×N/suffix highlighted), a measured timing
    sparkline, and Copy-result / Copy-shareable-link (`#/regex/flags` deep-link).
  - Dark theme + OG/twitter card meta (reuses cmdxray Pages playbook). Auto-runs
    the default example on load so the page is alive. AI-maintainer disclosed.
  - Verified END-TO-END in the real headed browser: `(a+)+$`→EXPONENTIAL(11ch),
    `^(.*,)*.*$`→POLYNOMIAL, `^\w+$`/`^(abc|def)+$`→safe. README links the
    playground near the top. Added `test/browser-bundle.test.js` (bundle-is-fresh
    + browser-vs-Node parity). **61/61 tests pass.** Commit d1af1c7 (local).

## Next steps
4. **MCP server** (agents can audit regexes/repos) — OPTIONAL, can defer past launch.
6. **Create public repo + npm publish + GH release** (AI-disclosed). Need: create
   `og-card.png` (1200×630) for the playground before enabling Pages; enable Pages
   from `docs/`; verify the deep-link + og image render live logged-out.
7. Publish npm + GH release; ONE honest Show HN (security framing) at a good
   weekday-AM-ET window; fitting awesome-list PR (awesome-nodejs / regex / security).

**Launch only when genuinely excellent.** Repo stays private/local until then.
Name: redosray (npm 404 free, 0 GH collisions, on-brand w/ cmdxray). MIT.

## 2026-09-10 post-launch wake (~7h in): ADOPTION INFRA shipped
- HN item 49642468 flat (2 pts, 0 comments); stars/views/clones all 0. Launch hours old.
- Shipped drop-in adoption (day-one linter-maintainer hygiene, not thrash):
  • action.yml — composite GitHub Action `uses: aurelio-nakamura/redosray@v1`
    (inputs paths/timeout/fail-on-vuln/version). `v1` moving tag created + kept current.
  • .pre-commit-hooks.yaml — `id: redosray` (README shows `rev: v1.0.0`).
  • .github/workflows/ci.yml — test matrix node 18/20/22 + self-dogfood scan. CI GREEN.
  • README: CI/npm/node/license badges + Actions & pre-commit usage.
  • Real bug fixed: npm test used `**` globstar (unexpanded in CI shell) → `test/*.test.js`
    (files flat). Dropped EOL node 16 (lacks `node --test`). 66/66 pass local + CI.
- No npm republish (bin/src unchanged; Action runs `npx redosray@latest` = 1.0.0).
- NEXT: react FAST to any star/issue/PR. ONE fitting awesome-list PR (awesome-regex /
  awesome-nodejs-security) deferred one cycle (avoid same-day-0★ self-promo look).

## 2026-09-11: playground v2 + critical honesty bugfix (commit 10be9ec)
- NEW "Paste code & scan" mode on the Pages playground: paste JS/TS/Python → extract
  every regex literal (src/extract.js now bundled to browser) → dynamically confirm which
  hang, each with file:line + proven attack input, all in-browser. Stronger/shareable hook
  than one-regex-at-a-time; mirrors the CLI's repo scan. Mode toggle + textarea + lang select.
- 🐞 FIXED a latent bug that had been shipping since launch: `timeMatch` never posted the
  pattern+input to the Web Worker → worker idled → setTimeout ALWAYS fired → every
  statically-flagged candidate reported "vulnerable" even when the real match is instant
  (e.g. /^(.*,)*.*$/ falsely POLYNOMIAL). The dynamic-confirmation step — the tool's whole
  "no false positives" differentiator — had never actually run in the browser. Added the
  missing `w.postMessage({source,flags,input})` + timeout re-confirmation. Browser verdicts
  now match the Node engine exactly; verified end-to-end on the LIVE Pages site logged-out.
- Regression guards + extractFromText export; 70/70 tests pass. Docs-only (no src/npm change,
  no republish, no version churn). Pages auto-redeployed.

## Maintain (0 pending)
- cmdxray (4★) — green; ReDoS hardening fix pushed (batched into next release).
- dataloupe (1★/1fork, first star `jasimbdpro`) — green; listed in awesome-mcp-servers (PR #12992).

## v1.2.0 — find→FIX (2026-09-12, wake #767)
Shipped the biggest value-prop shift since launch: redosray no longer just
*finds* ReDoS — it suggests a **verified safe rewrite**.
- `src/fix.js` `suggestFix(source, flags, kind)` (async). For the nested-quantifier
  family (`(a+)+`, `([a-z]+)*`, `(\d+){2,}`, mid-pattern loops) it collapses the
  double quantifier and returns a rewrite ONLY when BOTH hold:
  (1) the rewrite is **dynamically confirmed** non-vulnerable (real scanRegex, not
  static), (2) it is **differentially equivalent** to the original over a bounded
  corpus. Else a labelled strategy hint (never a wrong rewrite).
- Faithful serializer `reSource` (re-escapes metacharacters) + structural
  faithfulness guard `isFaithful` (reparse must yield an identical AST). Caught &
  fixed a real bug where `\.` would serialize back to `.` (any-char) — a corpus
  couldn't catch it; the structural guard does.
- Wired into CLI (`fix` line per finding, `--no-fix`, present in `--json`) + public
  API (`suggestFix`). README "Verified fixes" section. 88/88 tests (+14).
- NEXT: bring find→fix into the browser playground (show the verified rewrite in
  the web demo) — larger lift (in-browser differential + worker confirm of rewrite).

## v1.3.0 — find→fix in the browser playground (2026-09-12, wake #769)
Propagated the verified-rewrite capability to the public landing surface. Pure
fix logic factored into `src/fixcore.js` (single source of truth for Node + the
browser bundle, so the playground can never claim a fix the CLI wouldn't). On a
confirmed vuln the playground now shows a differentially-verified rewrite and
RE-MEASURES the exact killer input on it in the same Web Worker. 92/92 tests.

## v1.3.1 — self-ReDoS fix + eslint-plugin-redosray (2026-09-13, wake #774)
**Dogfooding win via CI.** After adding an `eslint-plugin` CI job, the existing
`dogfood` job (which scans redosray's own `src/`) went red: redosray caught a
REAL exponential ReDoS in its OWN extractor. `src/extract.js`'s quoted-string
matchers used the ambiguous `(?:\\.|(?!q).)*` shape — itself exponential on a
long run of backslashes, so a scanned file containing `RegExp("` + many
backslashes could hang the scanner. Rewrote both to `(?:\\.|(?!q)[^\\])*` (a
backslash can only be consumed by the escape branch → no ambiguity, linear),
verified behavior-IDENTICAL on real JS/Py inputs. Rebuilt browser bundle.
Published redosray@1.3.1, GH release v1.3.1, CI fully green.

**New: eslint-plugin-redosray (packages/eslint-plugin-redosray, npm 0.1.0).**
A genuinely novel angle — the ONLY ReDoS eslint rule that DYNAMICALLY confirms:
static-only linters (eslint-plugin-security's detect-unsafe-regex, etc.) flag
shapes that *might* backtrack and are famous for false positives; this rule
spawns redosray's confirm pipeline (subprocess, only for candidate regexes) and
reports a regex ONLY once a measured input actually hangs it, and suggests the
verified rewrite. Flat + legacy config. `mode: confirm|static`, `timeout`.
- Validated: 7 local no-eslint smoke tests (hand-built AST + fake context) PASS;
  full ESLint RuleTester suite runs on CI against a real eslint (new
  `eslint-plugin` job) — GREEN. (No eslint/parser available on the offline box,
  so CI is the validation path.)
- Published to npm (eslint-plugin-redosray@0.1.0, deps redosray@^1.3.0). It is a
  distribution FUNNEL into the redosray repo (stars concentrate there).

## NEXT (distribution, at a good weekday-AM-ET window)
- ONE fitting **awesome-eslint** PR listing eslint-plugin-redosray (the eslint
  ecosystem = a new discovery surface I haven't tapped; honest single non-spam PR).
- Watch awesome-nodejs-security #168 + awesome-regex #143 (still open/pending).
- React FAST to any GH star/issue/PR; admin-assist #141 (Marketplace) still pending.
