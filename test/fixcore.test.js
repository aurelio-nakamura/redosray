'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { execFileSync } = require('node:child_process');
const { verifiedRewrite, staticallyClean } = require('../src/fixcore');

// fixcore.verifiedRewrite is the PURE core both Node and the browser build on.
// It must produce a differentially-verified equivalent rewrite for a collapsible
// nested quantifier, and null otherwise (so the caller never emits a false claim).
test('verifiedRewrite collapses (a+)+ to an equivalent linear rewrite', () => {
  const r = verifiedRewrite('(a+)+', '');
  assert.ok(r && r.rewrite, 'expected a candidate rewrite');
  assert.strictEqual(r.rewrite, 'a+');
  assert.strictEqual(r.capturesChanged, true);
  assert.ok(staticallyClean(r.rewrite, ''), 'rewrite must not be flagged by the static detector');
});

test('verifiedRewrite returns null when no single-atom nested quantifier exists', () => {
  // inner body is two atoms (x+x+), not a single simple atom -> no safe collapse
  assert.strictEqual(verifiedRewrite('(x+x+)+y', ''), null);
});

test('verifiedRewrite returns null for a genuinely safe pattern', () => {
  assert.strictEqual(verifiedRewrite('^(.*,)*.*$', ''), null);
});

// The browser bundle must expose the SAME core so the playground can't drift into
// a claim the CLI wouldn't make. Rebuild it and evaluate window.redosray.candidateFix.
test('browser bundle exposes candidateFix backed by fixcore', () => {
  const repo = path.join(__dirname, '..');
  execFileSync(process.execPath, ['scripts/build-browser.js'], { cwd: repo });
  const code = fs.readFileSync(path.join(repo, 'docs', 'redosray.browser.js'), 'utf8');
  const sandbox = { self: {} };
  vm.runInNewContext(code, sandbox);
  const rs = sandbox.self.redosray;
  assert.ok(rs && typeof rs.candidateFix === 'function', 'candidateFix must be exported');
  const r = rs.candidateFix('(a+)+', '');
  assert.ok(r && r.rewrite === 'a+', 'browser candidateFix must match Node fixcore');
  assert.strictEqual(rs.candidateFix('(x+x+)+y', ''), null);
  assert.strictEqual(rs.staticallyClean('a+', ''), true);
});
