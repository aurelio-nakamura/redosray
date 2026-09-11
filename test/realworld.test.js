'use strict';
// Real-world accuracy regression tests: validate redosray's core differentiator
// vs static-only linters — dynamic confirmation must NOT false-positive on
// scary-looking-but-safe shapes (e.g. unanchored nested quantifiers), and MUST
// confirm the genuinely catastrophic anchored variants with a real measured hang.
const test = require('node:test');
const assert = require('node:assert');
const { scanRegex } = require('../src/scan.js');

const T = { timeoutMs: 1200 };

test('anchored nested quantifier is confirmed EXPONENTIAL', async () => {
  const r = await scanRegex('^(a+)+$', '', T);
  assert.strictEqual(r.vulnerable, true);
  assert.strictEqual(r.complexity, 'exponential');
  assert.ok(r.proof, 'has a proof input');
});

test('anchored (\\w+\\s*)+$ is confirmed vulnerable', async () => {
  const r = await scanRegex('(\\w+\\s*)+$', '', T);
  assert.strictEqual(r.vulnerable, true);
});

// Regression: the classic vulnerable email validator. The exploitable overlap is
// on the trailing `[a-zA-Z0-9]+`, not the first-encountered `[_]+` — earlier
// versions probed only the first inner loop and missed this real ReDoS.
test('classic vulnerable email regex is confirmed (multi inner-loop)', async () => {
  const src = '^([a-zA-Z0-9])(([\\-.]|[_]+)?([a-zA-Z0-9]+))*(@){1}[a-z0-9]+[.]{1}(([a-z]{2,3})|([a-z]{2,3}[.]{1}[a-z]{2,3}))$';
  const r = await scanRegex(src, '', { timeoutMs: 1500 });
  assert.strictEqual(r.vulnerable, true);
});

// Regression: vulnerable loop buried mid-pattern needs a REACHING PREFIX (the
// `<` literal) and an end-of-string suffix so the required trailing `>` fails.
test('mid-pattern (X*)* after a required prefix is confirmed', async () => {
  const r = await scanRegex('<([a-z]+)([^>]*)*>', '', { timeoutMs: 1500 });
  assert.strictEqual(r.vulnerable, true);
  assert.ok(r.proof.input.startsWith('<'), 'proof input reaches the loop via the `<` prefix');
});

test('UNANCHORED (\\w+\\s*)+ is safe (no catastrophic backtracking)', async () => {
  // Static-only tools false-positive here; dynamic confirmation clears it.
  const r = await scanRegex('(\\w+\\s*)+', '', T);
  assert.strictEqual(r.vulnerable, false);
});

test('^(.*,)*.*$ is not catastrophic in practice (no false positive)', async () => {
  const r = await scanRegex('^(.*,)*.*$', '', T);
  assert.strictEqual(r.vulnerable, false);
});

test('common safe patterns are never flagged', async () => {
  for (const src of ['^\\w+$', '^(abc|def)+$', '^[a-z]{1,10}$', '^\\d{4}-\\d{2}-\\d{2}$', '^\\s+|\\s+$']) {
    const r = await scanRegex(src, '', T);
    assert.strictEqual(r.vulnerable, false, `${src} should be safe`);
  }
});
