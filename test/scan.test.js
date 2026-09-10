'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { scanRegex, findCandidates } = require('../src/index');

const FAST = { timeoutMs: 700, maxPumps: 4000 };

// ---- Vulnerable patterns: must be CONFIRMED (real measured hang) ----
const VULN = [
  ['^(a+)+$', 'nested-quantifier'],
  ['^([a-z]+)*$', 'nested-quantifier'],
  ['^(\\d+)+$', 'nested-quantifier'],
  ['^(?:a+)+$', 'nested-quantifier'],
  ['^(a|a)+$', 'ambiguous-alternation'],
  ['^(\\w|\\d)+$', 'ambiguous-alternation'],
  ['^(a|.)+$', 'ambiguous-alternation'],
  ['^(.*a){2,}$', 'nested-quantifier'],
];

for (const [src, kind] of VULN) {
  test(`confirms vulnerable: ${src}`, async () => {
    const r = await scanRegex(src, '', FAST);
    assert.ok(r.vulnerable, `${src} should be confirmed vulnerable`);
    assert.ok(r.proof && r.proof.input.length > 0, 'has a proof input');
    assert.ok(r.proof.input.length < 5000, 'proof is a manageable size');
  });
}

// ---- Safe patterns: must NOT be flagged (no confirmed hang) ----
const SAFE = [
  '^a+$',
  '^[a-z]+$',
  '^(abc|def)$',
  '^\\d{4}-\\d{2}-\\d{2}$',
  '^(ba+)+$',        // each group iteration starts with a required 'b'
  '^https?://\\S+$',
  '^(a|b|c)+$',      // disjoint alternation -> linear
];

for (const src of SAFE) {
  test(`does not flag safe: ${src}`, async () => {
    const r = await scanRegex(src, '', FAST);
    assert.strictEqual(r.vulnerable, false, `${src} should be safe`);
  });
}

test('polynomial sequential quantifier is detected as a candidate', () => {
  const cands = findCandidates('\\d+\\d+$');
  assert.ok(cands.some((c) => c.kind === 'sequential-quantifier'));
});

test('proof input actually reproduces the hang deterministically', async () => {
  const { timeMatch } = require('../src/index');
  const r = await scanRegex('^(a+)+$', '', FAST);
  assert.ok(r.vulnerable);
  const replay = await timeMatch('^(a+)+$', '', r.proof.input, 700);
  assert.ok(replay.timedOut, 'replaying the proof input re-triggers the hang');
});
