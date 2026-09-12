'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { suggestFix } = require('../src/fix');
const { scanRegex } = require('../src/scan');

// Every verified rewrite MUST: (1) be dynamically confirmed non-vulnerable,
// (2) match exactly the same strings as the original over a broad corpus.
function sameLanguage(a, b, flags = '') {
  const reA = new RegExp(a, flags.replace(/[gy]/g, ''));
  const reB = new RegExp(b, flags.replace(/[gy]/g, ''));
  // bounded corpus so a catastrophic original can't hang the test
  const chars = ['a', 'b', 'x', '0', '_', ' ', '!', '\n', '@', '.', '-'];
  let seed = 987654;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  for (let k = 0; k <= 16; k++) {
    for (const t of [a[0] === '^' ? '' : '', '', '!', '\n']) {
      const s = 'a'.repeat(k) + t;
      if (reA.test(s) !== reB.test(s)) return false;
    }
  }
  for (let n = 0; n < 2000; n++) {
    const len = Math.floor(rnd() * 17);
    let s = '';
    for (let j = 0; j < len; j++) s += chars[Math.floor(rnd() * chars.length)];
    if (reA.test(s) !== reB.test(s)) return false;
  }
  return true;
}

const COLLAPSIBLE = [
  ['(a+)+', 'a+'],
  ['(a*)*', 'a*'],
  ['(a+)*', 'a*'],
  ['(a*)+', 'a*'],
  ['([a-z]+)+', '[a-z]+'],
  ['(\\d+)+', '\\d+'],
  ['^(a+){2,}$', '^a{2,}$'],
];

for (const [src, expected] of COLLAPSIBLE) {
  test(`verified rewrite: ${src} -> ${expected}`, async () => {
    const r = await suggestFix(src, '', 'nested-quantifier');
    assert.strictEqual(r.verified, true, `${src} should get a verified rewrite`);
    assert.strictEqual(r.rewrite, expected);
    // gate integrity: rewrite is truly non-vulnerable AND same language
    const scan = await scanRegex(r.rewrite, '', { timeoutMs: 800 });
    assert.strictEqual(scan.vulnerable, false, `${src} rewrite must be non-vulnerable`);
    assert.ok(sameLanguage(src, r.rewrite), `${src} rewrite must match the same strings`);
  });
}

test('never emits a false rewrite for ambiguous alternation (note only)', async () => {
  const r = await suggestFix('(x|x)+y', '', 'ambiguous-alternation');
  assert.strictEqual(r.verified, false);
  assert.strictEqual(r.rewrite, undefined);
  assert.match(r.note, /mutually exclusive/i);
});

test('note only for polynomial sequential shape', async () => {
  const r = await suggestFix('(.*a){2,}', '', 'sequential-quantifier');
  assert.strictEqual(r.verified, false);
  assert.ok(r.note && r.note.length > 0);
});

test('mid-pattern nested loop gets a dynamically-clean rewrite', async () => {
  const r = await suggestFix('<([a-z]+)([^>]*)*>', '', 'nested-quantifier');
  assert.strictEqual(r.verified, true);
  const scan = await scanRegex(r.rewrite, '', { timeoutMs: 800 });
  assert.strictEqual(scan.vulnerable, false);
  assert.ok(sameLanguage('<([a-z]+)([^>]*)*>', r.rewrite));
});

test('unparseable / non-vulnerable input never throws, returns a note', async () => {
  const r = await suggestFix('(a', '', 'nested-quantifier');
  assert.strictEqual(r.verified, false);
  assert.ok(typeof r.note === 'string');
});

test('capturesChanged flag set when a capture group is removed', async () => {
  const r = await suggestFix('(a+)+', '', 'nested-quantifier');
  assert.strictEqual(r.capturesChanged, true);
});

// Regression: the serializer must re-escape metacharacters. A naive rewrite
// turned \. (literal dot) into . (any char) — a silent semantics change that
// a literal-sparse corpus would miss. Guard it explicitly.
test('preserves escaped metacharacters in the rewrite (\\. stays \\.)', async () => {
  const src = '^([a-zA-Z0-9]+)+@example\\.com$';
  const r = await suggestFix(src, '', 'nested-quantifier');
  assert.strictEqual(r.verified, true);
  assert.strictEqual(r.rewrite, '^[a-zA-Z0-9]+@example\\.com$');
  const reOrig = new RegExp(src);
  const reNew = new RegExp(r.rewrite);
  // The literal dot must NOT have become "any char" in the rewrite.
  for (const s of ['a@example.com', 'a@exampleXcom', 'ab@example.com', 'a@example-com']) {
    assert.strictEqual(reOrig.test(s), reNew.test(s), `mismatch on "${s}"`);
  }
  assert.strictEqual(reNew.test('a@exampleXcom'), false);
});

test('does not rewrite when the loop body is not a single simple atom', async () => {
  const r = await suggestFix('(a\\.b+)+', '', 'nested-quantifier');
  assert.strictEqual(r.verified, false);
  assert.strictEqual(r.rewrite, undefined);
});
