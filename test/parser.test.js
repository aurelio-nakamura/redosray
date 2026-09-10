'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { parse } = require('../src/parser');
const { shapeOf } = require('../src/analyze');

// Round-trip a sample of regexes through parse -> shapeOf. shapeOf is not a
// perfect inverse (it normalises), so we assert on structural round-trips that
// should be stable.
const roundtrips = [
  'abc',
  'a|b|c',
  'a+',
  'a*',
  'a?',
  '(a+)+',
  '(?:a+)+',
  '([a-z]+)*',
  '\\d+\\d+',
  '(a|ab)+',
  '.*.*',
  'a{2,5}',
  '(foo|bar)baz',
];

for (const src of roundtrips) {
  test(`parses and re-serialises: ${src}`, () => {
    const ast = parse(src);
    const out = shapeOf(ast);
    assert.strictEqual(out, src, `${src} -> ${out}`);
  });
}

test('parses named group and lookahead without throwing', () => {
  assert.doesNotThrow(() => parse('(?<year>\\d{4})-(?=\\d)'));
});

test('parses negated and ranged char classes', () => {
  const ast = parse('[^a-z0-9_]');
  assert.strictEqual(ast.type, 'class');
  assert.strictEqual(ast.negated, true);
});

test('throws on unbalanced group', () => {
  assert.throws(() => parse('(a+'));
});
