'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { extractFromText } = require('../src/extract');

function sources(text, path = 'x.js') {
  return extractFromText(text, path).map((r) => r.source);
}

test('extracts a simple JS regex literal', () => {
  const s = sources('const re = /^(a+)+$/;');
  assert.deepStrictEqual(s, ['^(a+)+$']);
});

test('extracts flags and reports line/column', () => {
  const found = extractFromText('\n\nconst r = /foo/gi;', 'x.js');
  assert.strictEqual(found.length, 1);
  assert.strictEqual(found[0].source, 'foo');
  assert.strictEqual(found[0].flags, 'gi');
  assert.strictEqual(found[0].line, 3);
});

test('does NOT treat division as a regex', () => {
  const s = sources('const x = a / b / c;');
  assert.deepStrictEqual(s, []);
});

test('ignores regex-looking content inside strings', () => {
  const s = sources('const msg = "use /pattern/ here";');
  assert.deepStrictEqual(s, []);
});

test('ignores regex-looking content inside line comments', () => {
  const s = sources('// this /is/ not code\nconst n = 1;');
  assert.deepStrictEqual(s, []);
});

test('ignores block comments', () => {
  const s = sources('/* /a+/ inside comment */ const n = 2;');
  assert.deepStrictEqual(s, []);
});

test('handles character classes containing a slash', () => {
  const s = sources('const p = /[/a-z]+/;');
  assert.deepStrictEqual(s, ['[/a-z]+']);
});

test('extracts new RegExp("...") constructor', () => {
  const s = sources('const r = new RegExp("(a|a)+", "i");');
  assert.deepStrictEqual(s, ['(a|a)+']);
});

test('regex allowed after return', () => {
  const s = sources('function f(){ return /x+y/; }');
  assert.deepStrictEqual(s, ['x+y']);
});

test('extracts Python re.compile raw string', () => {
  const s = sources("re.compile(r'^(a+)+$')", 'x.py');
  assert.deepStrictEqual(s, ['^(a+)+$']);
});

test('extracts Python re.match', () => {
  const s = sources('re.match("\\\\d+abc", value)', 'x.py');
  assert.strictEqual(s.length, 1);
});

test('multiple literals in one file', () => {
  const s = sources('const a = /foo/; const b = /bar/g; const c = /(x+)+/;');
  assert.deepStrictEqual(s, ['foo', 'bar', '(x+)+']);
});
