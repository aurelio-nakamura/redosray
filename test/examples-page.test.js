'use strict';
// Guards that docs/examples.html never drifts from the engine: every regex the
// page links to the playground as "vulnerable" must actually be confirmed
// vulnerable by scanRegex, and every safe rewrite / safe example must be safe.
// (Same spirit as the playground chip-consistency guard.)
const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { scanRegex } = require('../src/index');

const HTML = fs.readFileSync(path.join(__dirname, '..', 'docs', 'examples.html'), 'utf8');

// Featured "Prove it live" deep-links → the class the page claims for them.
// (%2F.../%2F is the #/regex/flags deep-link, URL-encoded.)
const claims = [
  ['^(a+)+$', 'vuln'],
  ['(x+x+)+y', 'vuln'],
  ['^([a-zA-Z0-9])(([\\.\\-]?[a-zA-Z0-9]+)*)@', 'vuln'],
  ['<([a-z]+)([^>]*)*>', 'vuln'],
  ['^(.*,)*.*$', 'safe'],
  // safe rewrites shown in <code class="good">
  ['^a+$', 'safe'],
  ['x+y', 'safe'],
  ['^[a-z0-9]+([._-][a-z0-9]+)*@', 'safe'],
  ['^\\d+$', 'safe'],
  ['^[a-z0-9]+([._-][a-z0-9]+)*$', 'safe'],
];

test('examples.html verdicts match the engine', async () => {
  for (const [src, want] of claims) {
    const flags = src === '^[a-z0-9]+([._-][a-z0-9]+)*@' ? 'i' : '';
    const r = await scanRegex(src, flags, { timeoutMs: 1000 });
    const got = r.vulnerable ? 'vuln' : 'safe';
    assert.strictEqual(got, want, `examples.html claims ${want} for /${src}/${flags} but engine says ${got}`);
  }
});

test('examples.html deep-links decode to the featured vulnerable patterns', () => {
  // Each vulnerable card links index.html#<encoded>/regex/flags — assert the
  // encoded forms for the four vulnerable examples are present verbatim.
  const encoded = [
    '%2F%5E%28a%2B%29%2B%24%2F',
    '%2F%28x%2Bx%2B%29%2By%2F',
    '%2F%5E%28%5Ba-zA-Z0-9%5D%29%28%28%5B%5C.%5C-%5D%3F%5Ba-zA-Z0-9%5D%2B%29%2A%29%40%2F',
    '%2F%3C%28%5Ba-z%5D%2B%29%28%5B%5E%3E%5D%2A%29%2A%3E%2F',
  ];
  for (const e of encoded) assert.ok(HTML.includes(e), `missing deep-link ${e}`);
});
