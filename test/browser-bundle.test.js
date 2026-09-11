'use strict';
// Guards that the generated browser bundle (docs/redosray.browser.js) stays in
// sync with the source analyzer: the static candidate finder must produce the
// same verdicts in-browser as it does in Node.
const test = require('node:test');
const assert = require('node:assert');
const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '..');
const BUNDLE = path.join(ROOT, 'docs', 'redosray.browser.js');
const { findCandidates } = require('../src/index');

function loadBundle() {
  const code = fs.readFileSync(BUNDLE, 'utf8');
  const sandbox = { self: {} };
  vm.runInNewContext(code, sandbox);
  return sandbox.self.redosray;
}

test('browser bundle is up to date with the source', () => {
  // Rebuild and confirm the committed bundle would be identical.
  const before = fs.readFileSync(BUNDLE, 'utf8');
  execFileSync(process.execPath, [path.join(ROOT, 'scripts', 'build-browser.js')], { cwd: ROOT });
  const after = fs.readFileSync(BUNDLE, 'utf8');
  assert.strictEqual(after, before, 'docs/redosray.browser.js is stale — run `npm run build:browser`');
});

test('browser bundle findCandidates matches the Node engine', () => {
  const browser = loadBundle();
  assert.ok(browser && typeof browser.findCandidates === 'function');
  const cases = ['(a+)+$', '([a-z]+)*$', '(\\w+)+$', '.*.*=.*', 'a+', '(abc|def)', '^\\w+$'];
  for (const src of cases) {
    const b = browser.findCandidates(src).length > 0;
    const n = findCandidates(src).length > 0;
    assert.strictEqual(b, n, `mismatch for /${src}/: browser=${b} node=${n}`);
  }
});

test('bundle exposes extractFromText for the code-scan playground', () => {
  const browser = loadBundle();
  assert.strictEqual(typeof browser.extractFromText, 'function');
  const found = browser.extractFromText('const re=/^(a+)+$/; const g=/\\d+/g;', 'snippet.ts');
  assert.strictEqual(found.length, 2);
  assert.strictEqual(found[0].source, '^(a+)+$');
});

test('playground worker is actually fed input (no idle-timeout false positives)', () => {
  // Regression guard: timeMatch MUST post the pattern+input to the worker, or the
  // worker idles and every candidate spuriously "times out" (false positives).
  const html = fs.readFileSync(path.join(ROOT, 'docs', 'index.html'), 'utf8');
  assert.ok(
    /w\.postMessage\(\s*\{\s*source\s*:/.test(html),
    'docs/index.html timeMatch must call w.postMessage({source,flags,input})'
  );
});

test('every "vulnerable:" demo chip is actually confirmed vulnerable (no mislabels)', async () => {
  // Regression guard: a chip in the vulnerable row that the engine reports SAFE
  // (or vice-versa) shows a self-contradicting verdict and destroys demo credibility.
  const { scanRegex } = require('../src/index');
  const html = fs.readFileSync(path.join(ROOT, 'docs', 'index.html'), 'utf8');
  const chipRe = /<span class="chip (bad|ok)"[^>]*data-re="([^"]*)"/g;
  let m;
  const chips = [];
  while ((m = chipRe.exec(html)) !== null) chips.push({ label: m[1], re: m[2].replace(/&amp;/g, '&') });
  assert.ok(chips.length >= 4, 'expected demo chips to be present');
  for (const { label, re } of chips) {
    const r = await scanRegex(re, '', { timeoutMs: 1000 });
    if (label === 'bad') {
      assert.ok(r.vulnerable, `chip "${re}" is labeled vulnerable but engine reports SAFE`);
    } else {
      assert.ok(!r.vulnerable, `chip "${re}" is labeled safe but engine reports VULNERABLE`);
    }
  }
});
