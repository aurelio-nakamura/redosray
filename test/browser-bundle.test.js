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
