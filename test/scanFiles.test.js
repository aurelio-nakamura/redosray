'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { scanPaths } = require('../src/scanFiles');

function tmpRepo(files) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redosray-'));
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(dir, rel);
    fs.mkdirSync(path.dirname(full), { recursive: true });
    fs.writeFileSync(full, content);
  }
  return dir;
}

test('finds and confirms a vulnerable regex in a JS file with location', async () => {
  const dir = tmpRepo({
    'src/a.js': 'const re = /^(a+)+$/;\nmodule.exports = re;\n',
    'src/safe.js': 'const ok = /^[a-z0-9]+$/;\n',
  });
  const report = await scanPaths(dir, { timeoutMs: 800 });
  assert.strictEqual(report.vulnerable, 1);
  const f = report.findings[0];
  assert.strictEqual(f.source, '^(a+)+$');
  assert.strictEqual(f.complexity, 'exponential');
  assert.ok(f.proof.input.length > 0);
  assert.strictEqual(f.locations[0].line, 1);
  assert.ok(f.locations[0].file.endsWith('a.js'));
});

test('reports zero findings for a clean repo', async () => {
  const dir = tmpRepo({
    'x.js': 'const a = /foo/; const b = /^[0-9]{3}-[0-9]{4}$/;\n',
  });
  const report = await scanPaths(dir, { timeoutMs: 800 });
  assert.strictEqual(report.vulnerable, 0);
});

test('skips node_modules by default', async () => {
  const dir = tmpRepo({
    'node_modules/dep/index.js': 'const re = /(a+)+$/;\n',
    'app.js': 'const ok = /hello/;\n',
  });
  const report = await scanPaths(dir, { timeoutMs: 800 });
  assert.strictEqual(report.vulnerable, 0);
});

test('dedupes identical patterns but keeps all locations', async () => {
  const dir = tmpRepo({
    'a.js': 'const r = /(x+)+$/;\n',
    'b.js': 'const r = /(x+)+$/;\n',
  });
  const report = await scanPaths(dir, { timeoutMs: 800 });
  assert.strictEqual(report.vulnerable, 1);
  assert.strictEqual(report.findings[0].locations.length, 2);
});

test('scans Python files', async () => {
  const dir = tmpRepo({
    'app.py': "import re\nP = re.compile(r'^(a+)+$')\n",
  });
  const report = await scanPaths(dir, { timeoutMs: 800 });
  assert.strictEqual(report.vulnerable, 1);
  assert.ok(report.findings[0].locations[0].file.endsWith('app.py'));
});
