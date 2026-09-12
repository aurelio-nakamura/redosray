'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFileSync } = require('child_process');

const BIN = path.join(__dirname, '..', 'bin', 'redosray.js');

function run(args, opts = {}) {
  try {
    const stdout = execFileSync('node', [BIN, ...args], {
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
      ...opts,
    });
    return { code: 0, stdout };
  } catch (e) {
    return { code: e.status, stdout: e.stdout || '', stderr: e.stderr || '' };
  }
}

test('--help exits 0 and mentions usage', () => {
  const r = run(['--help']);
  assert.strictEqual(r.code, 0);
  assert.match(r.stdout, /USAGE/);
});

test('--version prints a version', () => {
  const r = run(['--version']);
  assert.strictEqual(r.code, 0);
  assert.match(r.stdout, /redosray \d/);
});

test('-e on a vulnerable regex reports EXPONENTIAL', () => {
  const r = run(['-e', '(a+)+$']);
  assert.match(r.stdout, /EXPONENTIAL/);
  assert.match(r.stdout, /proof/);
});

test('-e on a safe regex reports safe and exits 0', () => {
  const r = run(['-e', '^\\d{4}-\\d{2}-\\d{2}$']);
  assert.strictEqual(r.code, 0);
  assert.match(r.stdout, /safe/);
});

test('--json emits valid JSON', () => {
  const r = run(['-e', '(a+)+$', '--json']);
  const obj = JSON.parse(r.stdout);
  assert.strictEqual(obj.vulnerable, true);
  assert.strictEqual(obj.complexity, 'exponential');
  assert.ok(obj.proof && typeof obj.proof.input === 'string');
});

test('--ci exits 2 when a vulnerability is confirmed', () => {
  const r = run(['-e', '(a+)+$', '--ci']);
  assert.strictEqual(r.code, 2);
});

test('--ci exits 0 when safe', () => {
  const r = run(['-e', 'abc', '--ci']);
  assert.strictEqual(r.code, 0);
});

test('scans a directory and finds a planted vuln (js + py)', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redosray-cli-'));
  fs.writeFileSync(path.join(dir, 'a.js'), 'const re = /^(\\d+)+$/;\n');
  fs.writeFileSync(path.join(dir, 'b.py'), "import re\nP = re.compile(r'(x+x+)+y')\n");
  const r = run([dir, '--json']);
  const obj = JSON.parse(r.stdout);
  assert.strictEqual(obj.vulnerable, 2);
  assert.strictEqual(obj.findings.length, 2);
  fs.rmSync(dir, { recursive: true, force: true });
});

test('unknown option exits 2', () => {
  const r = run(['--bogus']);
  assert.strictEqual(r.code, 2);
});

test('conversion footer never appears in piped/non-TTY output', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'redosray-cli-'));
  fs.writeFileSync(path.join(dir, 'a.js'), 'const re = /^(a+)+$/;\n');
  const full = execFileSync('node', [BIN, dir], {
    encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  assert.ok(!/star helps|playground/i.test(full), 'footer must not pollute piped stdout');
  const j = run([dir, '--json']);
  assert.ok(!/star helps/i.test(j.stdout), 'footer must not appear in --json');
  fs.rmSync(dir, { recursive: true, force: true });
});
