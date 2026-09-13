'use strict';
// Local smoke test that does NOT require `eslint` to be installed.
//
// It drives the rule's node visitors with hand-built ESTree nodes and a fake
// context, so we get real local signal on the core logic (source/flags
// extraction, the static gate, the out-of-process dynamic confirmation, the
// report messages, and the no-false-positive guarantee) even in an environment
// with no eslint/parser. The full ESLint RuleTester coverage lives in
// rule.test.js and runs against a real eslint on CI.

const { test } = require('node:test');
const assert = require('node:assert');
const rule = require('../lib/rules/no-vulnerable-regex');

function regexLiteral(pattern, flags = '') {
  return { type: 'Literal', regex: { pattern, flags }, value: null, raw: `/${pattern}/${flags}` };
}
function newRegExp(pattern, flags) {
  const args = [{ type: 'Literal', value: pattern }];
  if (flags != null) args.push({ type: 'Literal', value: flags });
  return { type: 'NewExpression', callee: { type: 'Identifier', name: 'RegExp' }, arguments: args };
}

// Minimal fake ESLint context. Collects report() calls.
function runRule(node, options = []) {
  const reports = [];
  const context = {
    options,
    report: (descriptor) => reports.push(descriptor),
  };
  const visitors = rule.create(context);
  const visit = visitors[node.type];
  if (visit) visit(node);
  return reports;
}

test('reports a proven exponential ReDoS (nested quantifier) with a fix', () => {
  const reports = runRule(regexLiteral('^(a+)+$'));
  assert.strictEqual(reports.length, 1);
  assert.strictEqual(reports[0].messageId, 'vulnerable');
  assert.strictEqual(reports[0].data.complexity, 'exponential');
  assert.ok(Number(reports[0].data.length) > 0, 'has a proof length');
  assert.match(reports[0].data.fix, /Safe rewrite: \/\^a\+\$\//);
});

test('does NOT report a safe regex (zero candidates → no subprocess)', () => {
  const reports = runRule(regexLiteral('^\\w+$'));
  assert.strictEqual(reports.length, 0);
});

test('NO FALSE POSITIVE: scary-but-safe regex is dynamically cleared', () => {
  // (a|a)+ without an anchor has candidates statically, but does not actually
  // catastrophically backtrack — dynamic confirmation must clear it.
  const reports = runRule(regexLiteral('(a|a)+'));
  assert.strictEqual(reports.length, 0);
});

test('detects vulnerable pattern in new RegExp("...")', () => {
  const reports = runRule(newRegExp('^(a+)+$', ''));
  assert.strictEqual(reports.length, 1);
  assert.strictEqual(reports[0].messageId, 'vulnerable');
});

test('ignores RegExp built from a non-literal (no false alarm)', () => {
  const node = {
    type: 'NewExpression',
    callee: { type: 'Identifier', name: 'RegExp' },
    arguments: [{ type: 'Identifier', name: 'userInput' }],
  };
  assert.strictEqual(runRule(node).length, 0);
});

test('static mode reports the candidate without confirming', () => {
  const reports = runRule(regexLiteral('(a|a)+'), [{ mode: 'static' }]);
  assert.strictEqual(reports.length, 1);
  assert.strictEqual(reports[0].messageId, 'candidate');
});

test('ignores unparseable / non-regex literals gracefully', () => {
  assert.strictEqual(runRule({ type: 'Literal', value: 'hello' }).length, 0);
});
