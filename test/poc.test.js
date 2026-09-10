'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { deriveAttack } = require('../src/attack');
const { confirm } = require('../src/confirm');

async function check(source, flags = '') {
  const attack = deriveAttack(source);
  if (!attack) return { found: false };
  const res = await confirm(source, flags, attack, { timeoutMs: 800, maxPumps: 200 });
  return { found: true, attack, res };
}

test('confirms classic nested-quantifier ReDoS (a+)+$', async () => {
  const out = await check('^(a+)+$');
  assert.ok(out.found, 'should derive an attack');
  assert.ok(out.res.vulnerable, 'should dynamically confirm the hang');
  assert.ok(out.res.proof.input.length < 200, 'proof input should be short');
});

test('confirms ([a-z]+)* ReDoS with class atom', async () => {
  const out = await check('^([a-z]+)*$');
  assert.ok(out.found && out.res.vulnerable);
});

test('does NOT flag a safe linear regex ^a+$', async () => {
  const attack = deriveAttack('^a+$');
  assert.strictEqual(attack, null, 'safe regex should not match a vulnerable shape');
});

test('safe regex that looks nested but is bounded stays fast', async () => {
  // (a+)+ shape absent; simple alternation is linear in V8.
  const attack = deriveAttack('^(abc|def)$');
  assert.strictEqual(attack, null);
});
