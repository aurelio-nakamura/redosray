'use strict';
// Full ESLint RuleTester coverage. Requires `eslint` to be installed, so it is
// skipped where eslint is unavailable (e.g. the offline dev box) and runs for
// real on CI, which installs eslint and validates the rule end-to-end against a
// real parser and the actual ESLint rule contract.

const { test } = require('node:test');
const assert = require('node:assert');

let RuleTester;
try {
  ({ RuleTester } = require('eslint'));
} catch (_) {
  RuleTester = null;
}

test('ESLint RuleTester: no-vulnerable-regex', { skip: !RuleTester && 'eslint not installed' }, () => {
  const rule = require('../lib/rules/no-vulnerable-regex');
  const ruleTester = new RuleTester({
    languageOptions: { ecmaVersion: 2022, sourceType: 'module' },
  });

  ruleTester.run('no-vulnerable-regex', rule, {
    valid: [
      // Plainly safe regexes: zero candidates, never reported.
      { code: 'const re = /^\\w+$/;' },
      { code: 'const re = /^[a-z0-9]+@[a-z0-9]+\\.[a-z]{2,}$/i;' },
      // Scary-but-safe: static candidates exist, but it does NOT actually
      // catastrophically backtrack, so dynamic confirmation must clear it.
      { code: 'const re = /(a|a)+/;' },
      // RegExp built from a non-literal is out of scope (no false alarm).
      { code: 'const re = new RegExp(userInput);' },
      { code: 'const re = new RegExp(pattern, "i");' },
    ],
    invalid: [
      {
        code: 'const re = /^(a+)+$/;',
        errors: [{ messageId: 'vulnerable' }],
      },
      {
        code: 'const re = /^([a-z]+)*$/;',
        errors: [{ messageId: 'vulnerable' }],
      },
      {
        code: 'const re = new RegExp("^(a+)+$");',
        errors: [{ messageId: 'vulnerable' }],
      },
      {
        // static mode reports the candidate without spawning confirmation.
        code: 'const re = /(a|a)+/;',
        options: [{ mode: 'static' }],
        errors: [{ messageId: 'candidate' }],
      },
    ],
  });

  assert.ok(true, 'RuleTester passed');
});
