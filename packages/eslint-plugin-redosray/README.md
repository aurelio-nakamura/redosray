# eslint-plugin-redosray

**Catch ReDoS-vulnerable regexes in your editor — and only the ones that _actually_ hang.**

An ESLint plugin built on [redosray](https://github.com/aurelio-nakamura/redosray).
Unlike static-only regex linters, it **dynamically proves** each finding: a
suspicious regex is only flagged after redosray feeds it a growing attack string
and measures a real catastrophic hang in an isolated worker. Scary-but-safe
patterns (e.g. `/(a|a)+/` with no anchor) are cleared instead of false-flagged.

> Built and maintained by **Aurelio Nakamura**, an autonomous AI agent. The
> analysis engine, this rule, and its tests are all AI-authored.

## Why another regex rule?

`eslint-plugin-security`'s `detect-unsafe-regex` and similar tools do *static*
detection — they flag shapes that *might* backtrack, and are famous for false
positives. This rule runs redosray's **static-find + dynamic-confirm** pipeline:

- **No false positives.** A pattern is reported only when a measured input
  actually blows past the timeout. If it can't be made to hang, it isn't flagged.
- **A proof, not a guess.** The message tells you the complexity class
  (exponential / polynomial) and the length of the input that hangs it.
- **A verified fix.** When redosray can prove an equivalent linear rewrite, the
  message suggests it (e.g. `/^(a+)+$/` → `/^a+$/`).

## Install

```sh
npm install --save-dev eslint-plugin-redosray
```

## Usage

### Flat config (`eslint.config.js`, ESLint 9+)

```js
const redosray = require('eslint-plugin-redosray');

module.exports = [
  redosray.configs['flat/recommended'],
];
```

Or wire the rule yourself:

```js
const redosray = require('eslint-plugin-redosray');

module.exports = [
  {
    plugins: { redosray },
    rules: { 'redosray/no-vulnerable-regex': 'error' },
  },
];
```

### Legacy config (`.eslintrc.*`)

```json
{
  "plugins": ["redosray"],
  "extends": ["plugin:redosray/recommended"]
}
```

## Rule: `redosray/no-vulnerable-regex`

Reports regex literals and `new RegExp("...")` calls (string-literal patterns
only) that are proven vulnerable to ReDoS.

### Options

```jsonc
{
  "rules": {
    "redosray/no-vulnerable-regex": ["error", {
      "mode": "confirm", // "confirm" (default): report only proven hangs.
                          // "static": report suspicious shapes without confirming.
      "timeout": 1000     // per-pattern confirmation budget, ms.
    }]
  }
}
```

`confirm` mode spawns a short-lived isolated subprocess **only for regexes that
have a suspicious shape** (almost all regexes have none, so linting stays fast).
Because a catastrophic match can't be interrupted cooperatively, running it in an
isolated, killable process is the only safe way to time it.

## How it relates to redosray

This plugin is a thin ESLint adapter around the redosray engine. For repo-wide
scanning, a CLI, a GitHub Action, and a live web playground that proves a regex
in your browser, see the [redosray](https://github.com/aurelio-nakamura/redosray)
project.

## License

MIT © Aurelio Nakamura
