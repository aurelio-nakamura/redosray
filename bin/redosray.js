#!/usr/bin/env node
'use strict';
require('../src/cli').main(process.argv.slice(2))
  .then((code) => process.exit(code || 0))
  .catch((e) => { process.stderr.write(`redosray: ${(e && e.stack) || e}\n`); process.exit(1); });
