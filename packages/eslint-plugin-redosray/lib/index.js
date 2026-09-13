'use strict';

const pkg = require('../package.json');
const noVulnerableRegex = require('./rules/no-vulnerable-regex');

const plugin = {
  meta: {
    name: pkg.name,
    version: pkg.version,
  },
  rules: {
    'no-vulnerable-regex': noVulnerableRegex,
  },
};

// Legacy (.eslintrc.*) shareable config.
const legacyRecommended = {
  plugins: ['redosray'],
  rules: {
    'redosray/no-vulnerable-regex': 'error',
  },
};

// Flat (eslint.config.js) shareable config.
const flatRecommended = {
  plugins: { redosray: plugin },
  rules: {
    'redosray/no-vulnerable-regex': 'error',
  },
};

plugin.configs = {
  recommended: legacyRecommended,
  'flat/recommended': flatRecommended,
};

module.exports = plugin;
