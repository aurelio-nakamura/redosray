'use strict';

const path = require('node:path');
const { execFileSync } = require('node:child_process');

// Static candidate finder — synchronous and cheap. It liberally lists the
// suspicious shapes in a regex; almost all real-world regexes have zero
// candidates, so the expensive dynamic step below runs only rarely.
function loadFindCandidates() {
  try {
    return require('redosray').findCandidates;
  } catch (_) {
    return require(path.join(__dirname, '..', '..', '..', '..', 'src', 'index.js')).findCandidates;
  }
}
const findCandidates = loadFindCandidates();

const CONFIRM = path.join(__dirname, '..', '..', 'scripts', 'confirm.js');

// Pull a { source, flags } pair out of the supported node shapes, or null.
function regexOf(node) {
  // /.../ literal
  if (node.type === 'Literal' && node.regex) {
    return { source: node.regex.pattern, flags: node.regex.flags || '' };
  }
  // new RegExp('...') / RegExp('...')
  if (
    (node.type === 'NewExpression' || node.type === 'CallExpression') &&
    node.callee &&
    node.callee.type === 'Identifier' &&
    node.callee.name === 'RegExp' &&
    node.arguments.length >= 1
  ) {
    const a0 = node.arguments[0];
    // Only string-literal patterns are analyzable statically; a RegExp built
    // from a variable or another RegExp is out of scope (no false alarms).
    if (a0.type === 'Literal' && typeof a0.value === 'string') {
      let flags = '';
      const a1 = node.arguments[1];
      if (a1 && a1.type === 'Literal' && typeof a1.value === 'string') flags = a1.value;
      return { source: a0.value, flags };
    }
  }
  return null;
}

// Run redosray's dynamic confirmation out-of-process. Returns the parsed
// verdict, or { error: true } if the subprocess could not produce a verdict.
function confirm(source, flags, timeoutMs) {
  try {
    const out = execFileSync(
      process.execPath,
      [CONFIRM, source, flags, String(timeoutMs)],
      {
        encoding: 'utf8',
        timeout: timeoutMs * 8 + 3000,
        maxBuffer: 8 * 1024 * 1024,
        stdio: ['ignore', 'pipe', 'ignore'],
      }
    );
    return JSON.parse(out);
  } catch (_) {
    return { error: true };
  }
}

module.exports = {
  meta: {
    type: 'problem',
    docs: {
      description:
        'Disallow regular expressions vulnerable to ReDoS (catastrophic backtracking), proven by a measured hang',
      recommended: true,
      url: 'https://github.com/aurelio-nakamura/redosray/tree/main/packages/eslint-plugin-redosray',
    },
    schema: [
      {
        type: 'object',
        properties: {
          // 'confirm' (default): report only vulnerabilities proven by a real
          // measured hang — no false positives on scary-but-safe regexes.
          // 'static': report every suspicious candidate without confirming
          //   (faster, spawns no subprocess, but may over-report).
          mode: { enum: ['confirm', 'static'] },
          // Per-pattern confirmation budget in milliseconds.
          timeout: { type: 'integer', minimum: 50 },
        },
        additionalProperties: false,
      },
    ],
    messages: {
      vulnerable:
        'ReDoS: this regex catastrophically backtracks ({{complexity}}). Proven — a {{length}}-char input hangs it >{{timeout}}ms.{{fix}}',
      candidate:
        'ReDoS: this regex has a {{kind}} shape that can catastrophically backtrack. Verify with redosray.',
    },
  },

  create(context) {
    const opts = (context.options && context.options[0]) || {};
    const mode = opts.mode || 'confirm';
    const timeoutMs = opts.timeout || 1000;

    function check(node) {
      const rx = regexOf(node);
      if (!rx || !rx.source) return;

      let candidates;
      try {
        candidates = findCandidates(rx.source);
      } catch (_) {
        return; // unparseable regex → stay silent (never a false alarm)
      }
      if (!candidates || candidates.length === 0) return;

      if (mode === 'static') {
        context.report({
          node,
          messageId: 'candidate',
          data: { kind: candidates[0].kind },
        });
        return;
      }

      // mode === 'confirm' (default): prove it before reporting.
      const res = confirm(rx.source, rx.flags, timeoutMs);
      if (res && res.vulnerable) {
        let fix = '';
        if (res.fix && res.fix.verified && res.fix.rewrite) {
          fix = ` Safe rewrite: /${res.fix.rewrite}/${rx.flags}`;
        }
        context.report({
          node,
          messageId: 'vulnerable',
          data: {
            complexity: res.complexity || 'super-linear',
            length: res.proof ? res.proof.length : '?',
            timeout: res.proof ? res.proof.timeoutMs : timeoutMs,
            fix,
          },
        });
      } else if (res && res.error) {
        // Could not confirm (subprocess failed/timed out). Fall back to a
        // lower-confidence candidate warning rather than silently missing it.
        context.report({
          node,
          messageId: 'candidate',
          data: { kind: candidates[0].kind },
        });
      }
      // res.vulnerable === false → dynamically cleared → report nothing.
      // This is the whole point: no false positives on safe-but-scary regexes.
    }

    return {
      Literal: check,
      NewExpression: check,
      CallExpression: check,
    };
  },
};
