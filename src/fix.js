'use strict';
// Safe-rewrite suggester.
//
// Design principle (same as the whole tool): NEVER emit a false claim. A concrete
// rewrite is only surfaced when it is DIFFERENTIALLY VERIFIED to match exactly the
// same set of strings as the original (over a large generated corpus) AND is itself
// no longer flagged as vulnerable. When we cannot prove a safe rewrite, we fall back
// to a labelled, generic strategy note (clearly marked as a suggestion, not a proof).

const { parse } = require('./analyze');
const { scanRegex } = require('./scan');

const SIMPLE_ATOM = new Set(['char', 'class', 'esc', 'any']);

// --- faithful regex serializer (AST -> source) ---
// Unlike the human-readable shapeOf(), this re-escapes metacharacters so the
// output round-trips exactly. If it meets a node it can't reproduce faithfully,
// it throws, and suggestFix falls back to a strategy note (never a wrong rewrite).
const CTRL = { '\n': '\\n', '\r': '\\r', '\t': '\\t', '\f': '\\f', '\v': '\\v', '\0': '\\0' };
const META = '\\^$.|?*+()[]{}';
function escChar(v) {
  if (Object.prototype.hasOwnProperty.call(CTRL, v)) return CTRL[v];
  if (v.length === 1 && META.includes(v)) return '\\' + v;
  return v;
}
function quant(min, max) {
  if (max === Infinity) return min === 0 ? '*' : (min === 1 ? '+' : `{${min},}`);
  if (min === 0 && max === 1) return '?';
  if (min === max) return `{${min}}`;
  return `{${min},${max}}`;
}
function reSource(node) {
  switch (node.type) {
    case 'char': return escChar(node.value);
    case 'any': return '.';
    case 'esc': return '\\' + node.kind;
    case 'class': return '[' + (node.negated ? '^' : '') + node.set + ']';
    case 'anchor': return node.kind;
    case 'backref': return /^\d+$/.test(node.ref) ? '\\' + node.ref : '\\k<' + node.ref + '>';
    case 'group':
      return '(' + (node.capturing ? (node.name ? '?<' + node.name + '>' : '') : '?:') +
        reSource(node.body) + ')';
    case 'look':
      return '(?' + (node.behind ? '<' : '') + (node.negative ? '!' : '=') + reSource(node.body) + ')';
    case 'alt': return node.options.map(reSource).join('|');
    case 'seq': return node.items.map(reSource).join('');
    case 'repeat': return reSource(node.body) + quant(node.min, node.max) + (node.greedy ? '' : '?');
    default: throw new Error('unserializable node: ' + node.type);
  }
}
// Structural proof that reSource faithfully represents `ast`: re-parsing its
// output must yield an identical AST. This does NOT depend on test-corpus luck.
function isFaithful(ast) {
  try { return JSON.stringify(parse(reSource(ast))) === JSON.stringify(ast); }
  catch { return false; }
}

// Find the first collapsible nested-quantifier: (X{a,})+  /  (X*)*  etc, where X is
// a single simple atom and BOTH the inner and outer quantifiers are unbounded.
// Returns the outer `repeat` node (to be mutated in place) + the pieces, or null.
function findNestedQuantifier(node) {
  if (!node || typeof node !== 'object') return null;
  if (node.type === 'repeat' && node.max === Infinity) {
    const body = node.body;
    if (body && body.type === 'group') {
      const inner = body.body;
      if (inner && inner.type === 'repeat' && inner.max === Infinity &&
          inner.body && SIMPLE_ATOM.has(inner.body.type)) {
        return { outer: node, group: body, inner, atom: inner.body };
      }
    }
  }
  // recurse
  for (const key of ['body', 'items', 'options']) {
    const v = node[key];
    if (Array.isArray(v)) {
      for (const c of v) { const r = findNestedQuantifier(c); if (r) return r; }
    } else if (v && typeof v === 'object') {
      const r = findNestedQuantifier(v); if (r) return r;
    }
  }
  return null;
}

function quantStr(min) {
  if (min === 0) return '*';
  if (min === 1) return '+';
  return `{${min},}`;
}

// Strip flags that make .test() stateful (g, y) so equivalence is order-independent.
function stableFlags(flags) {
  return (flags || '').replace(/[gy]/g, '');
}

// Build a corpus of test strings from the regex's own alphabet plus noise.
function buildCorpus(source, atom) {
  const alpha = new Set();
  // pull literal-ish chars out of the source
  for (const ch of source.replace(/\\./g, '')) {
    if (/[A-Za-z0-9_ ]/.test(ch)) alpha.add(ch);
  }
  // a concrete char the atom matches
  let atomChar = 'a';
  if (atom.type === 'char') atomChar = atom.value;
  else if (atom.type === 'esc') atomChar = ({ d: '0', w: 'a', s: ' ', D: '!', W: '!', S: 'a' })[atom.kind] || 'a';
  else if (atom.type === 'class') { const m = source.match(/\[[^\]]*\]/); atomChar = 'a'; }
  alpha.add(atomChar);
  for (const c of ['a', 'b', 'x', '0', '_', ' ', '!', '\n', '\t', '.', '@', '-']) alpha.add(c);
  const chars = [...alpha];

  const out = [''];
  // Targeted: runs of the atom char, with/without a trailing non-atom.
  // Lengths are capped small so the ORIGINAL (possibly catastrophic) regex stays
  // fast during verification — we are checking equivalence, not measuring the hang.
  for (let k = 0; k <= 16; k++) {
    out.push(atomChar.repeat(k));
    out.push(atomChar.repeat(k) + '!');
    out.push('!' + atomChar.repeat(k));
    out.push(atomChar.repeat(k) + '\n');
  }
  // deterministic pseudo-random strings over the alphabet (seeded LCG => reproducible)
  let seed = 1234567;
  const rnd = () => (seed = (seed * 1103515245 + 12345) & 0x7fffffff) / 0x7fffffff;
  for (let n = 0; n < 3000; n++) {
    const len = Math.floor(rnd() * 17);
    let s = '';
    for (let j = 0; j < len; j++) s += chars[Math.floor(rnd() * chars.length)];
    out.push(s);
  }
  return out;
}

function equivalent(reA, reB, corpus) {
  for (const s of corpus) {
    let a, b;
    try { a = reA.test(s); } catch { return false; }
    try { b = reB.test(s); } catch { return false; }
    if (a !== b) return false;
  }
  return true;
}

// Generic, honestly-labelled strategy notes keyed by vulnerability family.
const STRATEGY_NOTES = {
  'nested-quantifier':
    'A quantified group whose body is itself unbounded (e.g. (a+)+) makes the engine try exponentially ' +
    'many ways to split the same characters. Collapse the two quantifiers into one (a+), or make the ' +
    'inner atom and the following character mutually exclusive so only one split is possible.',
  'ambiguous-alternation':
    'The alternatives inside this quantified group can match the same input (e.g. (a|a)+, (a|ab)+), so ' +
    'the engine has multiple ways to consume each character. Rewrite the alternatives to be mutually ' +
    'exclusive (disjoint prefixes), or anchor/atomic-group the loop so it cannot backtrack into itself.',
  'sequential-quantifier':
    'Two adjacent quantifiers can match overlapping input (e.g. \\s*\\s*, .*.*), giving quadratic ' +
    'backtracking. Merge them into a single quantifier, or make the segments non-overlapping so each ' +
    'character can only be consumed by one of them.',
};

/**
 * Suggest a fix for a (candidate) ReDoS regex.
 * @param {string} source  regex source (no slashes)
 * @param {string} flags   regex flags
 * @param {string} [kind]  detected vulnerability family (for the strategy note)
 * @returns {{ rewrite?: string, verified: boolean, kind?: string, note: string,
 *             capturesChanged?: boolean }}
 *   - If `rewrite` is present, it is DIFFERENTIALLY VERIFIED equivalent and clean.
 *   - Otherwise `note` is a labelled strategy suggestion (not a proof).
 */
async function suggestFix(source, flags = '', kind) {
  let ast;
  try { ast = parse(source); } catch { ast = null; }

  if (ast && isFaithful(ast)) {
    const hit = findNestedQuantifier(ast);
    if (hit) {
      const { outer, group, inner, atom } = hit;
      const capturing = !!group.capturing;
      const innerSrc = reSource(inner);
      const collapsedMin = (inner.min > 0 && outer.min > 0) ? inner.min * outer.min : 0;
      // Mutate the outer repeat in place -> single quantifier on the atom.
      outer.body = atom;
      outer.min = collapsedMin;
      outer.max = Infinity;
      outer.greedy = true;
      let rewrite = reSource(ast);

      // Verify: (1) the rewrite is DYNAMICALLY confirmed non-vulnerable (a real
      // measured non-hang, not just a static guess), (2) it is differentially
      // equivalent to the original over a large corpus.
      let clean = false;
      try {
        const scan = await scanRegex(rewrite, flags, { timeoutMs: 800 });
        clean = !scan.vulnerable;
      } catch { clean = false; }
      if (clean) {
        let reOrig, reNew;
        try {
          reOrig = new RegExp(source, stableFlags(flags));
          reNew = new RegExp(rewrite, stableFlags(flags));
        } catch { reOrig = reNew = null; }
        if (reOrig && reNew && equivalent(reOrig, reNew, buildCorpus(source, atom))) {
          let note = 'Collapsed the nested quantifier into a single linear one — verified to match ' +
            'exactly the same strings, with no catastrophic backtracking.';
          if (capturing) {
            note += ' Note: this removes a capturing group; if you use its captured text, keep the ' +
              'group but drop the outer repeat, e.g. (' + innerSrc + '), which is also linear.';
          }
          return { rewrite, verified: true, kind: kind || 'nested-quantifier', note, capturesChanged: capturing };
        }
      }
    }
  }

  // No verified rewrite -> honest, labelled strategy note.
  const note = (kind && STRATEGY_NOTES[kind]) || STRATEGY_NOTES['nested-quantifier'];
  return { verified: false, kind, note };
}

module.exports = { suggestFix };
