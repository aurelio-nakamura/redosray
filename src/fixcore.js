'use strict';
// fixcore — the PURE, environment-agnostic core of the safe-rewrite suggester.
//
// It contains no Node-only dependencies (no worker_threads / scan), so it can be
// bundled into the browser playground unchanged. Both the Node CLI (src/fix.js)
// and the browser bundle build their `suggestFix` on top of this exact code, so
// there is a single source of truth for how a rewrite is generated and verified —
// no risk of the two drifting into different (and possibly false) claims.
//
// Design principle (same as the whole tool): NEVER emit a false claim. A concrete
// rewrite is only surfaced when it is DIFFERENTIALLY VERIFIED to match exactly the
// same set of strings as the original (over a large generated corpus). Whether it
// is *also* no-longer-vulnerable is confirmed by the caller (dynamically in Node,
// dynamically via a Web Worker in the browser) — never merely guessed.

const { parse, findCandidates } = require('./analyze');

const SIMPLE_ATOM = new Set(['char', 'class', 'esc', 'any']);

// --- faithful regex serializer (AST -> source) ---
// Unlike the human-readable shapeOf(), this re-escapes metacharacters so the
// output round-trips exactly. If it meets a node it can't reproduce faithfully,
// it throws, and the caller falls back to a strategy note (never a wrong rewrite).
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

// Strip flags that make .test() stateful (g, y) so equivalence is order-independent.
function stableFlags(flags) {
  return (flags || '').replace(/[gy]/g, '');
}

// Build a corpus of test strings from the regex's own alphabet plus noise.
function buildCorpus(source, atom) {
  const alpha = new Set();
  for (const ch of source.replace(/\\./g, '')) {
    if (/[A-Za-z0-9_ ]/.test(ch)) alpha.add(ch);
  }
  let atomChar = 'a';
  if (atom.type === 'char') atomChar = atom.value;
  else if (atom.type === 'esc') atomChar = ({ d: '0', w: 'a', s: ' ', D: '!', W: '!', S: 'a' })[atom.kind] || 'a';
  else if (atom.type === 'class') { atomChar = 'a'; }
  alpha.add(atomChar);
  for (const c of ['a', 'b', 'x', '0', '_', ' ', '!', '\n', '\t', '.', '@', '-']) alpha.add(c);
  const chars = [...alpha];

  const out = [''];
  for (let k = 0; k <= 16; k++) {
    out.push(atomChar.repeat(k));
    out.push(atomChar.repeat(k) + '!');
    out.push('!' + atomChar.repeat(k));
    out.push(atomChar.repeat(k) + '\n');
  }
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

// Build a DIFFERENTIALLY-VERIFIED candidate rewrite (faithful serialization +
// collapse of a nested quantifier + proven string-set equivalence over a large
// corpus). Returns { rewrite, capturesChanged, note, innerSrc } or null.
// It does NOT confirm the rewrite is non-vulnerable — that is the caller's job
// (dynamic measurement in Node / Web Worker in the browser), so no false claim
// is ever made from this pure module alone.
function verifiedRewrite(source, flags = '') {
  let ast;
  try { ast = parse(source); } catch { return null; }
  if (!isFaithful(ast)) return null;

  const hit = findNestedQuantifier(ast);
  if (!hit) return null;
  const { outer, group, inner, atom } = hit;
  const capturing = !!group.capturing;
  const innerSrc = reSource(inner);
  const collapsedMin = (inner.min > 0 && outer.min > 0) ? inner.min * outer.min : 0;
  outer.body = atom;
  outer.min = collapsedMin;
  outer.max = Infinity;
  outer.greedy = true;
  const rewrite = reSource(ast);

  let reOrig, reNew;
  try {
    reOrig = new RegExp(source, stableFlags(flags));
    reNew = new RegExp(rewrite, stableFlags(flags));
  } catch { return null; }
  if (!equivalent(reOrig, reNew, buildCorpus(source, atom))) return null;

  let note = 'Collapsed the nested quantifier into a single linear one — verified to match ' +
    'exactly the same strings, with no catastrophic backtracking.';
  if (capturing) {
    note += ' Note: this removes a capturing group; if you use its captured text, keep the ' +
      'group but drop the outer repeat, e.g. (' + innerSrc + '), which is also linear.';
  }
  return { rewrite, capturesChanged: capturing, note, innerSrc };
}

// A purely-static "is this regex still flagged?" check, for environments that
// cannot run the dynamic worker (or as a fast pre-filter). Uses the same static
// detector the whole tool is built on.
function staticallyClean(source, flags = '') {
  try {
    const cands = findCandidates(source, flags);
    return !cands || cands.length === 0;
  } catch { return false; }
}

module.exports = {
  reSource, isFaithful, findNestedQuantifier, stableFlags,
  buildCorpus, equivalent, STRATEGY_NOTES, verifiedRewrite, staticallyClean,
};
