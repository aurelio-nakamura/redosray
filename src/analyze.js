'use strict';
// AST-based candidate finder for catastrophic / super-linear backtracking.
//
// Philosophy: STATIC finds *candidates*; DYNAMIC confirmation (confirm.js)
// decides. So this file is deliberately liberal — it flags shapes that *might*
// blow up and derives a concrete attack string for each. Because every reported
// vulnerability is later proven by a measured hang, over-flagging here only
// costs a few extra confirmation runs; it never produces a false claim.

const { parse } = require('./parser');
const { canStart, isNullable, sampleChar, overlapChar, failChar } = require('./charset');

// Unwrap transparent wrappers (single-item seq, non-capturing/capturing groups)
// to reach the "meat" of a sub-expression.
function unwrap(node) {
  let cur = node;
  for (;;) {
    if (cur.type === 'group') { cur = cur.body; continue; }
    if (cur.type === 'seq' && cur.items.length === 1) { cur = cur.items[0]; continue; }
    return cur;
  }
}

function isUnbounded(node) {
  return node.type === 'repeat' && node.max === Infinity;
}

// Collect every descendant repeat node (with a path for context).
function walk(node, visit) {
  visit(node);
  switch (node.type) {
    case 'alt': node.options.forEach((o) => walk(o, visit)); break;
    case 'seq': node.items.forEach((it) => walk(it, visit)); break;
    case 'repeat': walk(node.body, visit); break;
    case 'group': case 'look': walk(node.body, visit); break;
    default: break;
  }
}

// Find, inside `node`, a descendant unbounded repeat over an atom-ish body.
function findInnerRepeat(node) {
  let found = null;
  walk(node, (n) => {
    if (found) return;
    if (isUnbounded(n)) {
      const b = unwrap(n.body);
      if (['char', 'class', 'any', 'esc'].includes(b.type)) found = { rep: n, atom: b };
    }
  });
  return found;
}

// Gather the alternation options at the top of a (possibly wrapped) node.
function altOptions(node) {
  const u = unwrap(node);
  if (u.type === 'alt') return u.options;
  return null;
}

function makeAttack(kind, matchedShape, pump, suffix, prefix = '') {
  return { kind, matchedShape, prefix, pump, suffix };
}

// Produce a stable-ish shape string for dedup/reporting.
function shapeOf(node) {
  switch (node.type) {
    case 'char': return node.value;
    case 'any': return '.';
    case 'esc': return '\\' + node.kind;
    case 'class': return '[' + (node.negated ? '^' : '') + node.set + ']';
    case 'anchor': return node.kind;
    case 'backref': return '\\' + node.ref;
    case 'group': return '(' + (node.capturing ? '' : '?:') + shapeOf(node.body) + ')';
    case 'look': return '(?' + (node.behind ? '<' : '') + (node.negative ? '!' : '=') + shapeOf(node.body) + ')';
    case 'alt': return node.options.map(shapeOf).join('|');
    case 'seq': return node.items.map(shapeOf).join('');
    case 'repeat': {
      const q = node.max === Infinity ? (node.min === 0 ? '*' : (node.min === 1 ? '+' : `{${node.min},}`))
        : (node.min === 0 && node.max === 1 ? '?' : `{${node.min},${node.max}}`);
      return shapeOf(node.body) + q + (node.greedy ? '' : '?');
    }
    default: return '?';
  }
}

/**
 * Return a de-duplicated list of attack candidates for a parsed regex source.
 * Each candidate: { kind, matchedShape, prefix, pump, suffix }.
 */
function findCandidates(source) {
  let ast;
  try { ast = parse(source); } catch { return []; }
  const out = [];
  const seen = new Set();
  const push = (c) => {
    if (!c || !c.pump) return;
    const key = c.kind + '|' + c.matchedShape + '|' + c.pump + '|' + c.suffix;
    if (seen.has(key)) return;
    seen.add(key);
    out.push(c);
  };

  walk(ast, (node) => {
    // ---- Family A: nested quantifier  (X+)+ , (X*)* , ((\d+))+ ...
    if (isUnbounded(node)) {
      const inner = findInnerRepeat(node.body);
      if (inner) {
        const pump = sampleChar(inner.atom);
        // Require the outer body to also start with pump, so consecutive outer
        // iterations overlap (this is what makes it ambiguous / exponential).
        if (pump && canStart(node.body, pump)) {
          const suffix = failChar(inner.atom);
          push(makeAttack('nested-quantifier', shapeOf(node), pump, suffix));
        }
      }

      // ---- Family B: ambiguous alternation under a quantifier  (a|a)+ (a|ab)+
      const opts = altOptions(node.body);
      if (opts && opts.length >= 2) {
        for (let x = 0; x < opts.length; x++) {
          for (let y = x + 1; y < opts.length; y++) {
            const pump = overlapChar(opts[x], opts[y]);
            if (pump) {
              const suffix = failChar(node.body);
              push(makeAttack('ambiguous-alternation', shapeOf(node), pump, suffix));
            }
          }
        }
      }
    }

    // ---- Family C: adjacent unbounded quantifiers with overlapping first sets
    //      \d+\d+ , a+a* , .*.*  -> polynomial (usually quadratic) backtracking.
    if (node.type === 'seq') {
      const reps = [];
      for (let k = 0; k < node.items.length; k++) {
        const it = node.items[k];
        if (isUnbounded(it)) reps.push({ idx: k, rep: it });
      }
      for (let a = 0; a < reps.length; a++) {
        for (let b = a + 1; b < reps.length; b++) {
          // only pair them if everything strictly between is nullable (so both
          // quantifiers actually compete over the same run of characters)
          let between = true;
          for (let m = reps[a].idx + 1; m < reps[b].idx; m++) {
            if (!isNullable(node.items[m])) { between = false; break; }
          }
          if (!between) continue;
          const pump = overlapChar(reps[a].rep.body, reps[b].rep.body);
          if (pump) {
            const suffix = failChar(reps[a].rep.body);
            const shape = shapeOf({ type: 'seq', items: node.items.slice(reps[a].idx, reps[b].idx + 1) });
            push(makeAttack('sequential-quantifier', shape, pump, suffix));
          }
        }
      }
    }
  });

  return out;
}

module.exports = { findCandidates, parse, shapeOf };
