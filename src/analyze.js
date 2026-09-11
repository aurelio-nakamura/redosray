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

// Find, inside `node`, ALL descendant unbounded repeats over an atom-ish body.
// (We can't know statically which inner loop drives the blow-up — e.g. in
// `(([_]+)?([a-z0-9]+))*` the exploitable overlap is on `[a-z0-9]+`, not the
// first-encountered `[_]+` — so we return every candidate and let dynamic
// confirmation pick the real one. Extra candidates only cost a probe run.)
function findInnerRepeats(node) {
  const found = [];
  walk(node, (n) => {
    if (isUnbounded(n)) {
      const b = unwrap(n.body);
      if (['char', 'class', 'any', 'esc'].includes(b.type)) found.push({ rep: n, atom: b });
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

// A minimal concrete string that `node` can match (a "witness"). Used to build
// the prefix that lets the engine actually REACH a vulnerable loop buried in
// the middle of a pattern (e.g. the `<` and `[a-z]+` before `([^>]*)*`).
function witness(node) {
  switch (node.type) {
    case 'char': return node.value;
    case 'any': return 'a';
    case 'esc': {
      const k = node.kind;
      if (k === 'd') return '0';
      if (k === 'D') return 'a';
      if (k === 'w') return 'a';
      if (k === 'W') return '!';
      if (k === 's') return ' ';
      if (k === 'S') return 'a';
      if (k === 'b' || k === 'B') return '';
      return '';
    }
    case 'class': return sampleChar(node) || 'a';
    case 'anchor': case 'look': return '';
    case 'backref': return '';
    case 'group': return witness(node.body);
    case 'alt': {
      for (const o of node.options) { const w = witness(o); if (w !== '') return w; }
      return witness(node.options[0]);
    }
    case 'seq': return node.items.map(witness).join('');
    case 'repeat': {
      const body = witness(node.body);
      return body.repeat(Math.max(0, node.min));
    }
    default: return '';
  }
}

// Build a concrete string matching everything strictly BEFORE `target` in the
// pattern, so the engine reaches the vulnerable loop. Returns { found, prefix }.
function reachingPrefix(node, target) {
  if (node === target) return { found: true, prefix: '' };
  switch (node.type) {
    case 'seq': {
      let acc = '';
      for (const it of node.items) {
        const r = reachingPrefix(it, target);
        if (r.found) return { found: true, prefix: acc + r.prefix };
        acc += witness(it);
      }
      return { found: false, prefix: acc };
    }
    case 'group': {
      const r = reachingPrefix(node.body, target);
      return r.found ? { found: true, prefix: r.prefix } : { found: false, prefix: witness(node) };
    }
    case 'repeat': {
      const r = reachingPrefix(node.body, target);
      // entering the loop body once is enough to reach a target inside it
      return r.found ? { found: true, prefix: r.prefix } : { found: false, prefix: witness(node) };
    }
    case 'alt': {
      for (const o of node.options) {
        const r = reachingPrefix(o, target);
        if (r.found) return { found: true, prefix: r.prefix };
      }
      return { found: false, prefix: witness(node) };
    }
    default:
      return { found: false, prefix: witness(node) };
  }
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

  // Suffixes to try after the pumped run. We over-generate: the true failing
  // suffix might be a char the loop can't eat (forces `$`/next-token to fail),
  // OR simply END-OF-STRING (empty) when a required trailing literal follows
  // the loop (e.g. the final `>` in `<([a-z]+)([^>]*)*>`). Dynamic confirmation
  // picks whichever actually hangs, so extra options only cost a probe run.
  const suffixSet = (atom) => {
    const s = new Set();
    s.add(failChar(atom));
    s.add('');
    s.add('\uffff');
    return [...s];
  };

  walk(ast, (node) => {
    // ---- Family A: nested quantifier  (X+)+ , (X*)* , ((\d+))+ ...
    if (isUnbounded(node)) {
      const pfx = reachingPrefix(ast, node).prefix;
      for (const inner of findInnerRepeats(node.body)) {
        const pump = sampleChar(inner.atom);
        // Require the outer body to also start with pump, so consecutive outer
        // iterations overlap (this is what makes it ambiguous / exponential).
        if (pump && canStart(node.body, pump)) {
          for (const suffix of suffixSet(inner.atom)) {
            push(makeAttack('nested-quantifier', shapeOf(node), pump, suffix, pfx));
          }
        }
      }

      // ---- Family B: ambiguous alternation under a quantifier  (a|a)+ (a|ab)+
      const opts = altOptions(node.body);
      if (opts && opts.length >= 2) {
        for (let x = 0; x < opts.length; x++) {
          for (let y = x + 1; y < opts.length; y++) {
            const pump = overlapChar(opts[x], opts[y]);
            if (pump) {
              for (const suffix of suffixSet(node.body)) {
                push(makeAttack('ambiguous-alternation', shapeOf(node), pump, suffix, pfx));
              }
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
            const pfx = reachingPrefix(ast, node.items[reps[a].idx]).prefix;
            const shape = shapeOf({ type: 'seq', items: node.items.slice(reps[a].idx, reps[b].idx + 1) });
            for (const suffix of suffixSet(reps[a].rep.body)) {
              push(makeAttack('sequential-quantifier', shape, pump, suffix, pfx));
            }
          }
        }
      }
    }
  });

  return out;
}

module.exports = { findCandidates, parse, shapeOf };
