'use strict';
// Small character-set reasoning over AST atoms. Used to (a) pick a concrete
// "pump" character an ambiguous sub-expression matches, and (b) pick a "fail"
// character that forces the engine to backtrack. These only need to be good
// enough to build an attack candidate — the dynamic confirmation step is the
// source of truth, so an imperfect guess yields a false-negative, never a
// false-positive.

const ASCII = [];
for (let c = 0x20; c < 0x7f; c++) ASCII.push(String.fromCharCode(c));
const PROBE = ['a', 'A', '1', '0', '_', ' ', '!', '@', '-', '\t'].concat(ASCII);

function classMatches(set, negated, ch) {
  try {
    const re = new RegExp('^[' + (negated ? '^' : '') + set + ']$');
    return re.test(ch);
  } catch {
    return false;
  }
}

// Can `node` begin a match with character `ch`?
function canStart(node, ch) {
  switch (node.type) {
    case 'char': return node.value === ch;
    case 'any': return ch !== '\n';
    case 'esc': {
      const k = node.kind;
      if (k === 'd') return /[0-9]/.test(ch);
      if (k === 'D') return !/[0-9]/.test(ch);
      if (k === 'w') return /[A-Za-z0-9_]/.test(ch);
      if (k === 'W') return !/[A-Za-z0-9_]/.test(ch);
      if (k === 's') return /\s/.test(ch);
      if (k === 'S') return !/\s/.test(ch);
      return false;
    }
    case 'class': return classMatches(node.set, node.negated, ch);
    case 'group': return canStart(node.body, ch);
    case 'look': return false; // zero-width; handled by nullability elsewhere
    case 'repeat': return canStart(node.body, ch);
    case 'alt': return node.options.some((o) => canStart(o, ch));
    case 'anchor': return false;
    case 'backref': return false;
    case 'seq': {
      for (const it of node.items) {
        if (isNullable(it)) { if (canStart(it, ch)) return true; continue; }
        return canStart(it, ch);
      }
      return false;
    }
    default: return false;
  }
}

function isNullable(node) {
  switch (node.type) {
    case 'repeat': return node.min === 0 || isNullable(node.body);
    case 'anchor': case 'look': return true;
    case 'group': return isNullable(node.body);
    case 'alt': return node.options.some(isNullable);
    case 'seq': return node.items.every(isNullable);
    default: return false;
  }
}

// A representative character the (atom-ish) node matches, or null.
function sampleChar(node) {
  for (const ch of PROBE) if (canStart(node, ch)) return ch;
  return null;
}

// A character both nodes can start with (their overlap), or null.
function overlapChar(a, b) {
  for (const ch of PROBE) if (canStart(a, ch) && canStart(b, ch)) return ch;
  return null;
}

// A character that the node does NOT match — used as the failing suffix that
// forces exhaustive backtracking. Prefer visible, benign chars.
function failChar(node) {
  const prefer = ['!', 'x', 'Z', '0', ' ', '\uffff', '\n', '\x00'];
  for (const ch of prefer) if (!canStart(node, ch)) return ch;
  for (const ch of PROBE) if (!canStart(node, ch)) return ch;
  return '\x00';
}

module.exports = { canStart, isNullable, sampleChar, overlapChar, failChar };
