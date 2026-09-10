'use strict';
// PROTOTYPE static analysis: find the classic catastrophic-backtracking shapes
// and derive a concrete attack (pump char + failing suffix). This is the
// "candidate finder"; confirm.js then PROVES each candidate dynamically, so a
// missed edge case here is a false-negative, never a false-positive claim.

// A matching char for common inner atoms, and a char guaranteed NOT to match it
// (used as the failing suffix that forces exhaustive backtracking).
function atomChars(atom) {
  if (atom === '\\d') return { match: '1', fail: '!' };
  if (atom === '\\w') return { match: 'a', fail: '!' };
  if (atom === '\\s') return { match: ' ', fail: 'x' };
  if (atom === '.') return { match: 'a', fail: '\n' };
  const cls = atom.match(/^\[\^?([^\]]+)\]$/);
  if (cls) {
    const body = cls[1];
    const first = body.replace(/(\\.|.)-(\\.|.)/g, (_, a) => a)[0] || 'a';
    return { match: first, fail: first === '!' ? '~' : '!' };
  }
  if (/^[A-Za-z0-9]$/.test(atom)) return { match: atom, fail: atom === '!' ? '~' : '!' };
  return null;
}

const ATOM = String.raw`(?:\\[dwsDWS]|\.|\[\^?[^\]]+\]|[A-Za-z0-9])`;

// Nested quantifier: an atom with a quantifier, wrapped in a group that is
// itself quantified — e.g. (a+)+, (\d*)+, ([a-z]+)*, (?:a+)+
const NESTED = new RegExp(String.raw`\((?:\?:)?(${ATOM})[+*]\)[+*]`);

/**
 * Return an attack candidate for a regex source, or null if no classic
 * vulnerable shape is recognised. The returned attack drives confirm().
 */
function deriveAttack(source) {
  const m = source.match(NESTED);
  if (m) {
    const chars = atomChars(m[1]);
    if (chars) {
      return {
        kind: 'nested-quantifier',
        matchedShape: m[0],
        prefix: '',
        pump: chars.match,
        suffix: chars.fail,
      };
    }
  }
  return null;
}

module.exports = { deriveAttack, atomChars, NESTED };
