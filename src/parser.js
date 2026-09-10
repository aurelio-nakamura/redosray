'use strict';
// A small, dependency-free parser for JavaScript-flavoured regular expressions.
// It produces an AST that the analyzer walks to find catastrophic-backtracking
// shapes. It intentionally covers the constructs that matter for ReDoS
// (groups, alternation, quantifiers, char classes, anchors, lookaround) and
// degrades gracefully on anything exotic by throwing, so the caller can fall
// back to "unknown" rather than emit a wrong result.
//
// AST node shapes:
//   { type: 'alt',    options: Node[] }              a|b|c
//   { type: 'seq',    items: Node[] }                abc
//   { type: 'repeat', min, max, greedy, body: Node } a*  a+  a?  a{2,5}
//   { type: 'group',  capturing, name, body: Node }  (a) (?:a) (?<x>a)
//   { type: 'look',   negative, behind, body: Node } (?=a) (?!a) (?<=a) (?<!a)
//   { type: 'char',   value: string }                literal char
//   { type: 'class',  negated, set: string }         [a-z]  (set is raw body)
//   { type: 'any' }                                  .
//   { type: 'anchor', kind: string }                 ^ $ \b \B
//   { type: 'esc',    kind: string }                 \d \w \s \D \W \S
//   { type: 'backref',ref: string }                  \1  \k<name>

function parse(source) {
  let i = 0;
  const n = source.length;

  function peek() { return source[i]; }
  function eof() { return i >= n; }

  function parseAlternation() {
    const options = [parseSequence()];
    while (!eof() && peek() === '|') {
      i++; // consume |
      options.push(parseSequence());
    }
    return options.length === 1 ? options[0] : { type: 'alt', options };
  }

  function parseSequence() {
    const items = [];
    while (!eof() && peek() !== '|' && peek() !== ')') {
      items.push(parseQuantified());
    }
    if (items.length === 1) return items[0];
    return { type: 'seq', items };
  }

  function parseQuantified() {
    const atom = parseAtom();
    if (eof()) return atom;
    const c = peek();
    let min, max;
    if (c === '*') { min = 0; max = Infinity; i++; }
    else if (c === '+') { min = 1; max = Infinity; i++; }
    else if (c === '?') { min = 0; max = 1; i++; }
    else if (c === '{') {
      const saved = i;
      const q = tryParseBrace();
      if (!q) return atom; // literal '{'
      min = q.min; max = q.max;
    } else {
      return atom;
    }
    let greedy = true;
    if (!eof() && peek() === '?') { greedy = false; i++; }
    else if (!eof() && peek() === '+') { greedy = true; i++; } // possessive-ish; treat greedy
    return { type: 'repeat', min, max, greedy, body: atom };
  }

  function tryParseBrace() {
    // i points at '{'
    const start = i;
    const m = /^\{(\d+)(,(\d*)?)?\}/.exec(source.slice(i));
    if (!m) return null;
    i += m[0].length;
    const min = parseInt(m[1], 10);
    let max;
    if (m[2] === undefined) max = min;         // {n}
    else if (m[3] === '' || m[3] === undefined) max = Infinity; // {n,}
    else max = parseInt(m[3], 10);             // {n,m}
    return { min, max };
  }

  function parseAtom() {
    const c = peek();
    if (c === '(') return parseGroup();
    if (c === '[') return parseClass();
    if (c === '^' || c === '$') { i++; return { type: 'anchor', kind: c }; }
    if (c === '.') { i++; return { type: 'any' }; }
    if (c === '\\') return parseEscape();
    if (c === '*' || c === '+' || c === '?') {
      // dangling quantifier — treat as literal to be forgiving
      i++; return { type: 'char', value: c };
    }
    i++;
    return { type: 'char', value: c };
  }

  function parseGroup() {
    i++; // consume (
    let capturing = true;
    let name = null;
    let look = null;
    if (peek() === '?') {
      i++;
      const k = peek();
      if (k === ':') { i++; capturing = false; }
      else if (k === '=') { i++; look = { negative: false, behind: false }; }
      else if (k === '!') { i++; look = { negative: true, behind: false }; }
      else if (k === '<') {
        i++;
        const k2 = peek();
        if (k2 === '=') { i++; look = { negative: false, behind: true }; }
        else if (k2 === '!') { i++; look = { negative: true, behind: true }; }
        else {
          // named group (?<name>...)
          let nm = '';
          while (!eof() && peek() !== '>') { nm += source[i++]; }
          if (peek() === '>') i++;
          name = nm; capturing = true;
        }
      } else {
        // unknown group flag (e.g. (?i)) — skip until ) conservatively
        capturing = false;
      }
    }
    const body = parseAlternation();
    if (peek() === ')') i++;
    else throw new Error('unbalanced group');
    if (look) return { type: 'look', negative: look.negative, behind: look.behind, body };
    return { type: 'group', capturing, name, body };
  }

  function parseClass() {
    i++; // consume [
    let negated = false;
    if (peek() === '^') { negated = true; i++; }
    let raw = '';
    // a ] immediately after [ or [^ is a literal
    if (peek() === ']') { raw += ']'; i++; }
    while (!eof() && peek() !== ']') {
      if (peek() === '\\') { raw += source[i++]; if (!eof()) raw += source[i++]; }
      else raw += source[i++];
    }
    if (peek() === ']') i++;
    else throw new Error('unterminated character class');
    return { type: 'class', negated, set: raw };
  }

  function parseEscape() {
    i++; // consume backslash
    if (eof()) return { type: 'char', value: '\\' };
    const c = source[i++];
    if ('dwsDWS'.includes(c)) return { type: 'esc', kind: c };
    if (c === 'b' || c === 'B') return { type: 'anchor', kind: '\\' + c };
    if (/[0-9]/.test(c)) return { type: 'backref', ref: c };
    if (c === 'k') {
      // \k<name>
      let nm = '';
      if (peek() === '<') { i++; while (!eof() && peek() !== '>') nm += source[i++]; if (peek() === '>') i++; }
      return { type: 'backref', ref: nm };
    }
    const map = { n: '\n', r: '\r', t: '\t', f: '\f', v: '\v', '0': '\0' };
    if (c in map) return { type: 'char', value: map[c] };
    return { type: 'char', value: c };
  }

  const ast = parseAlternation();
  if (!eof()) throw new Error('unexpected trailing input at ' + i);
  return ast;
}

module.exports = { parse };
