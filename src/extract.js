'use strict';

/**
 * Extract regex literals from source code, dependency-free, language-aware.
 *
 * The goal is NOT a full parser: it is to reliably find regex *sources* to feed
 * the analyzer, with file:line:column, while avoiding obvious false extractions
 * (division operators, comments, strings). We keep this conservative: it is fine
 * to miss an odd construction (false negative) but we must not mis-slice code
 * into a bogus "regex" that then wastes a dynamic confirmation.
 *
 * Supported:
 *   - JS/TS/JSX/TSX: `/pattern/flags` literals + `new RegExp("...", "flags")`
 *   - Python:        `re.compile("...")`, `re.match/search/fullmatch/... ("...")`
 * Returns array of { source, flags, line, column, raw, kind } (kind = 'literal'|'ctor').
 */

const JS_EXT = new Set(['.js', '.mjs', '.cjs', '.jsx', '.ts', '.tsx', '.mts', '.cts']);
const PY_EXT = new Set(['.py', '.pyi']);

function extForPath(p) {
  const m = /(\.[^.\/\\]+)$/.exec(p);
  return m ? m[1].toLowerCase() : '';
}

function languageForPath(p) {
  const ext = extForPath(p);
  if (JS_EXT.has(ext)) return 'js';
  if (PY_EXT.has(ext)) return 'py';
  return null;
}

// Precompute line-start offsets so we can map an index -> {line, column}.
function lineIndexer(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) {
    if (text[i] === '\n') starts.push(i + 1);
  }
  return function at(index) {
    // binary search for the greatest start <= index
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) {
      const mid = (lo + hi + 1) >> 1;
      if (starts[mid] <= index) lo = mid; else hi = mid - 1;
    }
    return { line: lo + 1, column: index - starts[lo] + 1 };
  };
}

/**
 * A tiny JS tokenizing scanner that walks the source char-by-char, tracking
 * whether we are inside a string / template / comment, so that a `/` is only
 * treated as a regex start when the previous significant token allows it.
 */
function scanJs(text) {
  const out = [];
  const n = text.length;
  let i = 0;
  // Track the last significant (non-space, non-comment) character to decide if
  // a `/` begins a regex (after operators, `(`, `,`, `=`, `:`, `[`, `!`, `&`,
  // `|`, `?`, `{`, `;`, `return`, etc.) versus division (after value/ident/`)`).
  let prevSig = '';
  let prevWord = '';

  const regexAllowedAfter = new Set([
    '', '(', ',', '=', ':', '[', '!', '&', '|', '?', '{', ';', '+', '-', '*',
    '%', '<', '>', '^', '~', '}', 'return',
  ]);

  function isRegexStart() {
    if (regexAllowedAfter.has(prevSig)) return true;
    if (/^(return|typeof|instanceof|in|of|new|do|else|yield|await|case|void|delete)$/.test(prevWord)) return true;
    return false;
  }

  while (i < n) {
    const c = text[i];
    // line comment
    if (c === '/' && text[i + 1] === '/') {
      i += 2;
      while (i < n && text[i] !== '\n') i++;
      continue;
    }
    // block comment
    if (c === '/' && text[i + 1] === '*') {
      i += 2;
      while (i < n && !(text[i] === '*' && text[i + 1] === '/')) i++;
      i += 2;
      continue;
    }
    // strings
    if (c === '"' || c === "'" || c === '`') {
      const quote = c;
      i++;
      while (i < n) {
        if (text[i] === '\\') { i += 2; continue; }
        if (text[i] === quote) { i++; break; }
        // naive template handling: skip ${...} not needed for our purpose
        i++;
      }
      prevSig = 'str'; prevWord = '';
      continue;
    }
    // regex literal
    if (c === '/' && isRegexStart()) {
      const start = i;
      i++;
      let inClass = false;
      let ok = false;
      let body = '';
      while (i < n) {
        const d = text[i];
        if (d === '\\') { body += d + (text[i + 1] || ''); i += 2; continue; }
        if (d === '\n') break; // unterminated -> not a regex
        if (d === '[') inClass = true;
        else if (d === ']') inClass = false;
        else if (d === '/' && !inClass) { ok = true; break; }
        body += d;
        i++;
      }
      if (ok) {
        i++; // consume closing /
        let flags = '';
        while (i < n && /[a-z]/i.test(text[i])) { flags += text[i]; i++; }
        // ignore trivially-empty or clearly-not-regex bodies
        if (body.length > 0) {
          out.push({ index: start, source: body, flags, raw: '/' + body + '/' + flags, kind: 'literal' });
        }
        prevSig = 'regex'; prevWord = '';
        continue;
      } else {
        // treat as division
        i = start + 1;
        prevSig = '/'; prevWord = '';
        continue;
      }
    }
    // new RegExp("...", "flags")  /  RegExp('...')
    if ((c === 'R') && /RegExp/.test(text.slice(i, i + 6)) && /\bRegExp$/.test(text.slice(0, i + 6))) {
      // fallthrough to word handling below; ctor handled by regex on whole text later
    }
    // identifiers / words
    if (/[A-Za-z_$]/.test(c)) {
      let w = '';
      const s = i;
      while (i < n && /[A-Za-z0-9_$]/.test(text[i])) { w += text[i]; i++; }
      prevWord = w; prevSig = 'ident';
      continue;
    }
    // whitespace
    if (/\s/.test(c)) { i++; continue; }
    // any other single significant char
    prevSig = c; prevWord = '';
    i++;
  }
  return out;
}

// new RegExp("src" [, "flags"]) — string-literal args only (dynamic args are
// out of scope; we cannot statically know their value).
function scanCtorArgs(text, ctorRe) {
  const out = [];
  let m;
  const re = new RegExp(ctorRe.source, 'g');
  while ((m = re.exec(text)) !== null) {
    const quote = m[1];
    let raw = m[2];
    const flags = m[4] || '';
    // Unescape the string-literal one level so it becomes a real regex source.
    let source;
    try {
      source = quote === '`'
        ? raw
        : JSON.parse('"' + raw.replace(/\\'/g, "'").replace(/"/g, '\\"') + '"');
    } catch {
      source = raw.replace(/\\(.)/g, '$1');
    }
    if (source && source.length > 0) {
      out.push({ index: m.index, source, flags, raw: m[0], kind: 'ctor' });
    }
  }
  return out;
}

function extractJs(text) {
  const found = scanJs(text);
  // new RegExp("...", "...") — allow single/double/backtick quotes
  const ctorRe = /\bRegExp\s*\(\s*(["'`])((?:\\.|(?!\1)[^\\])*)\1\s*(?:,\s*(["'`])([a-z]*)\3\s*)?\)/;
  return found.concat(scanCtorArgs(text, ctorRe));
}

function extractPy(text) {
  // re.compile(r"...") / re.match(r'...') / re.search("...") etc.
  const reCall = /\bre\.(?:compile|match|search|fullmatch|findall|finditer|sub|subn|split)\s*\(\s*(r?)(["'])((?:\\.|(?!\2)[^\\])*)\2/g;
  const out = [];
  let m;
  while ((m = reCall.exec(text)) !== null) {
    const rawFlag = m[1];
    const body = m[3];
    let source = body;
    if (!rawFlag) {
      // non-raw string: collapse one level of Python escapes for regex meaning
      source = body.replace(/\\(.)/g, (mm, ch) => (ch === '\\' ? '\\\\' : '\\' + ch));
    }
    if (source && source.length > 0) {
      out.push({ index: m.index, source, flags: '', raw: m[0], kind: 'ctor' });
    }
  }
  return out;
}

/**
 * Extract regex sources from a file's text.
 * @param {string} text  file contents
 * @param {string} path  file path (used for language detection)
 * @returns {Array<{source,flags,line,column,raw,kind}>}
 */
function extractFromText(text, path) {
  const lang = languageForPath(path) || 'js';
  const raw = lang === 'py' ? extractPy(text) : extractJs(text);
  const at = lineIndexer(text);
  return raw.map((r) => {
    const pos = at(r.index);
    return { source: r.source, flags: r.flags, line: pos.line, column: pos.column, raw: r.raw, kind: r.kind };
  });
}

module.exports = { extractFromText, languageForPath, JS_EXT, PY_EXT };
