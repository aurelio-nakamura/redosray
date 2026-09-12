'use strict';
// Public library API for redosray.
const { scanRegex } = require('./scan');
const { findCandidates, shapeOf } = require('./analyze');
const { parse } = require('./parser');
const { confirm, timeMatch } = require('./confirm');
const { scanPaths, collectFiles } = require('./scanFiles');
const { extractFromText } = require('./extract');
const { suggestFix } = require('./fix');

module.exports = {
  scanRegex,      // async: static candidates + dynamic confirmation -> proof
  suggestFix,     // async: verified safe rewrite (or labelled strategy note)
  scanPaths,      // async: scan files/dirs for vulnerable regexes -> report
  collectFiles,   // list scannable source files under roots
  extractFromText,// pull regex literals (+file position) from source text
  findCandidates, // static only: list attack candidates
  parse,          // regex -> AST
  shapeOf,        // AST -> source-ish string
  confirm,        // dynamic confirmation of one attack
  timeMatch,      // time a single regex match in an isolated worker
};
