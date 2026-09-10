'use strict';
// Public library API for redosray.
const { scanRegex } = require('./scan');
const { findCandidates, shapeOf } = require('./analyze');
const { parse } = require('./parser');
const { confirm, timeMatch } = require('./confirm');

module.exports = {
  scanRegex,      // async: static candidates + dynamic confirmation -> proof
  findCandidates, // static only: list attack candidates
  parse,          // regex -> AST
  shapeOf,        // AST -> source-ish string
  confirm,        // dynamic confirmation of one attack
  timeMatch,      // time a single regex match in an isolated worker
};
