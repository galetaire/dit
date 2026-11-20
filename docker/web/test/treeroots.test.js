'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const {createCollector} = require('../lib/treeroots');

const R1 = 'a'.repeat(64);
const R2 = 'b'.repeat(64);
const R3 = 'c'.repeat(64);
const NOW = 1795000000;

function collector() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'dit-roots-'));
  const file = path.join(dir, 'tree-roots.json');
  const c = createCollector({file, now: () => NOW, saveDelayMs: 0});
  return {c, file, read: () => JSON.parse(fs.readFileSync(file, 'utf8')).roots};
}

// What hnsd prints for one header
const block = (height, root, time = NOW - 3600) => [
  `chain (${height}): adding block: ${'0'.repeat(64)}`,
  `chain (${height}): tree_root ${root} timestamp ${time} `,
];

test('keeps the root of an accepted header', () => {
  const {c, read} = collector();
  [...block(100, R1), 'chain (101): adding block: ff'].forEach(c.feed);
  assert.deepStrictEqual(read(), [{root: R1, height: 101, time: NOW - 3600}]);
});

test('drops the root of a rejected or orphaned header', () => {
  const {c, read} = collector();
  [...block(100, R1), 'chain (100):   rejected: time-too-new',
   ...block(100, R2), 'chain (100):   stored as orphan',
   ...block(100, R3), 'chain (100):   rejected: pow error: invalid'].forEach(c.feed);
  c.flush();
  assert.deepStrictEqual(read(), []);
});

test('keeps one entry per root, with the first block that had it', () => {
  const {c, read} = collector();
  [...block(200, R1), ...block(199, R1), ...block(201, R1)].forEach(c.feed);
  c.flush();
  const roots = read();
  assert.strictEqual(roots.length, 1);
  assert.strictEqual(roots[0].height, 200);
});

test('forgets roots older than 16 days and ignores other lines', () => {
  const {c, read} = collector();
  [...block(10, R1, NOW - 20 * 86400), 'pool: some peer said hello', ...block(11, R2), 'chain (12): adding block: ee'].forEach(c.feed);
  c.flush();
  assert.deepStrictEqual(read().map(r => r.root), [R2]);
  assert.strictEqual(c.summary().count, 1);
});

test('loads what an earlier run saved', () => {
  const {c, file} = collector();
  [...block(300, R3), 'chain (301): adding block: 11'].forEach(c.feed);
  const again = createCollector({file, now: () => NOW, saveDelayMs: 0});
  assert.strictEqual(again.summary().count, 1);
  assert.strictEqual(again.summary().newestHeight, 301);
});
