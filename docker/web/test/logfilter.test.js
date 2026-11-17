'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {createLogFilter} = require('../lib/hnsd');

// The block hnsd logs for one root-server query
const nsQuery = (name, tld, klass) => [
  'ns: query',
  'ns:   id=1',
  'ns:   labels=2',
  `ns:   name=${name}`,
  'ns:   type=16',
  `ns:   class=${klass}`,
  'ns:   edns=1',
  'ns:   dnssec=1',
  `ns:   tld=${tld}`,
  'ns:   addr=127.0.0.1:40000',
];

function run(chunks) {
  const lines = [];
  const filter = createLogFilter(line => lines.push(line));
  chunks.forEach(chunk => filter.write(chunk));
  filter.end();
  return lines;
}

test('drops the blocks of Dit\'s own status queries', () => {
  const text = [...nsQuery('chain.hnsd.', 'hnsd', 4), 'pool: peer connected', ...nsQuery('size.pool.hnsd.', 'hnsd', 4)].join('\n') + '\n';
  assert.deepStrictEqual(run([text]), ['pool: peer connected']);
});

test('keeps the blocks of real lookups', () => {
  const block = nsQuery('woodburn.', 'woodburn', 1);
  assert.deepStrictEqual(run([block.join('\n') + '\n']), block);
});

test('joins lines cut between chunks', () => {
  const text = [...nsQuery('chain.hnsd.', 'hnsd', 4), 'rs: received answer for: woodburn.'].join('\n') + '\n';
  const cut = text.indexOf('query') + 2;
  assert.deepStrictEqual(run([text.slice(0, cut), text.slice(cut)]), ['rs: received answer for: woodburn.']);
});

test('keeps an unfinished block and a last line without newline', () => {
  assert.deepStrictEqual(run(['ns: query\nns:   id=5\nchain: done']), ['ns: query', 'ns:   id=5', 'chain: done']);
});
