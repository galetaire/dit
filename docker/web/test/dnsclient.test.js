'use strict';

// node --test   (no dependencies)
const test = require('node:test');
const assert = require('node:assert');
const dgram = require('dgram');
const {query} = require('../lib/dnsclient');

// A one-shot fake DNS server: answers every question with the records built by `build`.
function fakeServer(build) {
  return new Promise(resolve => {
    const socket = dgram.createSocket('udp4');
    socket.on('message', (msg, rinfo) => {
      let end = 12;
      while (msg[end] !== 0) end += msg[end] + 1;
      const question = msg.subarray(12, end + 5);
      const records = build();
      const header = Buffer.from([msg[0], msg[1], 0x81, 0xa0, 0, 1, 0, records.length, 0, 0, 0, 0]);
      socket.send(Buffer.concat([header, question, ...records]), rinfo.port, rinfo.address);
    });
    socket.bind(0, '127.0.0.1', () => resolve(socket));
  });
}

// A record whose name is a compression pointer to the question name (offset 12)
function record(type, klass, ttl, data) {
  const head = Buffer.alloc(12);
  head.writeUInt16BE(0xc00c, 0);
  head.writeUInt16BE(type, 2);
  head.writeUInt16BE(klass, 4);
  head.writeUInt32BE(ttl, 6);
  head.writeUInt16BE(data.length, 10);
  return Buffer.concat([head, data]);
}

test('parses A, AAAA, TXT and TLSA answers and the AD flag', async () => {
  const txt = Buffer.from('hello world');
  const server = await fakeServer(() => [
    record(1, 1, 300, Buffer.from([203, 0, 113, 7])),
    record(28, 1, 300, Buffer.from('20010db8000000000000000000000001', 'hex')),
    record(16, 1, 60, Buffer.concat([Buffer.from([txt.length]), txt])),
    record(52, 1, 60, Buffer.from('030101' + 'ab'.repeat(32), 'hex')),
    record(46, 1, 60, Buffer.from('00', 'hex')), // RRSIG: skipped
  ]);
  try {
    const res = await query({host: '127.0.0.1', port: server.address().port, name: 'www.mysite', type: 'A'});
    assert.strictEqual(res.rcode, 'NOERROR');
    assert.strictEqual(res.authenticated, true);
    assert.deepStrictEqual(res.answers.map(a => [a.name, a.type, a.data]), [
      ['www.mysite.', 'A', '203.0.113.7'],
      ['www.mysite.', 'AAAA', '2001:db8::1'],
      ['www.mysite.', 'TXT', 'hello world'],
      ['www.mysite.', 'TLSA', `3 1 1 ${'ab'.repeat(32)}`],
    ]);
  } finally {
    server.close();
  }
});

test('times out when nothing answers', async () => {
  const silent = dgram.createSocket('udp4');
  await new Promise(resolve => silent.bind(0, '127.0.0.1', resolve));
  try {
    await assert.rejects(query({host: '127.0.0.1', port: silent.address().port, name: 'mysite', timeout: 200}), /did not answer/);
  } finally {
    silent.close();
  }
});
