'use strict';

// Minimal DNS client over UDP (no dependencies). Used for:
// - test lookups against hnsd's recursive resolver, and
// - hnsd's status, which it publishes as TXT records in the Hesiod (HS) class.
const dgram = require('dgram');

const TYPES = {A: 1, NS: 2, CNAME: 5, SOA: 6, MX: 15, TXT: 16, AAAA: 28, DS: 43, RRSIG: 46, TLSA: 52, OPT: 41};
const TYPE_NAMES = Object.fromEntries(Object.entries(TYPES).map(([name, code]) => [code, name]));
const CLASSES = {IN: 1, HS: 4};
const RCODES = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 4: 'NOTIMP', 5: 'REFUSED'};

function encodeQuery(id, name, type, klass) {
  // RD (recurse) + AD (tell me if you validated DNSSEC)
  const parts = [Buffer.from([id >> 8, id & 0xff, 0x01, 0x20, 0, 1, 0, 0, 0, 0, 0, 1])];
  for (const label of name.replace(/\.$/, '').split('.').filter(Boolean)) {
    const bytes = Buffer.from(label, 'ascii');
    if (bytes.length > 63) throw new Error('DNS label too long');
    parts.push(Buffer.from([bytes.length]), bytes);
  }
  parts.push(Buffer.from([0, type >> 8, type & 0xff, klass >> 8, klass & 0xff]));
  // OPT: root name, type 41, UDP size 4096, extended rcode/version 0, DO bit, no options
  parts.push(Buffer.from([0, 0, TYPES.OPT, 0x10, 0x00, 0, 0, 0x80, 0, 0, 0]));
  return Buffer.concat(parts);
}

// Reads a (possibly compressed) name. Returns [name, offset after it].
function readName(buf, off) {
  const labels = [];
  let end = -1;
  for (let jumps = 0; jumps < 64; ) {
    const len = buf[off];
    if (len === undefined) throw new Error('truncated DNS answer');
    if (len === 0) {
      if (end < 0) end = off + 1;
      return [labels.length ? labels.join('.') + '.' : '.', end];
    }
    if ((len & 0xc0) === 0xc0) {
      if (end < 0) end = off + 2;
      off = ((len & 0x3f) << 8) | buf[off + 1];
      jumps++;
      continue;
    }
    labels.push(buf.toString('latin1', off + 1, off + 1 + len));
    off += len + 1;
  }
  throw new Error('DNS name has too many compression pointers');
}

function readTxt(data) {
  const chunks = [];
  for (let off = 0; off < data.length; off += data[off] + 1) {
    chunks.push(data.toString('utf8', off + 1, off + 1 + data[off]));
  }
  return chunks.join('');
}

function ipv6(data) {
  const groups = [];
  for (let i = 0; i < 16; i += 2) groups.push(data.readUInt16BE(i).toString(16));
  // Collapse the longest run of zero groups
  let best = [-1, 0];
  for (let i = 0; i < 8; i++) {
    let j = i;
    while (j < 8 && groups[j] === '0') j++;
    if (j - i > best[1] && j - i > 1) best = [i, j - i];
  }
  if (best[0] < 0) return groups.join(':');
  return `${groups.slice(0, best[0]).join(':')}::${groups.slice(best[0] + best[1]).join(':')}`;
}

function readData(buf, type, start, length) {
  const data = buf.subarray(start, start + length);
  switch (type) {
    case TYPES.A: return [...data].join('.');
    case TYPES.AAAA: return ipv6(data);
    case TYPES.NS:
    case TYPES.CNAME: return readName(buf, start)[0];
    case TYPES.MX: return `${data.readUInt16BE(0)} ${readName(buf, start + 2)[0]}`;
    case TYPES.TXT: return readTxt(data);
    case TYPES.TLSA: return `${data[0]} ${data[1]} ${data[2]} ${data.subarray(3).toString('hex')}`;
    case TYPES.DS: return `${data.readUInt16BE(0)} ${data[2]} ${data[3]} ${data.subarray(4).toString('hex')}`;
    case TYPES.SOA: {
      const [mname, next] = readName(buf, start);
      const [rname, rest] = readName(buf, next);
      return `${mname} ${rname} ${buf.readUInt32BE(rest)}`;
    }
    default: return data.toString('hex');
  }
}

function parseResponse(buf) {
  const flags = buf.readUInt16BE(2);
  const result = {
    rcode: RCODES[flags & 0xf] || `RCODE ${flags & 0xf}`,
    truncated: !!(flags & 0x200),
    // The resolver validated the answer with DNSSEC
    authenticated: !!(flags & 0x20),
    answers: [],
  };
  let off = 12;
  for (let i = buf.readUInt16BE(4); i > 0; i--) off = readName(buf, off)[1] + 4;
  for (let i = buf.readUInt16BE(6); i > 0; i--) {
    const [name, next] = readName(buf, off);
    const type = buf.readUInt16BE(next);
    const ttl = buf.readUInt32BE(next + 4);
    const length = buf.readUInt16BE(next + 8);
    // Signatures are shown as the "DNSSEC" flag, not as rows
    if (type !== TYPES.RRSIG) {
      result.answers.push({name, type: TYPE_NAMES[type] || `TYPE${type}`, ttl, data: readData(buf, type, next + 10, length)});
    }
    off = next + 10 + length;
  }
  return result;
}

// query({host, port, name, type: 'A', klass: 'IN', timeout})
function query({host, port, name, type = 'A', klass = 'IN', timeout = 6000}) {
  return new Promise((resolve, reject) => {
    const id = Math.floor(Math.random() * 0x10000);
    let packet;
    try {
      packet = encodeQuery(id, name, TYPES[type], CLASSES[klass]);
    } catch (e) {
      reject(e);
      return;
    }
    const socket = dgram.createSocket(host.includes(':') ? 'udp6' : 'udp4');
    const done = (err, value) => {
      clearTimeout(timer);
      try { socket.close(); } catch (e) { /* already closed */ }
      if (err) reject(err); else resolve(value);
    };
    const timer = setTimeout(() => done(new Error('The resolver did not answer in time.')), timeout);
    socket.on('error', err => done(err));
    socket.on('message', message => {
      if (message.length < 12 || message.readUInt16BE(0) !== id) return;
      try {
        done(null, parseResponse(message));
      } catch (e) {
        done(e);
      }
    });
    socket.send(packet, port, host, err => { if (err) done(err); });
  });
}

module.exports = {query, TYPES, encodeQuery, parseResponse};
