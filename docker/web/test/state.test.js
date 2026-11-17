'use strict';

const test = require('node:test');
const assert = require('node:assert');
const {validRedirectIp, redirectEnabled} = require('../lib/state');

test('accepts private IPv4 addresses for DANE without proxy settings', () => {
  for (const ip of ['192.168.1.200', '10.0.0.5', '172.16.0.9', '172.31.255.1']) assert.ok(validRedirectIp(ip), ip);
});

test('refuses public, network, broadcast and malformed addresses', () => {
  for (const ip of ['8.8.8.8', '172.32.0.1', '192.168.1.0', '192.168.1.255', '192.168.1', '300.1.1.1', 'fd00::1', '', null]) {
    assert.ok(!validRedirectIp(ip), String(ip));
  }
});

test('redirect is on only when enabled with a valid address', () => {
  assert.ok(redirectEnabled({redirect: {enabled: true, ip: '192.168.1.200'}}));
  assert.ok(!redirectEnabled({redirect: {enabled: false, ip: '192.168.1.200'}}));
  assert.ok(!redirectEnabled({redirect: {enabled: true, ip: '8.8.8.8'}}));
  assert.ok(!redirectEnabled({mode: 'auto'}));
});
