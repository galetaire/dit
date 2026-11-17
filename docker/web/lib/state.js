'use strict';

// Files shared between the two containers, in the data folder:
// - settings.json   written by the web server (this app's settings)
// - dns-state.json  written by the dns runner (what it is listening on)
const fs = require('fs');
const path = require('path');

const DATA_DIR = process.env.DIT_DATA || '/data';
const SETTINGS_FILE = path.join(DATA_DIR, 'settings.json');
const DNS_STATE_FILE = path.join(DATA_DIR, 'dns-state.json');
// Written by the dane service (docker/dane/main.go): port, CA fingerprint
const DANE_STATE_FILE = path.join(DATA_DIR, 'dane-state.json');

// auto:       use port 53 unless another app already has it (decided once)
// standalone: Dit is the network's DNS server (port 53 + the alternate port)
// upstream:   only the alternate port, for Pi-hole or AdGuard Home to forward to
const MODES = ['auto', 'standalone', 'upstream'];
const DEFAULT_SETTINGS = {mode: 'auto'};

function readJson(file, fallback) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    return fallback;
  }
}

// Write to a temporary file and rename, so the other container never reads half a file
function writeAtomic(file, text, mode = 0o644) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, text, {mode});
  fs.renameSync(tmp, file);
}

// DANE without proxy settings: a private IPv4 address, not .0 or .255.
// The same rule as validRedirectIP in docker/dane/settings.go.
function validRedirectIp(value) {
  const parts = String(value || '').trim().split('.');
  if (parts.length !== 4 || !parts.every(p => /^\d{1,3}$/.test(p) && Number(p) <= 255)) return false;
  const [a, b, , d] = parts.map(Number);
  const isPrivate = a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  return isPrivate && d !== 0 && d !== 255;
}

// Is DANE without proxy settings switched on, with a usable address?
function redirectEnabled(settings) {
  const redirect = settings.redirect || {};
  return redirect.enabled === true && validRedirectIp(redirect.ip);
}

function loadSettings() {
  const settings = {...DEFAULT_SETTINGS, ...readJson(SETTINGS_FILE, {})};
  if (!MODES.includes(settings.mode)) settings.mode = DEFAULT_SETTINGS.mode;
  return settings;
}

function saveSettings(settings) {
  fs.mkdirSync(DATA_DIR, {recursive: true});
  writeAtomic(SETTINGS_FILE, JSON.stringify(settings, null, 2) + '\n');
}

const loadDnsState = () => readJson(DNS_STATE_FILE, null);
const loadDaneState = () => readJson(DANE_STATE_FILE, null);

function saveDnsState(state) {
  fs.mkdirSync(DATA_DIR, {recursive: true});
  writeAtomic(DNS_STATE_FILE, JSON.stringify(state, null, 2) + '\n');
}

// Written by the net service ("dit-dane net"): the extra address it set up
const NET_STATE_FILE = path.join(DATA_DIR, 'net-state.json');
const loadNetState = () => readJson(NET_STATE_FILE, null);

module.exports = {
  MODES, DATA_DIR, loadSettings, saveSettings, loadDnsState, saveDnsState, loadDaneState, loadNetState,
  validRedirectIp, redirectEnabled,
};
