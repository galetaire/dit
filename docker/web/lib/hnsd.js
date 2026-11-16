'use strict';

// Runs hnsd (the Handshake light client) as a child process, restarts it if it
// stops, keeps its recent log lines, and reads its status.
//
// hnsd has two DNS servers:
// - the root nameserver (NS_PORT): answers for the Handshake root zone and,
//   in the Hesiod class, publishes hnsd's own status. It only answers status
//   queries that come from localhost, which is why hnsd runs in this container;
// - the recursive resolver (RS_PORT): what the rest of the network uses.
const {spawn} = require('child_process');
const fs = require('fs');
const path = require('path');
const dnsclient = require('./dnsclient');

const HNSD_BIN = process.env.DIT_HNSD_BIN || 'hnsd';
const DATA_DIR = path.join(process.env.DIT_DATA || '/data', 'hnsd');
const NS_PORT = Number(process.env.DIT_HNSD_NS_PORT || 5349);
const RS_PORT = Number(process.env.DIT_HNSD_RS_PORT || 5350);
// Listen address of the recursive resolver: all interfaces of this container,
// so the published port (docker-compose.yml) reaches it
const RS_BIND = process.env.DIT_HNSD_RS_BIND || '0.0.0.0';
const POOL_SIZE = Number(process.env.DIT_HNSD_POOL_SIZE || 4);
const MAX_LOG_LINES = 300;

let child = null;
let stopping = false;
let startedAt = null;
let restarts = 0;
let lastExit = null;
const logLines = [];

function pushLog(text) {
  for (const line of String(text).split('\n')) {
    if (!line.trim()) continue;
    logLines.push(line);
    if (logLines.length > MAX_LOG_LINES) logLines.shift();
  }
}

function start() {
  if (process.env.DIT_HNSD_DISABLED === 'true') {
    pushLog('hnsd is not started by Dit (DIT_HNSD_DISABLED=true).');
    return;
  }
  fs.mkdirSync(DATA_DIR, {recursive: true});
  // -t: start from the built-in checkpoint; -x: save headers, so later starts take seconds
  const args = ['-t', '-x', DATA_DIR, '-n', `127.0.0.1:${NS_PORT}`, '-r', `${RS_BIND}:${RS_PORT}`, '-p', String(POOL_SIZE)];
  pushLog(`[dit] starting: ${HNSD_BIN} ${args.join(' ')}`);
  startedAt = Date.now();
  child = spawn(HNSD_BIN, args, {stdio: ['ignore', 'pipe', 'pipe']});
  child.stdout.on('data', pushLog);
  child.stderr.on('data', pushLog);
  child.on('error', err => {
    lastExit = `could not start hnsd: ${err.message}`;
    pushLog(`[dit] ${lastExit}`);
  });
  child.on('close', (code, signal) => {
    child = null;
    if (stopping) return;
    lastExit = `hnsd stopped (${signal || `exit code ${code}`})`;
    restarts++;
    // Back off: 2s, 4s, ... up to 30s
    const delay = Math.min(30000, 2000 * Math.min(restarts, 15));
    pushLog(`[dit] ${lastExit}, restarting in ${delay / 1000}s`);
    setTimeout(() => { if (!stopping) start(); }, delay);
  });
}

function stop() {
  stopping = true;
  if (!child) return Promise.resolve();
  return new Promise(resolve => {
    const timer = setTimeout(() => { if (child) child.kill('SIGKILL'); }, 20000);
    child.once('close', () => { clearTimeout(timer); resolve(); });
    // hnsd saves its headers on SIGINT/SIGTERM
    child.kill('SIGTERM');
  });
}

async function hesiod(name) {
  const res = await dnsclient.query({host: '127.0.0.1', port: NS_PORT, name, type: 'TXT', klass: 'HS', timeout: 2500});
  const map = {};
  for (const answer of res.answers) map[answer.name.toLowerCase()] = answer.data;
  return map;
}

// {running, reachable, synced, height, progress, tipTime, peers, ...}
async function status() {
  const result = {
    running: !!child,
    startedAt,
    restarts,
    lastExit,
    reachable: false,
    synced: false,
    height: null,
    progress: null,
    tipTime: null,
    peers: null,
  };
  try {
    const chain = await hesiod('chain.hnsd.');
    result.reachable = true;
    result.synced = chain['synced.chain.hnsd.'] === 'true';
    result.height = Number(chain['height.tip.chain.hnsd.'] || 0);
    result.progress = Number(chain['progress.chain.hnsd.'] || 0);
    result.tipTime = Number(chain['time.tip.chain.hnsd.'] || 0) || null;
    const pool = await hesiod('size.pool.hnsd.');
    result.peers = Number(pool['size.pool.hnsd.'] || 0);
  } catch (e) {
    // hnsd is still starting, or stopped: "reachable" stays false
  }
  return result;
}

// A lookup through hnsd's recursive resolver, the same path your devices use
function lookup(name, type) {
  return dnsclient.query({host: '127.0.0.1', port: RS_PORT, name, type});
}

module.exports = {start, stop, status, lookup, log: () => logLines.slice(), RS_PORT, NS_PORT};
