'use strict';

// Tree roots synced by Dit's own hnsd, for the Stateless DANE checker.
//
// A Stateless DANE proof (HIP-17) is anchored to a Handshake name tree root.
// hnsd logs every block header it adds:
//   chain (<height>): adding block: <hash>
//   chain (<height>): tree_root <hex> timestamp <unix>
// and on every start it re-adds about two weeks of headers (it saves a
// checkpoint 2000 blocks behind the tip), so this collects two weeks of roots.
//
// hnsd logs the root before validating the header, so a root is only kept
// when no "rejected" or "stored as orphan" line follows it.
// The roots are kept in /data/tree-roots.json for `dit-dane check`.

const fs = require('fs');
const path = require('path');

const FILE = path.join(process.env.DIT_DATA || '/data', 'tree-roots.json');
// Older roots are of no use: the checker refuses proofs older than 15 days
const KEEP_SECONDS = 16 * 24 * 3600;

const ROOT_RE = /chain \((\d+)\): tree_root ([0-9a-f]{64}) timestamp (\d+)/;
const REJECT_RE = /chain \(\d+\):\s+(rejected|stored as orphan)/;
const CHAIN_RE = /^chain \(\d+\):/;

function createCollector({file = FILE, now = () => Date.now() / 1000, saveDelayMs = 5000} = {}) {
  // root -> {root, height, time}
  const roots = new Map();
  let pending = null;
  let pendingTimer = null;
  let saveTimer = null;

  try {
    const saved = JSON.parse(fs.readFileSync(file, 'utf8'));
    for (const r of saved.roots || []) {
      if (/^[0-9a-f]{64}$/.test(r.root)) roots.set(r.root, r);
    }
  } catch (e) {
    // first start: nothing collected yet
  }

  function prune() {
    const oldest = now() - KEEP_SECONDS;
    for (const [root, r] of roots) if (r.time < oldest) roots.delete(root);
  }

  function save() {
    clearTimeout(saveTimer);
    saveTimer = null;
    prune();
    const list = [...roots.values()].sort((a, b) => a.height - b.height);
    const text = JSON.stringify({roots: list, updatedAt: new Date(now() * 1000).toISOString()}) + '\n';
    try {
      fs.mkdirSync(path.dirname(file), {recursive: true});
      const tmp = `${file}.${process.pid}.tmp`;
      fs.writeFileSync(tmp, text);
      fs.renameSync(tmp, file);
    } catch (e) {
      console.error('[Dit] could not save tree roots:', e.message);
    }
  }

  function scheduleSave() {
    if (saveDelayMs === 0) return save();
    if (!saveTimer) saveTimer = setTimeout(save, saveDelayMs);
  }

  function commit() {
    clearTimeout(pendingTimer);
    pendingTimer = null;
    if (!pending) return;
    const known = roots.get(pending.root);
    // The same root covers 36 blocks: keep the first block that had it
    if (!known || pending.height < known.height) {
      roots.set(pending.root, pending);
      scheduleSave();
    }
    pending = null;
  }

  // One line of hnsd output
  function feed(line) {
    const m = ROOT_RE.exec(line);
    if (m) {
      commit();
      // hnsd prints the height before adding: the block itself is one higher
      pending = {root: m[2], height: Number(m[1]) + 1, time: Number(m[3])};
      // No verdict line within a few seconds means it was accepted
      if (saveDelayMs !== 0) pendingTimer = setTimeout(commit, 3000);
      return;
    }
    if (!pending || !CHAIN_RE.test(line)) return;
    if (REJECT_RE.test(line)) {
      clearTimeout(pendingTimer);
      pending = null;
    } else {
      commit();
    }
  }

  return {
    feed,
    flush() { commit(); save(); },
    summary() {
      prune();
      let newest = null;
      for (const r of roots.values()) if (!newest || r.height > newest.height) newest = r;
      return {count: roots.size, newestHeight: newest ? newest.height : null, newestTime: newest ? newest.time : null};
    },
    file,
  };
}

module.exports = {createCollector, FILE};
