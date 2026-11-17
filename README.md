# Dit

A Handshake (HNS) resolver for your home network, as an umbrelOS community app.

Point your router, your phone or a single device at your Umbrel and Handshake
names resolve next to all the regular internet names. Nothing to install on each
device, and no public resolver to trust.

*Dit* is Catalan for finger, after Fingertip, the desktop resolver this app
brings to the whole network.

> **Status: v0.1.1, early.** The image builds for amd64 and arm64 and the app
> runs on an Umbrel (Raspberry Pi). See [Tested and not tested](#tested-and-not-tested).

## What it does

- Runs **hnsd**, the Handshake light client. It syncs block headers from a
  checkpoint, saves them, and verifies every Handshake answer against them.
  No full node, very little disk.
- Serves DNS to your network through **dnsproxy** (cache, UDP and TCP).
- Two ways to use it, switchable from the web page:
  - **DNS server for my network**: listens on port 53.
  - **Upstream for Pi-hole or AdGuard Home**: listens on port 5300 only and
    leaves port 53 to them.
- A page behind the Umbrel login with the sync status, a name tester and setup
  guides for routers, Android, Tailscale, Pi-hole and AdGuard Home.

This version resolves names. A site secured only with DANE (for example one
hosted with [Castell](https://github.com/galetaire/castell)) still shows a
certificate warning in the browser. Validating DANE for your devices is the
plan for v0.2.

## How it is built

```
your devices ──DNS──▶ dns service (dnsproxy, host network)
                        port 53 and/or 5300
                              │ 127.0.0.1:15350/udp
                              ▼
                      server service
                        hnsd  recursive resolver :5350
                              root nameserver   127.0.0.1:5349 (status)
                        web UI + API :3000  ◀── Umbrel app_proxy ◀── you
```

| Service | Network | What runs | Why |
|---|---|---|---|
| `server` | Umbrel's Docker network | Node web server, which starts and supervises hnsd | hnsd only answers status queries from localhost, so the UI shares its container |
| `dns` | host | Node runner, which starts and supervises dnsproxy | Pi-hole and AdGuard Home use host networking and port 53 on Umbrel; host networking lets Dit pick its ports at runtime instead of failing to start |

Both services use the same image and share the data folder:

| File | Written by | Content |
|---|---|---|
| `data/hnsd/` | hnsd | saved headers (fast restarts) |
| `data/settings.json` | web server | the listening mode |
| `data/dns-state.json` | dns runner | ports in use, errors, the Umbrel's addresses |

### Listening modes

| Mode | Ports | Notes |
|---|---|---|
| Automatic (default) | 53 + 5300 if port 53 is free, else 5300 | Decided on first start and remembered, so it does not depend on which app starts first after a reboot |
| DNS server for my network | 53 + 5300 | If another app holds port 53, Dit listens on 5300 only and shows a warning |
| Upstream | 5300 | For `127.0.0.1#5300` in Pi-hole or `127.0.0.1:5300` in AdGuard Home |

Saving a mode again makes the runner retry port 53.

## Install on umbrelOS

1. Push this repository to GitHub and let the workflow build
   `ghcr.io/galetaire/dit:<version>` (make the package public).
2. In umbrelOS: App Store → ⋯ → Community App Stores → add
   `https://github.com/galetaire/dit`.
3. Install Dit and open it.

## Security notes

- The web page sits behind the Umbrel login and only accepts connections
  routed by Umbrel (`docker/web/lib/source.js`, the same check as Castell).
  Changes need an `X-Dit` header, so other websites cannot change settings
  through your browser.
- The `dns` service runs as root with all capabilities dropped except binding
  low ports and writing its state file.
- **Never forward port 53 from your router to the Umbrel.** dnsproxy has no
  client allowlist; an open resolver gets abused. ANY queries are refused.
- hnsd's own resolver is published on the Umbrel's loopback only (15350/udp).

## hnsd patch

The image builds hnsd with unbound's `aggressive-nsec` turned off. hnsd
cannot prove that a single Handshake name is missing, so it answers with an
NSEC record that makes the whole root zone look empty (`. → .`, 24 hours).
With aggressive NSEC, on by default since unbound 1.15, unbound then denies
every Handshake name until that record expires. The proper fix upstream,
[handshake-org/hnsd#86](https://github.com/handshake-org/hnsd/pull/86), is
not merged. See `docker/Dockerfile`.

## Known limits

- No DANE validation for browsers yet (v0.2: letsdane proxy and a local CA).
- No encrypted DNS (DoT/DoH) listeners yet. Android's Private DNS field needs
  a publicly trusted certificate, so remote use goes through Tailscale.
- dnsproxy talks to hnsd over UDP only (hnsd has no TCP listener). hnsd
  accepts answers up to 4096 bytes, which covers normal use.
- Ports 53, 5300 and 15350 are fixed in `docker-compose.yml`.
- No gallery screenshots yet (`gallery: []` in the manifest).

## Development

No npm dependencies. With Node 22+, an hnsd binary and a dnsproxy binary:

```sh
cd docker/web
npm test                       # DNS client unit tests

# Web server + hnsd
DIT_DATA=/tmp/dit DIT_HNSD_BIN=/path/to/hnsd PORT=3900 node server.js

# DNS runner on unprivileged ports
DIT_DATA=/tmp/dit DIT_DNSPROXY_BIN=/path/to/dnsproxy \
  DIT_UPSTREAM=127.0.0.1:5350 DIT_MAIN_PORT=5053 node dns-runner.js
```

Environment variables:

| Variable | Default | Used by |
|---|---|---|
| `DIT_DATA` | `/data` | both |
| `DIT_PROXY_HOST`, `DIT_TRUSTED_IPS`, `DIT_ALLOW_ANY_SOURCE` | – | web: who may connect |
| `DIT_HNSD_BIN`, `DIT_HNSD_POOL_SIZE`, `DIT_HNSD_DISABLED` | `hnsd`, `4`, `false` | web |
| `DIT_DNSPROXY_BIN` | `dnsproxy` | dns |
| `DIT_UPSTREAM` | `127.0.0.1:15350` | dns |
| `DIT_MAIN_PORT`, `DIT_ALT_PORT` | `53`, `5300` | dns |
| `DIT_CACHE_BYTES` | 8 MB | dns |

### Releasing

1. Bump `version` in `dit-resolver/umbrel-app.yml`, the image tag (twice)
   in `dit-resolver/docker-compose.yml`, and `docker/web/package.json`.
2. Push to `main`: the workflow builds amd64 and arm64 images tagged with that
   version.

## Tested and not tested

Tested locally (Node 22, hnsd built from the pinned commit, dnsproxy v0.86.0):

- DNS client: parsing of A, AAAA, TXT and TLSA answers, the DNSSEC flag, timeouts.
- hnsd starts under the web server with the flags used here, and its status
  (height, sync progress, peers) is read through the Hesiod queries.
- Status queries from a non-loopback address get no answer.
- Runner: first start in automatic mode, switching modes from the API,
  port-53-busy fallback (pinned and automatic), the remembered decision after
  a restart, restart of a killed dnsproxy, clean shutdown of both children.
- API: source check, `X-Dit` header, name validation.
- Log filter: Dit's status queries are dropped, lines split across chunks are joined.

Tested on an Umbrel (Raspberry Pi, v0.1.0):

- The image build for amd64 and arm64 and the GitHub workflow.
- Install from the community store, `app_proxy`, header sync to the tip.
- Port 53 taken by Pi-hole: automatic mode fell back to port 5300; after
  removing Pi-hole, standalone mode got port 53.
- Real lookups through ports 53 and 5300. This found the aggressive-NSEC
  problem described in [hnsd patch](#hnsd-patch).

Not tested yet:

- The hnsd patch on a real Umbrel (v0.1.1).
- Android over Wi-Fi and Tailscale, AdGuard Home in front of Dit.
- hnsd serving a whole network for days.

## Credits and licenses

- [hnsd](https://github.com/handshake-org/hnsd) (MIT), Handshake light client.
- [dnsproxy](https://github.com/AdguardTeam/dnsproxy) (Apache-2.0), AdGuard.
- IBM Plex fonts (SIL Open Font License), see `docker/web/public/fonts/OFL.txt`.

Dit itself is released under the MIT License, see `LICENSE`.
