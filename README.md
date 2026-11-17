# Dit

A Handshake (HNS) resolver for your home network, as an umbrelOS community app.

Point your router, your phone or a single device at your Umbrel and Handshake
names resolve next to all the regular internet names. Nothing to install on each
device, and no public resolver to trust.

*Dit* is Catalan for finger, after Fingertip, the desktop resolver this app
brings to the whole network.

> **Status: v0.3.1, early.** The image builds for amd64 and arm64 and the app
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

Since v0.2 Dit also validates DANE for your browsers: sites secured only by
their TLSA record (for example one hosted with
[Castell](https://github.com/galetaire/castell)) open without a certificate
warning, through a proxy on the Umbrel and a local CA you install once per
device. See [DANE proxy](#dane-proxy).

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

your browsers ──PAC──▶ dane service (dit-dane, host network) :9053
                        checks TLSA via 127.0.0.1:5300, re-signs with the local CA
```

| Service | Network | What runs | Why |
|---|---|---|---|
| `server` | Umbrel's Docker network | Node web server, which starts and supervises hnsd | hnsd only answers status queries from localhost, so the UI shares its container |
| `dns` | host | Node runner, which starts and supervises dnsproxy | Pi-hole and AdGuard Home use host networking and port 53 on Umbrel; host networking lets Dit pick its ports at runtime instead of failing to start |
| `dane` | host | dit-dane (Go, built on letsdane): DANE proxy, DNS rewriter, redirect fronts | Devices on the LAN reach the proxy directly, and it reaches hnsd on the Umbrel's loopback |
| `net` | host, root with `NET_ADMIN`, `NET_RAW`, `DAC_OVERRIDE` | `dit-dane net` | Only for DANE without proxy settings: adds the extra address and two firewall rules while that feature is on, nothing otherwise |

All services use the same image and share the data folder:

| File | Written by | Content |
|---|---|---|
| `data/hnsd/` | hnsd | saved headers (fast restarts) |
| `data/settings.json` | web server | the listening mode |
| `data/dns-state.json` | dns runner | ports in use, errors, the Umbrel's addresses |
| `data/dane/ca.crt`, `ca.key` | dane service | the local CA (key 0600, never leaves the Umbrel) |
| `data/dane-state.json` | dane service | proxy port, CA fingerprint and expiry |
| `data/net-state.json` | net service | the extra address it set up, or why it could not |

### Listening modes

| Mode | Ports | Notes |
|---|---|---|
| Automatic (default) | 53 + 5300 if port 53 is free, else 5300 | Decided on first start and remembered, so it does not depend on which app starts first after a reboot. If port 53 frees up later, the page offers it ("Use port 53") but Dit never takes it by itself: the other DNS app may only be restarting |
| DNS server for my network | 53 + 5300 | If another app holds port 53, Dit listens on 5300 only, shows a warning, and takes port 53 as soon as it is free (checked every 30 s) |
| Upstream | 5300 | For `127.0.0.1#5300` in Pi-hole or `127.0.0.1:5300` in AdGuard Home. Port 53 is never checked |

Saving a mode again makes the runner retry port 53. Saving Automatic again also
forgets its remembered decision.

## DANE proxy

Browsers don't check DANE. The `dane` service (`docker/dane/main.go`) is a
small Go program built on [letsdane](https://github.com/buffrr/letsdane)
v0.6.1, the library Fingertip uses:

1. Devices load the auto-config file `http://<umbrel>:9053/proxy.pac`. It
   sends only Handshake names to the proxy: ICANN names (IANA's list,
   downloaded at every image build), special-use names (`.local`,
   `localhost`, `home.arpa`, `.onion`…) and IP addresses go direct.
2. For a Handshake name, the proxy looks up the TLSA record through Dit
   (`127.0.0.1:5300`; it trusts the DNSSEC AD flag of that loopback
   resolver) and checks the site's certificate against it.
3. If it matches, the browser gets a certificate for the name signed by the
   local CA, valid for an hour. If not, the connection is closed. Names
   without TLSA records are tunnelled untouched.

The CA is created on first start (RSA 2048, valid 5 years). Its critical name
constraints exclude every ICANN TLD, the special-use names and all IP
addresses, so a certificate it signs is rejected for `gmail.com` or a bank
even if the key were stolen (`main_test.go` checks this). Devices download it
from `http://<umbrel>:9053/dit-dane.crt`; the page shows its SHA-256
fingerprint to compare. The proxy only serves private, loopback and Tailscale
addresses.

Limits: Android has proxy settings per Wi-Fi network only, and most Android
apps ignore user-installed CAs (Chrome trusts them). New ICANN TLDs added
after the CA was created are not in its constraints, though the PAC file of a
newer image still sends them direct.

## DANE without proxy settings (v0.3, beta)

Opt-in, on the Secure sites page: devices that use Dit as their DNS server
open DANE sites with only the certificate installed, no auto-config proxy.

umbrelOS serves its own HTTPS ("Umbrel Local HTTPS CA") on port 443 of every
address the Umbrel has, for every name, so Dit uses an **extra address** on
the LAN, chosen on the page (outside the router's DHCP range):

1. The `net` service adds that address to the interface whose subnet
   contains it, after an ARP check that nothing else uses it, and two nat
   `PREROUTING` rules tagged `dit-redirect`: `<address>:443` to the dane
   service's TLS front (9443), `<address>:80` to its HTTP front (9080). It
   re-adds rules that disappear, and removes everything when the feature is
   switched off or the app stops. What it set up is kept in
   `data/net-state.json`, so a crash leaves nothing behind after the next start.
2. The `dns` service sends queries to the dane service's DNS rewriter
   (`127.0.0.1:15351`), with hnsd as `--fallback`: if the rewriter is down,
   DNS keeps working and DANE sites simply get their real address.
3. The rewriter answers A questions for Handshake names with a
   DNSSEC-validated TLSA record (usage 2 or 3) with the extra address, and
   AAAA, HTTPS and SVCB questions for them with no records. Everything else
   comes from hnsd unchanged. Rewritten answers never carry the AD flag.
4. The TLS front reads the name from the browser's ClientHello and hands the
   connection to the DANE proxy as a CONNECT, so the same DANE check and the
   same name-constrained CA apply. ICANN names are refused. The HTTP front
   redirects to `https://`.

The DANE proxy itself always resolves through hnsd directly
(`127.0.0.1:15350`), never through the rewriter.

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
- The `net` service is the only privileged part: root with `NET_ADMIN`,
  `NET_RAW` and `DAC_OVERRIDE`, and it does nothing until DANE without proxy
  settings is switched on. Its rules are tagged `dit-redirect` and only match
  the chosen extra address.
- **Never forward port 9053 either.** The DANE proxy refuses clients outside
  private, loopback and Tailscale ranges, but it is meant for your LAN. Its
  CA key stays in `data/dane/` (0600); the CA cannot sign ICANN names.

## hnsd patch

The image builds hnsd with unbound's `aggressive-nsec` turned off. hnsd
cannot prove that a single Handshake name is missing, so it answers with an
NSEC record that makes the whole root zone look empty (`. → .`, 24 hours).
With aggressive NSEC, on by default since unbound 1.15, unbound then denies
every Handshake name until that record expires. The proper fix upstream,
[handshake-org/hnsd#86](https://github.com/handshake-org/hnsd/pull/86), is
not merged. See `docker/Dockerfile`.

## Known limits

- DANE works in browsers that use the system proxy and trust user CAs
  (Chrome, Edge; Firefox with its own settings), not in most Android apps.
- No encrypted DNS (DoT/DoH) listeners yet. Android's Private DNS field needs
  a publicly trusted certificate, so remote use goes through Tailscale.
- dnsproxy talks to hnsd over UDP only (hnsd has no TCP listener). hnsd
  accepts answers up to 4096 bytes, which covers normal use.
- Ports 53, 5300, 9053, 9443, 9080, 15350 and 15351 are fixed in
  `docker-compose.yml`.
- DANE without proxy settings uses IPv4 only (AAAA answers for DANE names
  are empty) and needs a free address in the Umbrel's own subnet.
- Windows never sends single-word names (`mysite`) to DNS
  (`ERR_NAME_NOT_RESOLVED` in Chrome), so without the PAC file only names
  with a dot open there. With the PAC file the proxy resolves them itself.
  A trailing dot (`mysite.`) does reach DNS, but the DANE check then sees
  `mysite.` as a different name and closes the connection.
- Firefox needs DNS over HTTPS off and Dit's CA in its own store (or, on
  Android, "Use third party CA certificates" in its secret settings).
- No gallery screenshots yet (`gallery: []` in the manifest).

## Development

No npm dependencies. With Node 22+, an hnsd binary and a dnsproxy binary:

```sh
cd docker/web
npm test                       # DNS client and log filter unit tests

# DANE proxy (Go 1.26), or: docker run --rm -v "$PWD/../dane:/src" -w /src golang:1.26-alpine go test ./...
cd ../dane && go test ./...

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

On the Umbrel (v0.1.2): Handshake names resolve on port 53 and keep
resolving after lookups of missing names (the hnsd patch works); a PC and an
Android phone on the home Wi-Fi resolve Handshake names.

DANE proxy (v0.2, locally, image built with Docker, resolving through the
Umbrel): Go unit tests (TLD list, client check, PAC file, CA name
constraints: a leaf for `www.com` is rejected, one for `nathan.woodburn`
accepted); `nathan.woodburn` and `hnsdoh` load through the proxy with the
local CA (HTTP 200); without the CA the client rejects them; `example.com`
is tunnelled with its real certificate; the PAC file sends Handshake names to
the proxy and ICANN, special-use names and IPs direct.

On the Umbrel (v0.2.0): the DANE proxy serves the PAC file and CA,
`nathan.woodburn` and `hnsdoh` load through it; an Android phone with
Chrome opens DANE sites with the CA and the auto-config proxy.

DANE without proxy settings (v0.3, locally, in Docker: dns runner +
dnsproxy, dane and net services together, resolving through the Umbrel):
switched on and off through settings.json as the page saves it (address and
rules added and removed); DANE names answer the extra address, others are
unchanged; HTTPS to the extra address with no proxy setting returns 200 with
the Dit CA; an address another device uses is refused with a message; with
the rewriter killed, new names still resolve through the fallback; the
helper cleans up on SIGTERM and recovers after kill -9. Go tests cover the
rewriter against a fake hnsd; Node tests the address validation.

Not tested yet:

- DANE without proxy settings on a real Umbrel (a second address on wlan0,
  umbrelOS's firewall backend) and on a phone.
- AdGuard Home in front of Dit; Tailscale (not used by the maintainer).
- hnsd serving a whole network for days.

## Credits and licenses

- [hnsd](https://github.com/handshake-org/hnsd) (MIT), Handshake light client.
- [dnsproxy](https://github.com/AdguardTeam/dnsproxy) (Apache-2.0), AdGuard.
- IBM Plex fonts (SIL Open Font License), see `docker/web/public/fonts/OFL.txt`.

Dit itself is released under the MIT License, see `LICENSE`.
