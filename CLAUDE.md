# Dit: project context

Handoff notes from the design conversation (16 Nov 2026). Read README.md for
the architecture; this file records decisions, state and next steps.

## What this is

Dit is an umbrelOS community app by galetaire: a Handshake (HNS) resolver for
the home network. Goal: resolve Handshake names on every device, in particular
an Android phone, self-hosted, the way Fingertip-dit
(github.com/galetaire/fingertip-dit) does on a desktop. Sibling apps:
Bob DNS (galetaire/bob-dns), Finestra (galetaire/finestra), Castell
(galetaire/castell). Target hardware includes a Raspberry Pi 4 (arm64).

Conventions follow Castell: one image built from `docker/`, a dependency-free
Node 22 server, `lib/source.js` request-source check, an `X-Dit` header on
state-changing requests, multi-arch GitHub workflow, image tag = app version.

## State: v0.6.0

- `server` service: Node web UI/API that starts and supervises hnsd
  (pinned commit 0cb70e5, checkpoint sync, saved headers). hnsd status comes
  from Hesiod TXT queries on 127.0.0.1:5349, which hnsd only answers from
  loopback; that is why hnsd shares the web container.
- `dns` service: host networking, Node runner supervising dnsproxy v0.86.0.
  Modes: auto / standalone (53 + 5300) / upstream (5300 only). Reason: Pi-hole,
  AdGuard Home and Tailscale all use host networking on Umbrel, and the first
  two bind port 53.
- UI (0.1.2): Castell's layout (dark sidebar with nav, status panel and
  theme toggle; pages #/, #/setup, #/mode, #/log as sections of index.html
  shown by hash). Colours from the logo (19 Nov 2026): brand teal #31C4A1,
  light-mode buttons/links in deeper teal #177D66 (white text 5:1; #31C4A1
  with white text is only ~2.2:1), dark-mode accent #31C4A1 with dark text,
  sidebar in the logo's navy (#1A2338 light, #0C1220 dark). Light/dark
  via data-theme on <html>, set by `public/theme.js` (CSP forbids inline
  scripts): saved choice (`dit-theme` in localStorage), else system setting.
  Logo: `dit-resolver/dit.png` (2383 px, store icon) is the source;
  `docker/web/public/icon.png` is a 256 px copy of it. IBM Plex fonts. Local preview: `.claude/launch.json`
  ("dit-ui", hnsd disabled, data in gitignored `.dev-data/`).
- App id `dit-resolver`, store id `dit`, UI port 4748, image
  `ghcr.io/galetaire/dit`.

- hnsd is patched at build time (Dockerfile): unbound `aggressive-nsec: no`.
  hnsd answers every missing name with an NSEC `. → .` (whole root zone
  empty, TTL 86400); with aggressive NSEC (unbound >= 1.15 default) one such
  answer made unbound deny all Handshake names for 24h. Found on the Umbrel
  17 Nov 2026. Upstream fix handshake-org/hnsd#86 unmerged since 2022.
- The hnsd log on the status page filters out Dit's own Hesiod status
  queries (they filled the 300-line buffer).

Tested: unit tests (`cd docker/web && npm test`); on the Umbrel (Pi,
v0.1.0): image build amd64 + arm64, install, header sync, Pi-hole holding
port 53 (auto fell back to upstream), standalone on 53 after removing it.

## To do before first release

1. ~~Move `build-image.yml` from the repo root to `.github/workflows/`.~~ Done.
2. ~~Push as `galetaire/dit`; build the image; make the ghcr package public.~~ Done.
3. ~~Install from the community store on the Umbrel; watch the first sync.~~
   Done. 0.1.2 installed 17 Nov 2026: Handshake names resolve on port 53
   (woodburn, nathan.woodburn, nb, c, AD flag set) and keep resolving after
   lookups of missing names, so the aggressive-NSEC patch works.
4. ~~Check port 53.~~ Pi-hole was installed and held it; user removed it.
   That showed "Automatic" never re-checked port 53. Fixed in 0.1.3: the runner probes port 53 every 30 s while on 5300 only;
   standalone takes it when free, auto only sets `mainPortFree` and the
   Overview page offers "Use port 53" (re-saves auto, which now forgets
   the remembered decision). Auto never takes it alone: Pi-hole may only be
   restarting. Simulated locally with a fake dnsproxy; not run on the Umbrel.
5. Test Android: ~~Wi-Fi DNS pointed at the Umbrel~~ (works on PC and
   phone, router DNS = Umbrel, 17 Nov 2026). Tailscale DNS: dropped, the
   owner doesn't use Tailscale. The setup guide stays in the app for other
   users, untested.
6. ~~Add a LICENSE~~ (MIT, done) and gallery screenshots (`gallery: []` in
   the manifest).

## Roadmap

- v0.2 DONE (0.2.0 on the Umbrel 17 Nov 2026: proxy on 9053, PAC names
  192.168.1.27:9053, nathan.woodburn and hnsdoh load with the CA; Android
  phone with Chrome, CA installed and Wi-Fi proxy on auto-config, works.
  The Umbrel has a fixed address, 192.168.1.27, reserved in the router,
  which hands it out as the only DNS server): DANE validation
  at home. `dane` service = docker/dane (Go 1.26, letsdane v0.6.1 as a
  library, deps upgraded, govulncheck clean), port 9053 host network, PAC +
  CA served by the proxy itself, Secure sites page in the UI (#/dane).
  Tested locally against the Umbrel's resolver: DANE sites load with the CA.
  Originally: letsdane proxy on the Umbrel, PAC file, a
  local CA to install per device. Android limits: proxy settings exist only
  per Wi-Fi network; Chrome trusts user CAs, most apps do not.
  Design notes (17 Nov 2026), modelled on Fingertip
  (~/Fingertip-dit/third_party/fingertip, internal/config):
  - letsdane (buffrr/letsdane, Apache-2.0) is quiet: last commit Feb 2024,
    last release v0.5.0 (2020, no binaries). Fingertip uses tag v0.6.1 as a
    Go library. Plan: a small Go program in docker/ built in the image,
    importing letsdane v0.6.1, resolver = Dit's dnsproxy (AD bit needed).
  - CA: letsdane.NewAuthority with name constraints that EXCLUDE every ICANN
    TLD, so a leaked Umbrel CA cannot sign gmail.com etc. Fingertip's list
    (tld.go) is from 2020: regenerate from
    https://data.iana.org/TLD/tlds-alpha-by-domain.txt at image build time.
    Fingertip settings: SkipNameChecks=false, Validity=1h.
  - PAC: everything except ICANN TLDs and IP literals goes to the proxy
    (Fingertip's getPACScript). Must be reachable WITHOUT the Umbrel login,
    so the proxy serves /proxy.pac and the CA download itself (letsdane's
    ContentHandler), not the Dit web UI behind app_proxy.
  - Proxy port on the host network, LAN only; same rule as port 53: never
    forward it from the router.
- v0.3 "DANE without proxy settings": built, shipped as 0.3.0-0.3.2 and
  REMOVED in 0.4.0 (see Decisions). Kept here so it is not rebuilt blindly.
  How it worked: a privileged "net" service added an extra LAN address
  (192.168.1.200 on wlan0) plus nat REDIRECT rules (443 -> 9443, 80 -> 9080);
  a DNS rewriter answered DANE names with that address; an SNI front handed
  connections to the v0.2 proxy as CONNECT. It worked on the Umbrel and on
  Android (Chrome; Firefox with "Use third party CA certificates").
  Lessons that still apply:
  - umbrelOS "Local HTTPS" answers port 443 on every Umbrel address for
    every SNI ("Umbrel Local HTTPS CA"): Dit cannot use host port 443.
  - Windows never sends single-word names to DNS (ERR_NAME_NOT_RESOLVED);
    only the PAC proxy makes them work on Windows.
  - Desktop browsers often use their own secure DNS (Brave by default), which
    skips Dit; the PAC proxy works regardless.
  - Firefox on Android needs "Use third party CA certificates" (secret
    settings) to trust Dit's CA; Firefox needs DNS over HTTPS off.
  - A trailing dot (mysite.) reaches DNS on Windows but letsdane closes the
    connection: SNI "mysite." != TLSA domain "mysite".

## Decisions already made

- DANE without proxy settings (v0.3) was removed in 0.4.0 at the owner's
  request (18 Nov 2026): it only saved one Wi-Fi proxy setting on phones,
  computers needed the PAC anyway, and it cost a root service with
  NET_ADMIN, an extra LAN address, firewall rules and a DNS rewriter. The
  auto-config proxy (v0.2) is the one way to get DANE. 0.4.0 checked on the
  Umbrel (18 Nov 2026): .200 gone, real DNS answers, 9443/9080 closed, PAC
  served, nathan.woodburn and hnsdoh load through the proxy.

- SANE / stateless DANE (randomlogin/sane, htools-org/stateless-dane) was
  evaluated and rejected for this app: no fallback to plain DANE, so sites
  without proof-carrying certificates fail; unmaintained since 2024; adds
  nothing when the proxy trusts a resolver on the same Umbrel. Possible later
  as a Castell feature (needs RSA keys, `delv`, weekly reissue, a full node).
  Revisited 19-20 Nov 2026: the owner wanted it as a beta, built as an
  opt-in checker only (v0.5.0), browsing unchanged.
- No DoT/DoH listeners in v0.1: Android Private DNS needs a publicly trusted
  certificate; remote use goes through Tailscale.
- dnsproxy has no client allowlist: never forward port 53 from the router.

## Stateless DANE checker (beta), built 20 Nov 2026 (v0.5.0)

Phase 1 of HIP-17 support: a "Stateless DANE (beta)" card on the Secure sites
page (#/dane). See README "Stateless DANE checker (beta)" for the design.
- Go (docker/dane): `urkel.go` (own MIT port of handshake-org/urkel's proof
  verifier; nodech/go-hsd-utils was NOT used: it has no license), `hns.go`
  (NameState name/resource, DS from hsd resource records), `dnssecchain.go`
  (RFC 9102-style chain: skip 4 bytes, wire RRs; trust only the on-chain DS),
  `check.go` (`dit-dane check -name`, JSON steps). Tests use real proofs in
  testdata/ with a fixed date (proofDay, 20 Nov 2026).
- Node: `lib/treeroots.js` collects roots from hnsd output (fed in
  lib/hnsd.js), `data/tree-roots.json`, 16 days kept; server.js
  `POST /api/sane-check` runs the Go checker (one at a time, 45 s) and adds
  a "live" step comparing with hnsd's own TLSA answer.
- Facts learned: proof services anchor to the root from ~8 days ago (HIP-17's
  32nd most recent), so a 7-day window would fail; services answer HTTP 500
  for names without TLSA (humbly). SANE's reference sites (htools/,
  test.lazydane/) fail every TLS handshake.
- Tested in Docker with the real image and a real hnsd (synced to 356629 in
  ~70 s, 64 roots). On the Umbrel (21 Nov 2026, v0.5.0): 64 roots, newest
  block 356617; nathan.woodburn and hnsdoh VERIFIED in all 8 steps (root
  0e7787ce… from block 355465).
- v0.6.0 (21 Nov 2026): the checker reads the proofs from the site's own
  certificate first (`sitecert.go`: address via hnsd, `-resolver` from
  server.js; OIDs 1.3.6.1.4.1.54392.5.1620/1621), falls back to the proof
  services, and adds a "key" step: the served certificate must match a proven
  TLSA (usage 3, or 2 on the chain), which stops proof replay on another
  server. belikebill (Castell 0.4.0 with proofs turned on) VERIFIED from its
  own certificate; services give HTTP 500 for it. Tested natively on Windows
  (dit-dane.exe, resolver 192.168.1.27:53): Docker Desktop routes container
  HTTPS through Windows' PAC = Dit's own proxy, so containers saw Dit-signed
  certs (key step rejected them, correctly). Not yet run on the Umbrel.
- Still open: verifying certificate proofs inside the DANE proxy while
  browsing; HIP-17 extension OIDs are still "TBD" in the spec.

## Spin-off: fingertip-android

Away-from-home DANE on the phone moved to its own project,
~/Documents/GitHub/fingertip-android (Android app: a VPN that only sets a
system proxy, then letsdane via gomobile). Its CLAUDE.md has the full
handoff; work on it there, not in this repo.

## Other ideas parked

An "identity on your name" app (Lightning address, Nostr NIP-05, HIP-2,
OpenPGP, SSHFP), an authoritative nameserver app, a name-expiry watchdog.
