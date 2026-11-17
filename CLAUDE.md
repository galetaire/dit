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

## State: v0.3.1

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
  shown by hash) with a violet accent instead of Castell's rust. Light/dark
  via data-theme on <html>, set by `public/theme.js` (CSP forbids inline
  scripts): saved choice (`dit-theme` in localStorage), else system setting.
  Fingerprint icon, IBM Plex fonts. Local preview: `.claude/launch.json`
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
- v0.3: DANE everywhere through DNS redirection (resolver answers with the
  Umbrel's address for Handshake names with TLSA, Umbrel re-signs with the
  local CA). Blocker to prototype: umbrelOS uses host port 443.
  Built as 0.3.0 (17 Nov 2026, opt-in "Without proxy settings (beta)" card on
  the Secure sites page; settings.json redirect {enabled, ip, savedAt},
  separate from the mode's savedAt so Automatic keeps its decision). The
  shell helper became "dit-dane net" (netsetup.go, net service, state in
  net-state.json); rewriter + fronts always run, rewrite only while on; dns
  runner switches upstream to the rewriter with hnsd as --fallback; the v0.2
  proxy now resolves via hnsd 127.0.0.1:15350. E2E-tested in Docker with
  all services. On the Umbrel (17 Nov 2026, extra address 192.168.1.200 on
  wlan0, net-state active): DANE names answer .200, AAAA empty, others
  unchanged; HTTPS to .200 with no proxy: nathan.woodburn and hnsdoh 200;
  http -> 301 https; umbrelOS's own 443 on .27 untouched. Phone without the
  proxy setting: not yet tested. Windows PC (headless Chrome, user's CA in
  CurrentUser\Root): nathan.woodburn loads with no proxy; single-word names
  (hnsdoh, woodburn) give ERR_NAME_NOT_RESOLVED because Windows never sends
  single-label names to DNS; with the PAC script set they load. Trailing dot
  (hnsdoh.) resolves but letsdane closes: SNI "hnsdoh." != TLSA domain.
  woodburn's own nginx returns 502 (site down, not Dit). The Secure sites
  page now says to keep the PAC script on Windows and has a Firefox card
  (DoH off, CA trust), released as 0.3.1. Prototype notes:
  - Blocker confirmed: umbrelOS "Local HTTPS" answers 443 on every Umbrel
    address for every SNI ("Umbrel Local HTTPS CA").
  - Way around: a second LAN address for Dit. docker/dane/dit-net.sh (host
    network, NET_ADMIN + NET_RAW) adds DIT_REDIRECT_IP to the interface
    (ARP duplicate check, refuses lo) and two nat PREROUTING REDIRECT rules
    tagged "dit-redirect": IP:443 -> 9443, IP:80 -> 9080. Removes them on
    SIGTERM; survives kill -9 + restart without duplicates.
  - docker/dane/redirect.go (on when DIT_REDIRECT_IP is set): DNS rewriter
    on 127.0.0.1:15351 (A -> DIT_REDIRECT_IP, AAAA/HTTPS/SVCB -> no records
    for names with AD-validated TLSA usage 2/3; everything else passed
    through from DIT_REWRITE_UPSTREAM); SNI front on 9443 that hands the
    connection to the v0.2 proxy as a CONNECT (same DANE check, same CA);
    HTTP 9080 -> 301 https.
  - Tested in Docker with a simulated Umbrel resolving through the real one:
    rewrite correct (DANE names -> alias, humbly/ICANN untouched), HTTPS
    to the alias with no proxy setting: nathan.woodburn HTTP/2 200 with the
    Dit CA, hnsdoh 200, untrusted without the CA, ICANN SNI refused.
  - To ship: dns service upstream 127.0.0.1:15351 with dnsproxy --fallback
    127.0.0.1:15350 (DNS keeps working if dane dies); the v0.2 proxy must
    resolve via hnsd directly (127.0.0.1:15350), else it would loop into the
    alias; a privileged "net" service in compose; a UI setting to pick the
    address (outside the DHCP range, here .200-.254) and switch it on.
    Unknowns on the Umbrel: iptables backend, a second address on wlan0,
    whether NET_ADMIN is acceptable for the community store (Tailscale uses
    it).

## Decisions already made

- SANE / stateless DANE (randomlogin/sane, htools-org/stateless-dane) was
  evaluated and rejected for this app: no fallback to plain DANE, so sites
  without proof-carrying certificates fail; unmaintained since 2024; adds
  nothing when the proxy trusts a resolver on the same Umbrel. Possible later
  as a Castell feature (needs RSA keys, `delv`, weekly reissue, a full node).
- No DoT/DoH listeners in v0.1: Android Private DNS needs a publicly trusted
  certificate; remote use goes through Tailscale.
- dnsproxy has no client allowlist: never forward port 53 from the router.

## Other ideas parked

An "identity on your name" app (Lightning address, Nostr NIP-05, HIP-2,
OpenPGP, SSHFP), an authoritative nameserver app, a name-expiry watchdog.
