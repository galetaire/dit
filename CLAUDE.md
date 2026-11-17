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

## State: v0.1.3

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

- v0.2: DANE validation at home. letsdane proxy on the Umbrel, PAC file, a
  local CA to install per device. Android limits: proxy settings exist only
  per Wi-Fi network; Chrome trusts user CAs, most apps do not.
- v0.3: DANE everywhere through DNS redirection (resolver answers with the
  Umbrel's address for Handshake names with TLSA, Umbrel re-signs with the
  local CA). Blocker to prototype: umbrelOS uses host port 443.

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
