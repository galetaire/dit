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

## State: v0.1.0 scaffold

- `server` service: Node web UI/API that starts and supervises hnsd
  (pinned commit 0cb70e5, checkpoint sync, saved headers). hnsd status comes
  from Hesiod TXT queries on 127.0.0.1:5349, which hnsd only answers from
  loopback; that is why hnsd shares the web container.
- `dns` service: host networking, Node runner supervising dnsproxy v0.86.0.
  Modes: auto / standalone (53 + 5300) / upstream (5300 only). Reason: Pi-hole,
  AdGuard Home and Tailscale all use host networking on Umbrel, and the first
  two bind port 53.
- UI: light purple palette, fingerprint icon, IBM Plex fonts.
- App id `dit-resolver`, store id `dit`, UI port 4748, image
  `ghcr.io/galetaire/dit`.

Tested locally: unit tests (`cd docker/web && npm test`), hnsd start-up and
status, mode switching, port-53-busy fallback, crash restart, shutdown.

Not tested: the Docker build (Alpine, amd64 + arm64), the GitHub workflow,
anything on a real Umbrel, a full header sync, real lookups.

## To do before first release

1. ~~Move `build-image.yml` from the repo root to `.github/workflows/`.~~ Done.
2. Push as `galetaire/dit`; build the image; make the ghcr package public.
3. Install from the community store on the Umbrel; watch the first sync
   (built-in checkpoint is height 136000, from 2022).
4. Check that umbrelOS leaves port 53 free with no other DNS app installed.
5. Test Android: Wi-Fi DNS pointed at the Umbrel, then Tailscale DNS.
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
