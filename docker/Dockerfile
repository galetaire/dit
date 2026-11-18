# ---- hnsd: the Handshake light client and recursive resolver ----
FROM alpine:3.20 AS hnsd
RUN apk add --no-cache build-base bash automake autoconf libtool unbound-dev git
# handshake-org/hnsd master, 2026-08-19 (checkpoint sync and saved headers)
ARG HNSD_COMMIT=0cb70e565b1b659bf85484e1a445825be306fda1
# Patch: turn off unbound's aggressive NSEC (on by default since unbound 1.15).
# hnsd proves a missing name with an NSEC record that covers the whole root
# zone (". -> .", resource.c hsk_resource_to_nx), so with aggressive NSEC one
# lookup of any missing name makes unbound deny every Handshake name for 24h.
# The proper fix, handshake-org/hnsd#86, is unmerged. The grep fails the build
# if the line moved upstream and the patch no longer applies.
RUN git clone https://github.com/handshake-org/hnsd.git /hnsd \
 && cd /hnsd && git checkout "$HNSD_COMMIT" \
 && sed -i 's|ub_ctx_set_option(ns->ub, "qname-minimisation:", "yes");|& ub_ctx_set_option(ns->ub, "aggressive-nsec:", "no");|' src/rs.c \
 && grep -q '"aggressive-nsec:", "no"' src/rs.c \
 && ./autogen.sh && ./configure && make

# ---- dnsproxy: the DNS front end (AdGuard, Apache-2.0) ----
FROM alpine:3.20 AS dnsproxy
ARG TARGETARCH
ARG DNSPROXY_VERSION=v0.86.0
RUN apk add --no-cache curl \
 && curl -fsSL "https://github.com/AdguardTeam/dnsproxy/releases/download/${DNSPROXY_VERSION}/dnsproxy-linux-${TARGETARCH}-${DNSPROXY_VERSION}.tar.gz" \
    | tar xz -C /tmp \
 && mv "/tmp/linux-${TARGETARCH}/dnsproxy" /dnsproxy

# ---- dit-dane: the DANE proxy (Go, built on letsdane, Apache-2.0) ----
FROM golang:1.26-alpine AS dane
WORKDIR /src
COPY dane/go.mod dane/go.sum ./
RUN go mod download
COPY dane/ ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /dit-dane .
# IANA's list of ICANN top-level domains, fresh at every build: these names go
# direct (not through the proxy) and the local CA can never sign them.
# The count check stops a truncated download from weakening the CA.
RUN wget -qO /icann-tlds.txt https://data.iana.org/TLD/tlds-alpha-by-domain.txt \
 && test "$(grep -vc '^#' /icann-tlds.txt)" -gt 1000

# ---- Dit ----
FROM node:22-alpine

# unbound-libs: hnsd's resolver; su-exec drops root after fixing ownership
RUN apk add --no-cache unbound-libs su-exec tini

COPY --from=hnsd /hnsd/hnsd /usr/local/bin/hnsd
COPY --from=dnsproxy /dnsproxy /usr/local/bin/dnsproxy
COPY --from=dane /dit-dane /usr/local/bin/dit-dane

# Dit has no npm dependencies, only Node's standard library
COPY web /opt/dit
COPY --from=dane /icann-tlds.txt /opt/dit/icann-tlds.txt
RUN chmod 755 /opt/dit/entrypoint.sh

ENV NODE_ENV=production \
    PORT=3000 \
    DIT_DATA=/data

EXPOSE 3000
VOLUME /data

# The entrypoint starts as root to fix /data ownership, then runs Dit as
# uid/gid 1000 (the node image's "node" user, like Umbrel's app data).
# The "dns" service in docker-compose.yml overrides both lines.
ENTRYPOINT ["/sbin/tini", "--", "/opt/dit/entrypoint.sh"]
CMD ["node", "/opt/dit/server.js"]
