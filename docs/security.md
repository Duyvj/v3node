# Security model

## Trust boundaries

The local configuration and panel are trusted control inputs. Panel responses
are still treated as untrusted bytes until size limits, JSON structure, node
ownership, protocol fields, filesystem paths, and engine validation all pass.
Customer traffic and source addresses are untrusted data-plane input.

The controller never executes a panel-provided command. Engine configuration is
written below the managed state directory and switched atomically. A candidate
must pass the engine's own configuration check before it can become active.

## Credentials

Use `panel.token_file` rather than embedding a token in `config.json`. The
recommended files are owned by `root:v3node`, with directory mode `0750` and
file mode `0640`. Do not pass the token on a command line or put it in a public
repository.

The legacy-compatible panel API requires the token as a query parameter. This
means HTTPS is mandatory in production and every error/log path must redact the
query string. `allow_insecure_http` exists only for isolated development
networks and defaults to false.

The sing-box Connections API has a separate random 256-bit bearer secret in
`/var/lib/v3node/api.secret` (mode `0600`). The controller creates it from the
OS random source on first check/run, persists it across generations, and sends
it as a bearer credential for Connections reads and closes. It is not the panel
token and must not be copied into panel configuration. Connections JSON is
stream-decoded under byte and item limits rather than decoded into an
unbounded generic object tree.

Both engines install early rules which reject ordinary VPN-user routes to the
configured Stats/Connections loopback addresses and ports, even if
`network.block_private` is disabled. Xray's unauthenticated Stats gRPC listener
therefore remains reachable only from the local service boundary under the
default direct/block/DNS routing policy. A panel-supplied custom Xray outbound
is trusted administrator configuration and can itself proxy or redirect toward
loopback, bypassing that route-layer guard; do not grant panel administration
to an untrusted party. Filesystem or local-user compromise remains outside the
service boundary and can expose either local management credential.

## Installer supply chain

`deploy/install.sh` uses only versioned GitHub release asset URLs. It does not
download from `main`, `master`, `latest`, or a raw branch URL. Every downloaded
controller or engine asset must match an embedded 64-character SHA256 before it
is extracted or executed.

The controller and project-built engine hashes remain explicit `UNPUBLISHED`
placeholders until the first release is built. The installer fails closed while
any required project-built hash is a placeholder. Local binaries/archives may
be supplied only with explicit SHA256 values. sing-box source is pinned to
version 1.13.18 and commit
`45ca32dcb966f07f97fc888fe8586e359dbe8405`; the project patchset is kept under
`engine-patches/sing-box/`, and the installer verifies that the engine reports
the required build tags. Stock Xray is pinned to v26.3.27 official amd64/arm64
ZIP assets with reviewed SHA256 values; the installer extracts only the expected
root executable and verifies its reported version.

Release maintainers should obtain upstream hashes independently, download each
asset again, compare its digest, and review the diff of both
`deploy/release-manifest.env` and the embedded constants in `install.sh`.
The project-built sing-box binary must be accompanied by exact, patched
Corresponding Source for the binary actually shipped: upstream source, all
linked module source, build/install scripts, patchset, license/notices/patent
files and source-to-binary hashes. The upstream license's final
naming/association condition must be preserved and reviewed before public
distribution. Xray distributions must preserve MPL-2.0 notices and identify a
timely source location for the exact version. See
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).

The sing-box source packager computes the dependency closure for the exact
Linux amd64/arm64 build tags and includes that source under `vendor/`. It then
rebuilds with `GOPROXY=off` and an empty module cache. Optional upstream modules
behind disabled tags are not linked and are not copied merely because they
appear in `go.mod`; `vendor/modules.txt` is the auditable package-to-module
manifest for the released binary.

## Service isolation

The supplied systemd unit applies an unprivileged service user, a minimal
capability set, read-only system directories, private devices and temporary
storage, namespace restrictions, kernel/control-group protection, native-only
syscalls, and IPv4/IPv6/Unix address-family restrictions. Writable locations
are limited to systemd-managed state and runtime directories.

The unit deliberately does not set `MemoryMax`. It enables accounting and
relies on bounded controller structures so normal concurrency is not killed by
a rigid cap. Operators can add a site-specific drop-in after load testing.

## Host changes

Installation does not alter sysctl, firewall, DNS, routes, congestion control,
swap, or kernel modules. The separate `v3node-tune` command only changes a
dedicated `/etc/sysctl.d/90-v3node.conf` after an operator runs
`v3node-tune apply`. It can remove that file and reapply the underlying host
configuration with `v3node-tune remove`.

The uninstaller removes only known managed executables and unit files by
default. Configuration, credentials, state, and tuning are retained unless the
operator explicitly requests their removal.

## Anti-GFW and traffic camouflage

No server configuration can guarantee that an address will never be detected
or blocked. Blocking also depends on the client fingerprint, the public port,
domain/SNI and certificate, the REALITY target, IP reputation, ASN and routing,
traffic patterns, and active probes. Keep tested replacement nodes and monitor
from inside the target network instead of treating one profile as permanent.

The controller fails closed before either engine sees malformed REALITY
secrets. The X25519 private key must be 32-byte raw URL-safe base64; short IDs
must be even-length hexadecimal values of at most 8 bytes and unique after zero
padding; server names cannot contain wildcards; and an optional ML-DSA-65 seed
must be a distinct 32-byte raw URL-safe base64 value. This also prevents Xray
v26.3.27 validation errors from echoing malformed private-key material into the
service journal. Apple and iCloud targets/server names are rejected because the
pinned Xray source explicitly warns that they can increase GFW blocking risk.

Both renderers apply a five-minute REALITY `maxTimeDiff` replay window. VPS and
client clocks therefore need working time synchronization. A deliberately empty
short ID remains compatible but emits a warning; a random non-empty value is
preferred. The pinned Xray source also warns when REALITY does not listen on
port 443. v3node reports this warning rather than rejecting it because a public
port 443 can legitimately be forwarded by NAT or a load balancer to a different
internal node port.

For a China-facing public node, the conservative starting profile is VLESS over
TCP/raw with REALITY on external port 443. `xtls-rprx-vision` is accepted only
with TCP/raw plus TLS/REALITY, or when VLESS Encryption is enabled. Choose a
REALITY target whose accepted SNI and certificate SAN match the panel values;
prefer a suitable target in the same ASN and test it with the pinned engine's
`xray tls ping <target>:443`. Do not enable fixed fallback rate limits merely as
camouflage: upstream notes that the limiter can itself become a fingerprint.
When enabling ML-DSA, verify the target certificate length and post-quantum
exchange support as required by the upstream REALITY documentation.

Certificate TLS has a minimum of TLS 1.2 on both renderers. A public CA
certificate and a coherent real web frontend are materially different from
`cert_mode=self`; the managed self-signed mode is intended for explicit private
trust and emits a public-listener warning. Likewise, `tls=1` with
`cert_mode=none` means that v3node itself is serving plaintext. It is safe only
when external TLS termination and network exposure have been independently
verified.

VLESS Encryption fields are validated against the pinned Xray grammar. Modes
are limited to `native`, `xorpub`, or `random`; padding tokens remain below the
length at which Xray reinterprets them as keys; padding byte totals, component
count, individual gaps, and total delay are bounded. Session tickets are
limited to one hour, which bounds retention time but not the number of entries
in Xray's upstream session map. A non-zero ticket therefore emits a warning;
use `0s` for the strongest RAM-stability profile because it disables retained
0-RTT session state. Use the paired values produced by `xray vlessenc`;
server-side changes cannot be made independently of subscription/client
settings.

Shadowsocks 2022 server keys are validated at their exact method length and the
`none` method is rejected. The per-user credential conversion remains identical
to the existing v2node/panel contract; changing it only on this server would
disconnect every generated client. Direct Shadowsocks traffic still lacks an
ordinary HTTPS appearance and should not be presented as an anti-blocking
guarantee. On the Xray backend, Shadowsocks UDP also does not inherit the TCP
transport's TLS/REALITY camouflage; v3node warns instead of silently disabling
UDP and changing the panel contract.

Inbound PROXY protocol is unauthenticated by design. When panel transport
settings enable it, v3node emits a warning; firewall the backend listener so
only the intended load balancer or reverse proxy can reach it. REALITY `xver`
is a separate target-side PROXY protocol setting and is likewise reported.

Xray v26.3.27 interprets `trustedXForwardedFor` entries as HTTP header names,
not CIDRs, and trusts all X-Forwarded-For values when the list is empty. v3node
therefore inserts an impossible header-name gate for WebSocket, HTTPUpgrade,
and XHTTP, and rejects panel CIDR values until a newer pinned Xray version is
separately audited. DNS queries from VPN users on both TCP and UDP port 53 are
intercepted. A matcherless panel resolver is marked `finalQuery` so a failure
does not silently fall back to another locality, but DNS policy still cannot
change the client fingerprint or prevent GFW classification.

uTLS fingerprint selection, TLS fragmentation, record fragmentation, and TLS
spoofing are client-side features. Adding those fields to an inbound would not
make clients use them. sing-box also cautions that uTLS imitation can itself be
fingerprinted. v3node deliberately leaves client fingerprint policy to the
panel subscription and compatible client application.
