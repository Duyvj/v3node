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

Both engines always reject VPN-user routes to the configured
Stats/Connections loopback addresses and ports, even if
`network.block_private` is disabled. Xray's unauthenticated Stats gRPC listener
therefore remains reachable only from the local service boundary. Filesystem
or local-user compromise remains outside that boundary and can expose either
local management credential.

## Installer supply chain

`deploy/install.sh` uses only versioned GitHub release asset URLs. It does not
download from `main`, `master`, `latest`, or a raw branch URL. Every downloaded
controller or engine asset must match an embedded 64-character SHA256 before it
is extracted or executed.

The controller and project-built engine hashes remain explicit `UNPUBLISHED`
placeholders until the first release is built. The installer fails closed while
any required project-built hash is a placeholder. Local binaries/archives may
be supplied only with explicit SHA256 values. sing-box source is pinned to
version 1.13.12 and commit
`1086ab2563320e0da0c23b3a491d8dfa0939dff4`; the project patchset is kept under
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
