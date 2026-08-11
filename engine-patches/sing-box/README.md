# v3node edge engine

The controller uses sing-box as a separate data-plane process. Official
v1.13.18 binaries omit the V2Ray statistics API, so v3node publishes a
separate GPLv3 engine build with:

- upstream commit `45ca32dcb966f07f97fc888fe8586e359dbe8405`;
- the documented `with_v2ray_api`, QUIC, gRPC, Clash API and uTLS/Reality tags;
- one observable patch exposing the already authenticated user name in the
  loopback Clash `/connections` response;
- one bounded per-user token-bucket tracker used only when the controller
  renders a non-zero `speed_limit`.

The patches do not alter authentication, encryption or cryptography. The rate
tracker wraps authenticated TCP/UDP data after routing, shares one bucket per
configured user across all sessions and directions, and never creates entries
from connection churn. The controller remains a separate program and does not
link to sing-box.

This directory is not licensed under the controller's root Apache-2.0 grant.
The patches are distributed under the same terms that apply to the upstream
sing-box derivative. Preserve [`UPSTREAM_LICENSE`](UPSTREAM_LICENSE) verbatim,
including its final naming/association condition.

A binary release must include an exact Corresponding Source archive for the
binary actually shipped. That archive includes the fully patched upstream tree,
all Go module source linked into the binary (vendored for offline availability),
license/notice/patent files, `go.mod`, `go.sum`, both patches, build tags, build and
installation scripts, and hashes mapping source to every binary architecture.
Publishing only the upstream URL plus these patches is not the complete release
procedure. See [`THIRD_PARTY_NOTICES.md`](../../THIRD_PARTY_NOTICES.md) and the
full [`GPL-3.0.txt`](../../LICENSES/GPL-3.0.txt) before distribution.
