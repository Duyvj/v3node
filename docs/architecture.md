# Architecture

v3node is a clean-room node controller. It implements the panel contract,
configuration lifecycle, resource accounting, and engine supervision. It does
not implement VPN cryptography. One controller process hosts up to 16 isolated
node workers; a separately supervised engine provides each worker's protocol
data plane.

## Components

1. Each worker's panel client retrieves node settings and users over HTTPS,
   with bounded response bodies, explicit timeouts, conditional requests, and
   retry jitter.
2. Each node worker has its own panel client and validates panel data into
   engine-neutral models. Invalid or incomplete updates never replace that
   worker's last working configuration.
3. An engine adapter renders a candidate configuration. The candidate is
   checked by the target engine before it can replace the active file.
4. The node's supervisor stops its current engine, switches the configuration
   atomically, starts the selected engine, and confirms readiness. A failed
   replacement restores and restarts the previous configuration. An accepted
   change can therefore make existing clients reconnect; zero-downtime handover
   is not claimed in the beta.
5. Traffic and online-IP collectors use bounded in-memory structures. Reports
   are acknowledged transactionally so a failed panel request does not silently
   discard counters.

sing-box V2Ray API counters are process-local. An engine reload can discard a
delta that has not yet been collected. The supplied systemd unit therefore has
no generic `ExecReload`/SIGHUP path. Engine replacement must be serialized with
the accounting collector, expose a generation boundary, and be covered by a
measured loss/reconciliation test before release. This upstream limitation is
tracked in [SagerNet/sing-box issue 4059](https://github.com/SagerNet/sing-box/issues/4059).

The data-plane adapters are the project build of sing-box 1.13.18 and stock
Xray 26.3.27. Both remain separate binaries, and only the adapter selected for
each node runs. In multi-node mode that means one engine process per active
node, while the Go controller process and systemd unit are shared. Per-node
engine processes preserve listener, user, traffic, device-policy and failure
boundaries; they also make engine RAM grow with the number and load of nodes.

The local `nodes` array is expanded before workers start. Every identity has a
stable name, state directory, Stats endpoint and authenticated Connections
endpoint. All workers' management addresses are protected in every rendered
data-plane configuration. A process-wide listener registry also rejects equal
numeric public ports, even if their protocols would otherwise use different
TCP/UDP sockets. Public listener ports are authoritative panel data, not local
installer options.

## Policy enforcement and connection inventory

Policy values are accepted only when the selected data plane can enforce them:

- on the project sing-box engine, `speed_limit > 0` creates one configured,
  shared upload/download token bucket for that user; the limiter map cannot
  grow beyond the accepted user list;
- a generation selected for stock Xray fails validation if any user has
  `speed_limit > 0` or `device_limit > 0`, because its Stats API exposes
  neither a per-user shaper nor authenticated source-IP information;
- on sing-box, the controller polls the authenticated Connections API about
  every five seconds, maps the engine username back to the panel user, tracks
  accepted source IPs in a bounded TTL/LRU set, and closes a connection whose
  new source IP would exceed the user's non-zero `device_limit`.

The sing-box check is deliberately described as an IP limit, not a physical
device limit. It takes effect after the next Connections poll, so it is not an
admission-time or instantaneous guarantee. The panel's
`device_online_min_traffic` threshold affects reporting only; even a
low-traffic accepted IP occupies a bounded local policy slot. Existing sessions
from an already accepted IP do not consume another slot. Every complete local
Connections snapshot removes disconnected IPs and refreshes active ones. When
panel-side alive counts are available, the controller subtracts the number of
IPs in this node's last successfully posted online set and combines the
remaining cross-node baseline with the authoritative local snapshot before
accepting a new IP. A failed close rolls back slots newly reserved during that
snapshot so the next poll retries against the live connection set. Failed
online payloads never advance the overlap state, and an alive-list value is
discarded after five minutes without a successful refresh rather than
retaining a stale cross-node lock forever.

The Connections response is decoded as a JSON stream with both item-count and
body-size limits. The resulting bounded snapshot still occupies memory in
proportion to the number of accepted connection records; streaming avoids an
additional whole-response object tree, not all snapshot allocation. Only the
first snapshot of a policy generation is sorted, so the oldest existing
sessions are seeded deterministically without paying the sort cost on every
poll.

Each Connections endpoint is loopback-only and protected by a persistent random
256-bit bearer secret generated under that node's state directory with mode
`0600`. It is separate from the panel token and from other nodes' secrets.
Traffic checkpoints, online-IP inventory and device-policy state are likewise
owned by one worker, so equal panel user IDs on two nodes do not share local
counters. VPN-user routes to every node's internal management endpoints are
rejected in every rendered configuration even when the operator permits other
private destinations.

Cross-node device enforcement still uses the panel's `alive` aggregate as an
eventual global baseline. Each worker subtracts only its own last successfully
posted online set before combining the remainder with its authoritative local
snapshot. There is no synchronous in-process admission lock shared by nodes;
the global result converges on subsequent panel poll/report cycles.

The sing-box upstream license states GPL version 3 or later and includes an
additional naming/association condition. Distributors must preserve that exact
license, publish the exact patched Corresponding Source (including linked Go
module source and build/install scripts), and comply with all applicable terms.
Xray is MPL-2.0 and is distributed unmodified, with its source location and
license notice. Keeping engines as external executables does not remove the
distributor's obligations for either engine. See
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).

## Memory model

There is no hard cgroup RAM limit in the supplied systemd unit. Hard limits can
terminate active sessions during a legitimate traffic spike. Stability instead
comes from bounded inputs and retained state:

- local configuration: 1 MiB maximum;
- panel node configuration: configurable, 2 MiB by default;
- panel user response: configurable, 32 MiB by default;
- users, retained traffic-counter entries, online IPs, and per-user IPs:
  explicit item-count bounds;
- Stats RPC response size: bounded by `max_stats_response_bytes` (64 MiB by
  default); panel report payload and small control responses are independently
  bounded by `max_panel_payload_bytes` (32 MiB by default);
- bounded retry/backoff rather than an unbounded retry queue;
- after the initial online-policy seed, sorting is limited to users with a
  non-zero device policy instead of copying/sorting every online IP each poll;
- an external engine process whose lifecycle can be observed and replaced;
- journald output instead of an application-owned, unbounded log file.

The controller's shared heap avoids repeating one Go process per node, but the
bounds above are applied to each independent worker where appropriate. Every
node still has an engine process and per-node users/connections/state, so total
memory is not constant as node count grows. No fixed RSS or completed 2/4/8-node
soak result is claimed by this design description.

The defaults target ordinary 2-4 GiB VPS nodes and remain configurable for
larger fleets. Raising bounds increases worst-case memory use and should be
validated with a representative user count.

Unless `GOMEMLIMIT` is already supplied by the operator, the controller sets a
soft Go heap target to roughly one sixteenth of memory available to the
service, clamped to 64-256 MiB. Detection uses the lower applicable cgroup
limit and physical memory, with `sysinfo(2)` as a fallback when the hardened
systemd profile hides `/proc/meminfo`. This controls controller GC pressure; it
is neither a hard process limit nor a cap on the separately running engine.

## Country-aware networking

Customer traffic is sent directly through the VPS network stack. Therefore the
public egress address remains the VPS address. Operator-supplied `dns_servers`
and `address_strategy` affect resolver choice and IPv4/IPv6 preference.

These settings can improve path consistency; they cannot change the country
that a third-party GeoIP or streaming database assigns to the public IP. There
is deliberately no no-op country or MTU switch in the local schema. A mismatch
must be fixed with the VPS provider and affected GeoIP vendors, or by replacing
the IP.

## Filesystem layout

| Path | Purpose |
| --- | --- |
| `/usr/local/bin/v3node` | controller executable |
| `/usr/local/lib/v3node/edge-engine` | pinned patched data-plane engine |
| `/usr/local/lib/v3node/xray` | pinned stock Xray engine |
| `/etc/v3node/config.json` | local controller configuration |
| `/etc/v3node/panel.token` | recommended panel token file |
| `/var/lib/v3node` | singleton/legacy state retained during safe migration |
| `/var/lib/v3node/nodes/<name>` | multi-node state, checkpoint, engine config and API secret |
| `/run/v3node` | process-local runtime data |

The service runs as the unprivileged `v3node` account. Only
`CAP_NET_BIND_SERVICE` is granted, allowing low listening ports without giving
the process full root privileges.
