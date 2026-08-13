# Compatibility

## Host support

The deployment scripts support:

| Distribution | Minimum version | Architectures |
| --- | ---: | --- |
| Debian | 12 | amd64, arm64 |
| Ubuntu | 22.04 | amd64, arm64 |

systemd is required. Containers must provide a working systemd instance and the
capabilities needed to bind the configured ports. Transparent proxy/TUN routing
is not part of the base node profile and would require a separate security and
capability design.

## Panel contract

For compatibility with the current V2Board/v2node-style panel, every request
uses `node_type=v2node`, `node_id=<positive integer>`, and the API token. The
implemented contract targets these endpoints:

| Method | Endpoint | Purpose |
| --- | --- | --- |
| GET | `/api/v2/server/config` | node configuration |
| GET | `/api/v1/server/UniProxy/user` | assigned users |
| GET | `/api/v1/server/UniProxy/alivelist` | requested online report set |
| POST | `/api/v1/server/UniProxy/push` | upload/download counters |
| POST | `/api/v1/server/UniProxy/alive` | per-user online IPs |

User records contain `id`, `uuid`, `speed_limit`, and `device_limit`. Traffic is
reported as `{userID: [uploadBytes, downloadBytes]}` and online clients as
`{userID: [ip, ...]}`. Response-size and item-count bounds apply before data is
accepted.

The per-user device policy always comes from the panel's `device_limit` field;
`runtime.max_ips_per_user` is only a local memory-safety ceiling and never
replaces the panel value. The default ceiling is 1,024 IPs per user, allocated
lazily under the separate global online-IP bound.

The legacy singleton `{ "panel": ... }` configuration remains supported. A
multi-node installation instead uses up to 16 `nodes` entries. Native names
are `api_host`, `node_id`, `token_file`, and `timeout`; the parser also accepts
the original v2node spellings `ApiHost`, `NodeID`, `ApiKey`, and `Timeout`.
Installer/generator use of repeated `--node-id` is preferred because it writes
stable, non-overlapping state and loopback management endpoints from the
canonical panel identity plus NodeID automatically.
Legacy runtime metadata that predates persisted listener identity is not
started as last-known-good inside a multi-node process; the worker waits for a
fresh panel synchronization so it can reserve the correct public port first.
The singleton upgrade path keeps its version-2 last-known-good behavior.

## Protocol and engine matrix

| Protocol | sing-box 1.13.18 project build | Stock Xray 26.3.27 |
| --- | --- | --- |
| VMess | beta | beta |
| VLESS | beta | beta |
| Trojan | beta | beta |
| Shadowsocks | beta (legacy and 2022) | beta (legacy and AES-based 2022) |
| Hysteria2 | beta | not supported by this adapter |
| TUIC | beta | not supported by this adapter |
| AnyTLS | beta | not supported by this adapter |

The sing-box adapter accepts TCP/raw, WebSocket, gRPC, HTTPUpgrade and HTTP as
appropriate for the selected protocol. The Xray adapter accepts TCP/raw,
WebSocket, gRPC, HTTPUpgrade and XHTTP/SplitHTTP for VMess, VLESS and Trojan,
plus TCP/raw for Shadowsocks. `auto` selects Xray for XHTTP/SplitHTTP,
Shadowsocks TCP transport security, transport/settings that sing-box cannot represent,
and panel rules that reference Xray `geoip:`, `geosite:`, or `ext:` assets; it
selects the lighter project engine for Shadowsocks and the remaining supported
nodes.
Panel settings that cannot be represented exactly are rejected
with a clear error and are never silently approximated.

The pinned Xray v26.3.27 treats `trustedXForwardedFor` values as HTTP header
names rather than CIDRs and trusts X-Forwarded-For unconditionally when the
list is empty. v3node disables that implicit trust on WebSocket, HTTPUpgrade,
and XHTTP, and rejects non-empty panel CIDR values until a newer engine version
is pinned and tested. These values are not silently rendered with different
semantics.

TLS `file` certificates are operator-managed. When the panel omits `cert_file`
and `key_file`, the controller uses `/etc/v3node/<protocol><node-id>.cer` and
`.key` for a singleton, or the node's `/etc/v3node/nodes/<name>/` directory in
multi-node mode; both files must already exist and be readable by the `v3node`
service account. `cert_mode=self` creates a private ECDSA pair below that node's
state-directory `certificates/` subdirectory as a bounded reconciliation step.
`dns` and `http` remain explicitly rejected because this controller does not ingest
DNS-provider secrets or keep an ACME client resident. `tls=1` with an empty or
`none` certificate mode means external TLS termination, matching the original
panel contract. Reality does not use certificate files.

Certificate TLS has a minimum version of TLS 1.2 on both engines. REALITY
private keys, ML-DSA seeds, short IDs, server names, destination syntax and
obvious listener loops are validated before an engine configuration is written.
Both engines use a five-minute REALITY clock-difference window. The service
emits an operational warning for a non-443 REALITY node port because external
443-to-backend forwarding cannot be inferred from the panel response.

Panel custom outbound actions `route`, `route_ip`, and `default_out` select
Xray. Their JSON is capped at 256 KiB, accepts only reviewed outbound fields,
rejects protected/invalid tags and rejects conflicting duplicate definitions.
The sing-box adapter fails closed for these Xray-specific actions.

Both renderers intercept inbound client TCP/UDP port 53 and route it through the
engine's configured DNS stack, matching the original node's resolver behavior.

VLESS Encryption supports the pinned Xray `mlkem768x25519plus` grammar. Its
mode, ticket, padding and canonical authentication key are checked before
rendering. Padding components and delays are bounded. Ticket lifetime is capped
at one hour to bound retention time, but the pinned Xray session map has no
cardinality cap; `v3node check` warns for non-zero tickets and `0s` is the
RAM-stable profile.
`xtls-rprx-vision` is rejected outside TCP/raw plus TLS/REALITY unless VLESS
Encryption is active. Shadowsocks 2022 server keys must decode to the exact key
length required by the selected method.

The sing-box VMess, VLESS, Trojan and Shadowsocks inbounds accept multiplexed
clients explicitly because sing-box no longer enables inbound multiplex support
by default. v3node does not force clients to multiplex and does not require mux
padding, preserving non-multiplexed client compatibility.

“Beta” means rendering has fixture coverage and representative configurations
have passed the pinned engine's configuration check. It is not a production
claim. Production gates still include live concurrent load, reconnect behavior,
long-running memory observation, and measured accounting across engine
replacement for each protocol/transport combination.

On the project sing-box engine, `speed_limit` is enforced by one shared token
bucket per configured user across upload, download and all concurrent TCP/UDP
sessions. Only users with a non-zero limit allocate a bucket, and the immutable
map is bounded by `runtime.max_users`; connection churn cannot add entries.
Stock Xray has no equivalent audited hook, so a generation that requires Xray
and contains a non-zero speed limit fails validation. Online-IP collection and
device-limit closure use the authenticated sing-box Connections API. Its random
256-bit bearer secret is kept in `/var/lib/v3node/api.secret`, independently of
the panel token. The response is decoded as a bounded JSON stream, with limits
on both bytes and connection records.

On sing-box, a `device_limit` is an IP-based policy. About every five seconds,
the controller closes a connection from a newly observed source IP when that
IP would exceed the limit. `device_online_min_traffic` controls when an accepted
IP becomes reportable to the panel, not whether it occupies a local policy
slot. Each complete Connections snapshot also removes locally disconnected
IPs, so they normally release a slot on the next poll instead of waiting for
`online_ip_ttl`. The panel `alive` aggregate is used as a cross-node baseline
after subtracting the number of IPs in this node's last successfully posted
online set. A failed POST does not change that overlap; alive counts expire
locally after five minutes without a successful refresh. If a close fails,
newly reserved replacement slots from that snapshot are rolled back and
retried from the next live snapshot. Enforcement is consequently eventual, not an
admission-time guarantee, and multiple devices behind one NAT appear as one
IP. Stock Xray has no
equivalent source-IP/user hook, so an Xray generation
containing a non-zero `device_limit` also fails validation. These are explicit
compatibility boundaries, not claims that unsupported limits were applied.

Multi-node mode keeps one systemd service and one Go controller process, but
creates an isolated panel client, controller, engine process, state directory,
traffic checkpoint, API secret, Stats endpoint, and Connections endpoint for
each node. Equal user IDs on different nodes therefore do not merge local
traffic or device state. Device limits across nodes still use the panel
`alive` aggregate as an eventual baseline; they are not a synchronous global
admission lock.

Every node's public VPN listener port comes from its panel response. All nodes
on the VPS must use different numeric ports, including TCP versus UDP; startup
validation also rejects a public port matching any node's internal management
port. The per-node engine model preserves panel
semantics but consumes engine memory for every node, so multi-node RSS depends
on node count and workload. Long-running 2/4/8-node load and accounting soak
remain release gates rather than completed compatibility claims.
