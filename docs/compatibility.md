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

## Protocol and engine matrix

| Protocol | sing-box 1.13.12 project build | Stock Xray 26.3.27 |
| --- | --- | --- |
| VMess | beta | beta |
| VLESS | beta | beta |
| Trojan | beta | beta |
| Shadowsocks | beta (2022) | beta (legacy and AES-based 2022) |
| Hysteria2 | beta | not supported by this adapter |
| TUIC | beta | not supported by this adapter |
| AnyTLS | beta | not supported by this adapter |

The sing-box adapter accepts TCP/raw, WebSocket, gRPC, HTTPUpgrade and HTTP as
appropriate for the selected protocol. The Xray adapter accepts TCP/raw,
WebSocket, gRPC, HTTPUpgrade and XHTTP/SplitHTTP for VMess, VLESS and Trojan,
plus TCP/raw for Shadowsocks. `auto` selects Xray for XHTTP/SplitHTTP,
trusted X-Forwarded-For, legacy multi-user Shadowsocks, and panel rules that
reference Xray `geoip:`, `geosite:`, or `ext:` assets; it selects the lighter
project engine for Shadowsocks 2022 and the remaining supported nodes.
Panel settings that cannot be represented exactly are rejected
with a clear error and are never silently approximated.

TLS certificate files are operator-managed in this beta. When the panel omits
`cert_file` and `key_file`, the controller uses the conventional original
paths `/etc/v3node/<protocol><node-id>.cer` and `.key`; both files must already
exist and be readable by the `v3node` service account. Panel certificate modes
`dns`, `http`, and `self` are rejected explicitly because this controller does
not ingest DNS-provider secrets or run an unaudited ACME lifecycle. Reality
does not use these certificate files.

“Beta” means rendering has fixture coverage and representative configurations
have passed the pinned engine's configuration check. It is not a production
claim. Production gates still include live concurrent load, reconnect behavior,
long-running memory observation, and measured accounting across engine
replacement for each protocol/transport combination.

Per-user speed limits are parsed but this release has no audited data-plane
enforcement. A non-zero `speed_limit` therefore fails validation rather than
being silently ignored. Online-IP collection and device-limit closure use the
authenticated sing-box Connections API. Its random 256-bit bearer secret is
kept in `/var/lib/v3node/api.secret`, independently of the panel token. The
response is decoded as a bounded JSON stream, with limits on both bytes and
connection records.

On sing-box, a `device_limit` is an IP-based policy. About every five seconds,
the controller closes a connection from a newly observed source IP when that
IP would exceed the limit, after the connection passes the panel's
`device_online_min_traffic` threshold. Enforcement is consequently eventual,
not an admission-time guarantee, and multiple devices behind one NAT appear as
one IP. Stock Xray has no equivalent source-IP/user hook, so an Xray generation
containing a non-zero `device_limit` also fails validation. These are explicit
compatibility boundaries, not claims that unsupported limits were applied.
