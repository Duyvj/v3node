# Deployment

## Release state

The development-branch installer is intentionally locked: controller and
required-feature sing-box checksums remain placeholders, so a raw branch script
exits before changing the host. Release assembly replaces those values only in
the tagged installer artifact after building and reviewing amd64/arm64 assets.
The stock Xray archives are separately pinned to their official versioned
upstream assets and reviewed SHA256 values.

For a fully local test build, supply all binaries/archives and their digests
explicitly:

```bash
sha256sum ./v3node-linux-amd64
sha256sum ./v3node-edge-1.13.12-p2-linux-amd64
sha256sum ./Xray-linux-64.zip
sudo ./deploy/install.sh \
  --v3node-file ./v3node-linux-amd64 \
  --v3node-sha256 '<64-character digest>' \
  --sing-box-file ./v3node-edge-1.13.12-p2-linux-amd64 \
  --sing-box-sha256 '<64-character digest>' \
  --xray-archive ./Xray-linux-64.zip \
  --xray-sha256 '<64-character digest>' \
  --no-start
```

The generic upstream sing-box 1.13.12 Linux assets do not include the
`with_v2ray_api` build tag required for per-user accounting. The authoritative
source pin, source checksum, small authenticated-user metadata patch, and build
instructions live in `engine-patches/sing-box/`. The project engine uses
`with_quic`, `with_grpc`, `with_v2ray_api`, `with_clash_api`, and `with_utls`.
For a published v3node release, the installer downloads these versioned
sing-box assets from the same release and verifies their SHA256 plus reported
version, architecture, and build tags. It also downloads the pinned official
Xray 26.3.27 archive, verifies its SHA256 and reported version, and installs the
root `xray` executable, GeoIP/GeoSite data and license from that reviewed
archive. At runtime only the engine selected for the current node is started.

## Clean VPS installation

A supported clean VPS does not need the original wyx2685/v2node, Go, sing-box,
or Xray preinstalled. The installer creates the unprivileged service account
and managed directories, installs the controller plus both pinned engines, and
starts only the engine selected by the panel node configuration. The development
source tree cannot install from the network because its project asset hashes are
deliberately locked. The separate `script/install.sh` branch bootstrap pins a
reviewed release and its exact installer SHA-256 before execution; otherwise
use a tagged release or the fully local, hash-verified command above.

For a published release, download `install.sh` from one exact release tag,
verify it against the checksum published with that release, and run the local
file as root. Do not pipe a raw branch or `latest` URL into a shell. Supplying
`--config` and `--token-file` in the first invocation allows the installer to
validate the real panel response and selected engine before enabling the
service.

For command-line compatibility with the original v2node installer, the branch
bootstrap and release installer accept the following aliases:

```bash
wget -N https://raw.githubusercontent.com/Duyvj/v3node/main/script/install.sh
bash install.sh \
  --api-host 'https://panel.example.com' \
  --node-id 73 \
  --api-key 'your-api-key'
```

This compatibility form exposes the key to shell history and process argv.
The installer never logs it and stores it only in `/etc/v3node/panel.token`,
but `--token-file` remains the recommended production workflow.

## Configure the node

Installation creates the `v3node` account and installs a sample at
`/usr/share/doc/v3node/config.example.json`. Prepare credentials without putting
them in shell history:

```bash
sudo install -d -m 0750 -o root -g v3node /etc/v3node
sudo install -m 0640 -o root -g v3node /dev/null /etc/v3node/panel.token
sudoedit /etc/v3node/panel.token
sudo cp /usr/share/doc/v3node/config.example.json /etc/v3node/config.json
sudo chown root:v3node /etc/v3node/config.json
sudo chmod 0640 /etc/v3node/config.json
sudoedit /etc/v3node/config.json
```

For repeatable provisioning, keep both values in files and let the installer
apply their ownership and permissions:

```bash
sudo ./install.sh --config ./config.json --token-file ./panel.token
```

For a clean install, the release installer can also generate the local config
through the verified staged binary:

```bash
sudo ./install.sh \
  --panel-url https://panel.example.com \
  --node-id 42 \
  --token-file ./panel.token
```

Set the HTTPS panel URL and positive node ID. Add `network.dns_servers` only
when regional resolvers have been deliberately selected. There is no local
switch that changes the GeoIP identity of the VPS address.

For a TLS `file` (non-Reality) node, provision the panel-selected certificate
and key before running `v3node check`. If the panel leaves their paths empty,
install them as `/etc/v3node/<protocol><node-id>.cer` and `.key`, owned by
`root:v3node` with certificate mode `0644` or stricter and key mode `0640`.
For `cert_mode=self`, `v3node check` creates a private ECDSA pair atomically
below `/var/lib/v3node/certificates`. Automatic `dns` and `http` ACME modes are
not implemented in this beta.

Then start and inspect the node:

```bash
sudo -u v3node v3node check --config /etc/v3node/config.json
sudo systemctl enable --now v3node.service
systemctl status v3node.service
sudo journalctl -u v3node.service -n 100 --no-pager
```

For later edits, `sudo v3node config` keeps a bounded `.bak`, runs the same
online engine check, restarts only after validation, and restores/restarts the
previous config if activation fails.

When installation is allowed to start the service, it first runs `v3node check`
against the real panel response and the installed engine. A failed check does
not start a new node; an upgrade of an active node restores the previous
managed installation before restarting it.

## Migration from the original v2node

There is no automatic configuration converter. v3node deliberately uses
`/etc/v3node`, `/var/lib/v3node`, `/usr/local/bin/v3node`, and
`v3node.service`, so installation does not overwrite the original v2node files
or service. Never point v3node at the old JSON file. A clean VPS remains the
lowest-risk migration path.

For an in-place cutover, take a VPS snapshot and independently back up at least
these legacy paths:

```text
/etc/v2node/
/etc/systemd/system/v2node.service
/usr/local/v2node/
/usr/bin/v2node
```

Prepare a new `config.json` from this release's `config.example.json`. Map the
old `ApiHost` to `panel.url` and `NodeID` to `panel.node_id`; put the old
`ApiKey` only in the separate `panel.token` referenced by `panel.token_file`.
Review policy compatibility before cutover: sing-box enforces non-zero
`speed_limit` and `device_limit`, while a node whose settings require stock
Xray is rejected if either policy is non-zero.

Install v3node without starting its listener while legacy v2node is still
serving, then validate the panel and rendered engine configuration:

```bash
sudo ./install.sh --config ./config.json --token-file ./panel.token --no-start
sudo -u v3node /usr/local/bin/v3node check --config /etc/v3node/config.json
```

For the pre-release local flow, append the binary/archive and SHA256 arguments
shown in the first example in this document. During the maintenance window,
stop the old listener before starting the new one because both target the same
panel node port:

```bash
sudo systemctl stop v2node.service
sudo systemctl enable --now v3node.service
systemctl status v3node.service
sudo journalctl -u v3node.service -n 100 --no-pager
```

If the cutover fails, return to the untouched legacy service:

```bash
sudo systemctl disable --now v3node.service
sudo systemctl start v2node.service
```

The v3node installer can roll back a previous v3node upgrade; it does not
manage or roll back the separate v2node installation. Remove the old service
and files only after v3node has passed client connection, traffic-accounting,
panel-report, and soak checks.

## Optional host tuning

No tuning is applied during installation. Review current values first:

```bash
sudo v3node-tune status
sudo v3node tune --apply
```

The balanced profile enables BBR only when the running kernel advertises it and
sets conservative queue/socket maxima. It does not touch firewall, DNS, routes,
IP forwarding, or swap. To return to the host's underlying sysctl files:

```bash
sudo v3node-tune remove
```

## Upgrade and rollback behavior

The installer stages and verifies all three binaries before stopping an
existing service. Managed controller, sing-box and Xray binaries plus the unit
are copied to a root-only, timestamped directory below `/var/backups/v3node`.
The active configuration is never overwritten unless `--config` is supplied.

If service startup fails while replacing an active installation, the installer
restores the previous managed binaries, unit, and replaced configuration before
attempting to restart it. Automatic runtime configuration rollback is a
controller responsibility and is separate from this package rollback.

## Uninstall

The safe default removes the service and managed executables but retains
configuration, token, state, install backups, and optional host tuning. If the
managed tuning profile exists, the small `v3node-tune` helper is also retained
so the profile can still be reviewed or removed later:

```bash
sudo v3node-uninstall
```

Review the following destructive options before using them:

```bash
sudo v3node-uninstall --remove-tuning
sudo v3node-uninstall --purge --remove-tuning
```

`--purge` removes `/etc/v3node`, `/var/lib/v3node`, `/run/v3node`,
`/var/backups/v3node`, and an unchanged installer-created service account. It
does not remove unrelated packages or alter the firewall.
