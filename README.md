# v3node

`v3node` là node controller viết mới bằng Go cho panel tương thích
V2Board/v2node. Đây là một sản phẩm độc lập: VPS sạch có thể cài trực tiếp bản
phát hành của dự án, không cần cài v2node gốc trước và cũng không cài đè lên
source cũ.

> **Trạng thái: beta thử nghiệm.** Mã nguồn đã có kiểm thử đơn vị và kiểm
> tra cấu hình với engine thật, nhưng chưa hoàn tất toàn bộ kiểm thử tải dài hạn,
> chuyển cấu hình khi đang có nhiều phiên và đối soát traffic qua mọi tình huống
> lỗi. Chưa nên dùng cho node thương mại quan trọng nếu chưa tự chạy staging và
> theo dõi ít nhất vài ngày.

## Mục tiêu thiết kế

- Giữ RAM/CPU ổn định bằng giới hạn dữ liệu đầu vào, cache LRU có kích thước tối
  đa, bộ tích lũy report hữu hạn và checkpoint nguyên tử; không che lỗi rò RAM bằng
  một `MemoryMax` cứng có thể giết phiên đang hoạt động.
- Chỉ chạy một data-plane engine phù hợp với node tại một thời điểm.
- Kiểm tra cấu hình mới trước khi dùng, lưu last-known-good và tự rollback nếu
  engine mới không khởi động/không khỏe.
- Giữ controller, credential và data plane tách biệt. Controller không tự triển
  khai crypto, TLS hay giao thức VPN.
- Không tự ý đổi firewall, route, DNS, swap hoặc sysctl trong lúc cài. Tuning là
  thao tác chủ động của quản trị viên.

## Kiến trúc

```text
Panel V2Board/v2node
        │ HTTPS + API token
        ▼
v3node controller (Go)
  ├─ đồng bộ node/users
  ├─ traffic + online-IP có giới hạn
  ├─ render → check → apply → health-check → rollback
  └─ lưu checkpoint và last-known-good
        │ chỉ chọn một engine
        ├───────────────┐
        ▼               ▼
  sing-box tùy biến   Xray nguyên bản
        │               │
        └──── direct egress qua mạng của VPS ──── Internet
```

Controller dùng các endpoint panel sau và luôn giữ `node_type=v2node`:

| Method | Endpoint |
| --- | --- |
| `GET` | `/api/v2/server/config` |
| `GET` | `/api/v1/server/UniProxy/user` |
| `GET` | `/api/v1/server/UniProxy/alivelist` |
| `POST` | `/api/v1/server/UniProxy/push` |
| `POST` | `/api/v1/server/UniProxy/alive` |

## Protocol và engine

| Engine | Protocol | Transport chính |
| --- | --- | --- |
| sing-box 1.13.18 bản build của dự án | VMess, VLESS, Trojan, Shadowsocks, Hysteria2, TUIC, AnyTLS | TCP/raw, WebSocket, gRPC, HTTPUpgrade, HTTP; tùy protocol |
| Xray v26.3.27 nguyên bản | VMess, VLESS, Trojan, Shadowsocks | TCP/raw, WebSocket, gRPC, HTTPUpgrade, XHTTP/SplitHTTP |

`engine.backend: "auto"` ưu tiên sing-box cho cấu hình thông thường và chọn Xray
khi cần XHTTP/SplitHTTP, TLS cho Shadowsocks TCP hoặc route dùng cú pháp
GeoIP/GeoSite/custom outbound của Xray. Xray v26.3.27 chưa thực thi CIDR
`trusted_x_forwarded_for` an toàn nên v3node từ chối trường này thay vì âm thầm
tin địa chỉ do client tự khai. Custom outbound được giới hạn 256 KiB,
chỉ nhận các field đã duyệt và không được dùng tag nội bộ. Một cấu hình không
thể biểu diễn chính xác trên engine được chọn sẽ bị từ chối thay vì bị chuyển
đổi âm thầm.

TLS và Reality được hỗ trợ khi panel cung cấp đủ trường bắt buộc. Hysteria2,
TUIC và AnyTLS bắt buộc có TLS. Chế độ `auto` dùng engine sing-box đã patch cho
Shadowsocks legacy/2022 và các cấu hình biểu diễn chính xác được; Xray được chọn
khi transport, Reality hoặc route cần riêng khả năng của Xray.

Chế độ TLS `file` dùng chứng thư do quản trị viên cấp và gia hạn; nếu panel bỏ
trống đường dẫn, controller dùng quy ước `/etc/v3node/<protocol><node-id>.cer`
và `.key`. `cert_mode=self` được tạo một lần bằng ECDSA trong
`/var/lib/v3node/certificates/`, không cần worker chạy nền. Bản beta chưa nhận
secret DNS từ panel để tự chạy ACME `dns`/`http`. `tls=1` cùng `cert_mode=none`
giữ đúng hợp đồng TLS termination bên ngoài. Reality không dùng các file cert.

## Chống GFW và giảm rủi ro block IP

v3node kiểm tra key X25519, ML-DSA seed, SNI, short ID và destination của
REALITY trước khi ghi cấu hình engine; key lỗi không còn bị Xray in nguyên giá
trị vào journal. Cả hai engine dùng cửa sổ lệch thời gian REALITY 5 phút, vì vậy
VPS và thiết bị khách phải đồng bộ giờ. TLS certificate trên sing-box và Xray
đều có phiên bản tối thiểu 1.2. DNS TCP/UDP cổng 53 từ client đều được đưa qua
DNS stack của VPS.

Với node dành cho mạng Trung Quốc, profile nên ưu tiên VLESS + TCP/raw +
REALITY trên cổng ngoài 443; `flow=xtls-rprx-vision` chỉ được nhận ở tổ hợp mà
engine thực sự hỗ trợ. Không dùng Apple/iCloud làm target/SNI. Target cần có
TLS/SAN phù hợp và nên ở cùng ASN với VPS; kiểm tra thực tế bằng `xray tls ping`.
Nếu dùng ML-DSA, còn phải kiểm tra certificate target đủ lớn và hỗ trợ trao đổi
khóa phù hợp. `v3node check` và service log sẽ cảnh báo cổng REALITY khác 443,
short ID rỗng, TLS tự ký, listener không có TLS/REALITY và TUIC zero-RTT.

Fingerprint uTLS/ClientHello, fragmentation và `spoof` nằm ở phía client;
server v3node không thể ép các app khách dùng fingerprint đúng. TLS tự ký,
VLESS/Trojan plaintext hoặc Shadowsocks mở trực tiếp không tạo được diện mạo
HTTPS bình thường. Không protocol/cấu hình nào bảo đảm IP sẽ không bao giờ bị
GFW chặn; production vẫn cần IP/node dự phòng và kiểm tra từ mạng Trung Quốc.
Xem thêm phần vận hành trong [mô hình bảo mật](docs/security.md#anti-gfw-and-traffic-camouflage).

Các trạng thái cần hiểu rõ trong beta:

| Khả năng | Trạng thái hiện tại |
| --- | --- |
| Đồng bộ cấu hình/users, report upload/download | Đã triển khai; tiếp tục cần soak/load test |
| Giới hạn thiết bị theo IP | Enforce trên sing-box; cấu hình Xray có `device_limit > 0` bị từ chối rõ ràng |
| `speed_limit` theo từng user | Enforce hữu hạn trên sing-box; cấu hình buộc dùng Xray có giá trị khác 0 bị từ chối rõ ràng |
| Nhiều panel/node trong một process | Chưa có; mỗi cài đặt beta hiện quản lý một node |
| Cập nhật user không ngắt phiên | Chưa có; thay đổi cấu hình có thể restart engine và làm client reconnect |
| Traffic qua lúc thay engine | Có final drain trước khi đổi engine và checkpoint; vẫn cần soak test đối soát dài hạn |

## Tối ưu tài nguyên

Controller tự đặt soft heap target bằng khoảng 1/16 RAM khả dụng, tối thiểu
64 MiB và tối đa 256 MiB, trừ khi quản trị viên đã đặt `GOMEMLIMIT`. Nó đọc cả
cgroup và dùng `sysinfo(2)` khi profile systemd che `/proc/meminfo`. Đây là mục
tiêu GC của controller, không phải trần RAM của toàn bộ dịch vụ.

Các giới hạn mặc định gồm response config 2 MiB, response users 32 MiB, panel
payload 32 MiB, Stats RPC 64 MiB, 100.000 users, 200.000 online IP và 1.024 IP/user.
`runtime.max_ips_per_user` chỉ là trần an toàn bộ nhớ; giới hạn thực tế của
từng khách luôn lấy từ `device_limit` trên panel (`0` nghĩa là không giới hạn).
Traffic chờ report được giới hạn theo `max_users`. Có thể
chỉnh trong `runtime`, nhưng tăng giới hạn cũng làm tăng RAM xấu nhất. RAM của engine còn phụ
thuộc số kết nối đồng thời, protocol, QUIC, TLS và lưu lượng thực tế; dự án không
cam kết một con số RAM cố định cho mọi VPS. Danh sách connection được giải mã
streaming; toàn bộ IP chỉ được sort lúc seed policy, các vòng sau chỉ sort user
thực sự có `device_limit`. Cấu hình engine dùng JSON compact và
user struct thay vì một map động cho mỗi tài khoản để giảm heap spike khi reload.
Limiter tốc độ chỉ tạo một token bucket cho user có giới hạn, dùng chung cho mọi
phiên và cả hai chiều; kết nối mới không làm bảng limiter tăng vô hạn.

Giới hạn thiết bị lấy trực tiếp từ `users[].device_limit` của panel và tính theo
IP nguồn. Mỗi snapshot Connections đầy đủ giải phóng IP đã ngắt ở vòng poll kế
tiếp (khoảng 5 giây), không giữ oan slot đến hết TTL. Số `alive` của panel vẫn
được dùng để tính thiết bị trên node khác, nhưng số IP trong lần report thành
công gần nhất của chính node được trừ ra để tránh đếm hai lần. Payload report
lỗi không được trừ; `alive` cũ cũng bị bỏ sau 5 phút lỗi liên tục để không khóa
oan khách hàng vô thời hạn.

Unit systemd không đặt hard RAM limit để tránh OOM-kill phiên hợp lệ khi tải tăng.
Nó chạy bằng user `v3node`, chỉ có `CAP_NET_BIND_SERVICE`, bật accounting và giới
hạn vùng ghi. Profile BBR/socket là tùy chọn, xem `v3node tune --apply` sau khi đã
đo baseline.

Mặc định `network.block_private=false` để tương thích route của v2node gốc và
cho phép khách truy cập LAN/VPC khi cần. Có thể bật thành `true`; dù ở chế độ
nào, Stats/Connections API loopback của v3node vẫn luôn bị chặn khỏi VPN user.

## IP quốc gia, DNS và trải nghiệm khách hàng

Ở chế độ direct egress, traffic khách hàng đi ra bằng public IP của VPS. Nếu VPS
có IP Nhật và các dịch vụ đích nhận diện IP đó là Nhật, khách hàng thường được
thấy như đang truy cập từ Nhật. `network.dns_servers` và lựa chọn IPv4/IPv6 có
thể giúp phân giải/đường đi nhất quán hơn. Cả hai engine chặn hướng DNS bị rò
bằng cách đưa UDP/53 từ client vào DNS stack đã cấu hình, nhưng việc này không
đổi danh tính public IP.

Dự án **không thể**:

- sửa cơ sở dữ liệu GeoIP của Google, Netflix, MaxMind hoặc nhà cung cấp khác;
- biến IP datacenter thành IP residential/mobile;
- bảo đảm mở khóa streaming, ngân hàng, quảng cáo hay dịch vụ chống proxy;
- khắc phục routing/peering yếu của nhà cung cấp VPS chỉ bằng một file config.

Nếu quốc gia bị nhận sai, cần yêu cầu nhà cung cấp IP và từng cơ sở dữ liệu GeoIP
cập nhật, hoặc đổi IP/VPS. Controller không cung cấp nút cấu hình giả quốc gia;
egress mặc định đi trực tiếp bằng public IP thật của VPS. Quản trị viên có thể
chủ động cấu hình custom outbound Xray, khi đó IP đích nhìn thấy phụ thuộc vào
outbound ấy thay vì IP của VPS.

## Cài độc lập

Host mục tiêu hiện là Debian 12 hoặc Ubuntu 22.04 trở lên, systemd, kiến trúc
`amd64` hoặc `arm64`. Bản cài quản lý các đường dẫn chính sau:

| Đường dẫn | Nội dung |
| --- | --- |
| `/usr/local/bin/v3node` | controller và CLI |
| `/usr/local/lib/v3node/` | engine đã pin phiên bản |
| `/etc/v3node/config.json` | cấu hình local |
| `/etc/v3node/panel.token` | API token đề xuất |
| `/var/lib/v3node/` | state, checkpoint, last-known-good |

Installer đầy đủ trong `deploy/` trên nhánh phát triển cố ý giữ checksum
placeholder; quy trình đóng gói chỉ thay chúng trong artifact của release.
Riêng bootstrap nhỏ tại `script/install.sh` ghim một release cụ thể cùng
SHA-256 chính xác của installer, kiểm tra hash rồi mới thực thi. Vì vậy có thể
dùng đúng cú pháp quen thuộc của v2node gốc và chỉ thay link:

```bash
wget -N https://raw.githubusercontent.com/Duyvj/v3node/main/script/install.sh && \
bash install.sh --api-host 'https://panel.example.com' --node-id 73 --api-key 'your-api-key'
```

`--api-host` là alias của `--panel-url`; `--api-key` được lưu thành
`/etc/v3node/panel.token` với quyền hạn chế, không ghi vào `config.json` hay log.
Tuy nhiên key vẫn xuất hiện tạm thời trong history/argv do chính cú pháp tương
thích này. Với production, nên dùng `--token-file` như ví dụ bên dưới.

Không pipe raw script thẳng vào shell và không tự thay placeholder. Có thể tải
trực tiếp `install.sh` gắn với một tag cụ thể trong GitHub Releases, kiểm tra
checksum theo release notes rồi mới chạy:

```bash
curl -fLO --proto '=https' --tlsv1.2 \
  https://github.com/Duyvj/v3node/releases/download/<TAG>/install.sh
# Kiểm tra SHA-256 bằng SHA256SUMS đã ký/đăng cùng release.
sudo bash ./install.sh
```

Installer của release cài controller và engine cần thiết; không cần v2node gốc.
Quy trình build/cài local trước release nằm trong
[`docs/deployment.md`](docs/deployment.md).

Có thể tạo cấu hình ngay khi cài mà không để token trong argv/history:

```bash
sudo bash ./install.sh \
  --panel-url https://panel.example.com \
  --node-id 42 \
  --token-file ./panel.token
```

Hoặc sau khi cài, tạo token và cấu hình thủ công:

```bash
sudo install -d -m 0750 -o root -g v3node /etc/v3node
sudo install -m 0640 -o root -g v3node /dev/null /etc/v3node/panel.token
sudoedit /etc/v3node/panel.token
sudo cp /usr/share/doc/v3node/config.example.json /etc/v3node/config.json
sudo chown root:v3node /etc/v3node/config.json
sudo chmod 0640 /etc/v3node/config.json
sudoedit /etc/v3node/config.json
sudo -u v3node v3node check --config /etc/v3node/config.json
sudo systemctl enable --now v3node.service
```

Kiểm tra vận hành:

```bash
v3node version
sudo v3node diagnose --config /etc/v3node/config.json
systemctl status v3node.service
sudo journalctl -u v3node.service -n 100 --no-pager
```

CLI cũng có các lệnh `start`, `stop`, `restart`, `status`, `enable`, `disable`,
`log`, `generate`, `config`, `update`, `uninstall`, `x25519` và `tune`. Chạy
`v3node` trong terminal sẽ mở menu giới hạn; `v3node config` giữ backup, kiểm
tra online rồi mới restart và tự phục hồi nếu cấu hình mới lỗi. `update` chỉ chạy
installer sau khi kiểm tra `install.sh` bằng `SHA256SUMS` của cùng GitHub
Release; build beta theo kênh prerelease, còn build stable mặc định bỏ qua
prerelease.

Không đặt token trong câu lệnh, ảnh chụp hoặc repository. Production phải dùng
HTTPS tới panel; HTTP chỉ dành cho mạng phát triển cô lập.

Để tự động hóa nhiều VPS mà không đưa token vào lịch sử shell, chuẩn bị hai file
local rồi dùng `install.sh --config ./config.json --token-file ./panel.token`.
Installer cài token với owner `root:v3node`, mode `0640`, kiểm tra node trước khi
khởi động và rollback bản đang chạy nếu upgrade thất bại.

## Chuyển từ v2node gốc

Không có chuyển đổi cấu hình tự động. `v3node` dùng đường dẫn và service riêng,
nên không ghi đè `/etc/v2node`, `v2node.service` hay binary cũ. Không được đưa
file cấu hình v2node trực tiếp cho controller mới; hãy tạo config mới từ example
của đúng release.

Trên VPS đang chạy, có thể cài `v3node` với `--no-start`, chạy
`sudo -u v3node v3node check`,
rồi mới dừng `v2node.service` và khởi động `v3node.service`. Hai data plane không
thể cùng giữ một cổng node. Nếu cutover lỗi, dừng v3node và khởi động lại service
v2node cũ. Quy trình đầy đủ nằm trong
[`docs/deployment.md`](docs/deployment.md#migration-from-the-original-v2node).

## Tài liệu

- [Kiến trúc](docs/architecture.md)
- [Tương thích panel/protocol](docs/compatibility.md)
- [Triển khai và rollback](docs/deployment.md)
- [Mô hình bảo mật](docs/security.md)

## License và phần mềm bên thứ ba

Controller và phần mã nguyên bản của repository được phát hành theo
[Apache License 2.0](LICENSE). Các engine là chương trình riêng và giữ license
của upstream; Apache-2.0 không thay thế hoặc cấp lại license cho chúng.

sing-box tùy biến là tác phẩm phái sinh của upstream và phải được phân phối theo
license upstream, cùng exact Corresponding Source, patch, build scripts, module
source cần để tái tạo binary, notices và license. Xray giữ MPL-2.0. Xem đầy đủ
trong [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) và
[`engine-patches/sing-box/UPSTREAM_LICENSE`](engine-patches/sing-box/UPSTREAM_LICENSE).
Toàn văn GPLv3 và MPL-2.0 nằm trong [`LICENSES/`](LICENSES/).

Tên sing-box và Xray chỉ dùng để mô tả phần mềm tương thích/bên thứ ba. Dự án này
không được các dự án upstream tài trợ hoặc chứng thực.
