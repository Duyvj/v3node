# V3Node

V3Node là agent node hiệu năng cao và tối ưu tài nguyên dành cho [V2Board](https://github.com/v2board/v2board) / V2Node API và [ZBoard](https://github.com/AZZ-vopp/zboard).
Dự án hỗ trợ chạy nhiều logical node trên một VPS, giới hạn thiết bị phân tán qua Redis, và tích hợp các cơ chế tối ưu RAM/CPU chuyên sâu.

## Tính năng nổi bật

- **Tương thích toàn diện**: Hỗ trợ chuẩn API V2Board / V2Node UniProxy (`type: v2node`, `v2board`, `zboard`).
- **Tối ưu tài nguyên chuyên sâu (ResourceConfig)**:
  - Giới hạn bộ nhớ động (`MemLimitMB`), điều chỉnh chu kỳ GC (`GOGC`), scavenger giải phóng bộ nhớ định kỳ (`PeriodicMemoryReleaseInterval`).
  - Tắt domain sniffing inbound mặc định (`DisableSniffing: true`) để giảm tải CPU và tăng tốc xử lý gói tin.
  - Tối ưu buffer (`BufferSize: 128`), handshake và timeout kết nối.
- **Quản lý đa node**: Một agent quản lý nhiều logical node trên cùng VPS, tự động từ chối node trùng port.
- **Giới hạn thiết bị phân tán**: Giới hạn IP/HWID/UUID thiết bị qua Redis với cơ chế Pub/Sub đồng bộ tức thời.
- **Last-known-good offline runtime**: Khi panel mất kết nối hoặc server khởi động lại trong sự cố mạng, node vẫn giữ snapshot cấu hình và user cuối cùng để phục vụ liên tục.

Xem thêm [tài liệu Redis và tối ưu UDP](docs/ZNODE_REDIS_UDP_VI.md).

## Cài đặt

Cài đặt nhanh installer từ repository [Duyvj/v3node](https://github.com/Duyvj/v3node):

```bash
wget -N https://raw.githubusercontent.com/Duyvj/v3node/main/script/install.sh
bash install.sh
```

Cài agent bằng thông tin do panel cấp. Token được đọc qua stdin để bảo mật:

```bash
read -rsp 'Agent token: ' V3NODE_AGENT_TOKEN; echo
printf '%s\n' "$V3NODE_AGENT_TOKEN" | bash install.sh \
  --api-host https://panel.example.com \
  --agent-id AGENT_ID \
  --agent-token-stdin \
  --release-repo Duyvj/v3node \
  --release-branch main
unset V3NODE_AGENT_TOKEN
```

Installer lưu repository phát hành trong `/etc/znode/release-repo`; lệnh
`v3node update` sau này tiếp tục tải đúng binary từ `Duyvj/v3node`.
Installer chỉ chấp nhận gói có tệp `.dgst`, kiểm tra SHA-256 trước khi giải nén
và tải script qua HTTPS có kiểm tra chứng chỉ. Bản trước được giữ tại
`/usr/local/znode.rollback` để có thể khôi phục nếu cần; không tắt kiểm tra TLS
hoặc tự thay URL tải bằng nguồn không tin cậy.

## Biên dịch

Yêu cầu Go 1.26.5 và experiment JSON v2:

```bash
GOEXPERIMENT=jsonv2 ./script/with-xray-core.sh go test ./...
GOEXPERIMENT=jsonv2 ./script/with-xray-core.sh go build -v -o build_assets/v3node \
  -trimpath \
  -ldflags "-X 'github.com/Duyvj/v3node/cmd.version=dev' -s -w -buildid="
```

Wrapper trên giữ nguyên fork Xray có AnyTLS/TUIC, sau đó áp các backport đã
kiểm tra trong `patches/xray-core` vào bản sao tạm. Module cache gốc không bị
sửa và build sẽ dừng ngay nếu patch không còn tương thích với fork được ghim.

## Phát hành

GitHub Actions build binary theo kiến trúc khi push mã Go lên nhánh `main` hoặc
khi tạo Release. Để installer hoạt động, repository cần có ít nhất một GitHub
Release chứa các tệp `v3node-linux-<arch>.zip` do workflow tạo ra.

## Cấu hình Redis

ZBoard / V2Board và V3Node phải dùng cùng Redis nếu bật đồng bộ thiết bị thời gian thực.
Giữ cùng channel đã cấu hình trên panel, mặc định `v2board:device-sync`.

Thông tin Agent được lưu tại `/etc/znode/config.json` với quyền `0600`. Không
chia sẻ Agent token hoặc sao chép file này sang VPS khác.
Cấu hình chuẩn sử dụng trường `"type": "v2node"` (hoặc `"zboard"`).

Sau lần khởi động online thành công, V3Node ghi snapshot nguyên tử tại
`/var/lib/znode/runtime.snapshot`. File có quyền `0600`, được xác thực HMAC bằng
Agent token và chỉ được dùng khi API panel không truy cập được. Snapshot không
có thời hạn tự hết hiệu lực để VPS tiếp tục phục vụ trong sự cố dài; khi panel
trở lại, các task tự đồng bộ cấu hình, user và traffic đang chờ. Chỉ phản hồi
thu hồi Agent có marker riêng từ panel mới được phép gỡ các inbound;
trang lỗi `401/403` chung từ CDN/WAF không làm node dừng.

## Giấy phép

Xem [LICENSE](LICENSE). Dự án sử dụng Xray core đã tùy chỉnh theo khai báo trong
`go.mod`.

## Dữ liệu GeoIP và GeoSite

Các rule Xray dùng `geoip:` và `geosite:` cần đồng thời hai file
`geoip.dat` và `geosite.dat`. Bản phát hành tự tải dữ liệu mới nhất từ
Loyalsoldier, trình cài đặt xác thực file không rỗng rồi đặt chúng tại
`/etc/znode`. Znode tự đặt `XRAY_LOCATION_ASSET` về thư mục chứa đủ hai file;
Docker image cũng đóng gói sẵn dữ liệu vào `/etc/znode`.

Khi chạy Docker, phải gắn volume bền vững vào `/var/lib/znode`, ví dụ
`-v znode-data:/var/lib/znode`. Đây là nơi lưu batch traffic chưa được ZBoard
xác nhận; không mount thư mục này sẽ làm mất batch đang chờ khi thay container.

Có thể đổi nguồn tải khi cài bằng biến `ZNODE_GEODATA_URL`, ví dụ một mirror
nội bộ có cấu trúc `.../geoip.dat` và `.../geosite.dat`.
