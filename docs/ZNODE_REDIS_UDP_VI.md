# ZNode: device limit Redis và tối ưu UDP

## Bật giới hạn thiết bị dùng Redis

Đặt `GlobalDeviceLimitConfig` trong từng node. Các node dùng cùng panel/API host
và cùng Redis sẽ chia sẻ giới hạn theo UUID credential (không lưu UUID thô trong
Redis; key được băm SHA-256):

```json
{
  "ConnectionConfig": {
    "Handshake": 15,
    "ConnIdle": 120,
    "UplinkOnly": 2,
    "DownlinkOnly": 4,
    "BufferSize": 128,
    "DisableUDPContentSniffing": true
  },
  "Nodes": [
    {
      "ApiHost": "https://panel.example.com",
      "NodeID": 1,
      "ApiKey": "NODE_TOKEN",
      "Timeout": 15,
      "GlobalDeviceLimitConfig": {
        "Enable": true,
        "SyncEnabled": true,
        "SyncChannel": "v2board:device-sync",
        "RedisNetwork": "tcp",
        "RedisAddr": "127.0.0.1:6379",
        "RedisUsername": "",
        "RedisPassword": "CHANGE_ME",
        "RedisDB": 0,
        "Timeout": 1,
        "Expiry": 60,
        "RefreshInterval": 20,
        "MaxIPsPerUser": 256,
        "KeyPrefix": "znode:device",
        "FailClosed": false
      }
    }
  ]
}
```

## Đồng bộ UUID tức thời

Khi `SyncEnabled=true`, znode subscribe Redis Pub/Sub trên `SyncChannel`. Nếu
không khai báo trường này thì mặc định là `true`; đặt `false` để tắt watcher.
Mỗi
lần người dùng bind, xoá hoặc khoá một device, v2board phát sự kiện và node gọi
lại API user ngay lập tức; không cần chờ `PullInterval`. Sự kiện được lọc theo
`ApiHost`, vì vậy có thể dùng chung Redis cho nhiều panel. Nếu Redis tạm thời
không khả dụng, watcher tự reconnect và cơ chế pull định kỳ vẫn là fallback.

Trên v2board cần bật `device_sync_redis_enable` (mặc định bật) và để
`device_sync_redis_connection` trỏ tới Redis dùng chung. `SyncChannel` phải
giống nhau giữa panel và từng node.

`Expiry` là thời gian một IP được xem là online sau lần refresh cuối. Nên để
`RefreshInterval` nhỏ hơn `Expiry` (thường bằng một phần ba). Lua script trên
Redis thực hiện xoá IP hết hạn, kiểm tra số lượng, thêm IP và refresh TTL trong
một thao tác nguyên tử, nên hai node đồng thời không thể cùng vượt slot.

Profile khuyến nghị để đồng bộ nhanh nhưng vẫn nhẹ cho VPS là `Expiry=60`,
`RefreshInterval=20`, `Timeout=1`, `FailClosed=false`. Redis chỉ được chạm tối
đa một lần mỗi 20 giây cho mỗi IP đang hoạt động, không ghi theo từng packet.
Không nên hạ refresh dưới 5 giây; mức quá thấp chỉ tăng IOPS và CPU Redis mà
không làm Pub/Sub nhanh hơn. Redis nên nằm cùng private network với ZNode.

- `FailClosed=false`: khi Redis tạm thời lỗi, node dùng tracker local có TTL để
  giữ dịch vụ hoạt động.
- `FailClosed=true`: kết nối có IP mới bị từ chối nếu không xác nhận được với
  Redis; chỉ nên bật khi Redis có HA/monitoring.
- `MaxIPsPerUser` giới hạn bộ nhớ local cho một user. User không đặt
  `device_limit` vẫn được cho qua, nhưng chỉ giữ tối đa số IP này để tránh
  client lỗi hoặc scan làm phình RAM.

## Tối ưu RAM và UDP

- Không còn tạo `sync.Map` lồng nhau cho mỗi handshake. Một IP đang hoạt động
  chỉ có một entry nhỏ, được refresh theo TTL.
- Device limit được kiểm tra cho cả TCP và UDP. IP được chuẩn hoá IPv4-mapped
  IPv6 để không bị tính thành hai thiết bị.
- `BufferSize` mặc định là 128 KiB để tránh làm đầy bộ đệm và bỏ gói ở các
  luồng video UDP/QUIC, nhưng vẫn thấp hơn mặc định 512 KiB của Xray trên amd64.
- `ConnIdle` mặc định 120 giây để các luồng video tải trước không bị ngắt quá
  sớm trong lúc tạm thời không truyền dữ liệu.
- `DisableUDPContentSniffing=true` không giữ gói QUIC đầu tiên để đọc nội dung.
  TCP/TLS vẫn được sniff khi có rule hostname; rule hostname riêng cho UDP/QUIC
  cần đặt lại thành `false` và chấp nhận độ trễ đầu phiên trên đường truyền xa.
- Sniffing inbound mặc định tắt khi node không có rule domain/protocol. Khi có
  rule cần nhận diện nội dung, ZNode dùng `routeOnly=true`: hostname chỉ phục vụ
  chọn route, không thay IP đích bằng kết quả DNS của VPS. Cơ chế này tránh lỗi
  CDN Meta trên một số nhà mạng/VPS.
- LinkManager tự loại khỏi `sync.Map` khi user không còn link; bucket speed của
  user hết TTL cũng được thu hồi.

## Giới hạn nhận diện thiết bị

Một proxy node chuẩn nhận được credential và địa chỉ nguồn, không nhận được
HWID phần cứng của điện thoại/laptop. Vì vậy Redis limiter tại node là giới hạn
online theo UUID credential + IP. Binding HWID thật phải được thực hiện ở panel
qua flow subscription; với v2board hiện tại mỗi device bound đã có UUID node
riêng.

## Kiểm thử

```bash
GOEXPERIMENT=jsonv2 ./script/with-xray-core.sh go test ./...
GOEXPERIMENT=jsonv2 ./script/with-xray-core.sh go test -bench BenchmarkDeviceTrackerSameIP -benchmem ./limiter
```

Race detector cần CGO và một C compiler (`gcc`/MinGW). Sau khi cài toolchain,
nên chạy thêm:

```bash
CGO_ENABLED=1 GOEXPERIMENT=jsonv2 ./script/with-xray-core.sh go test -race ./...
```
