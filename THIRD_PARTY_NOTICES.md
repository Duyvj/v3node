# Third-party notices

Tài liệu này áp dụng cho source tree và binary phát hành của `v3node`.
Danh sách phải được rà lại từ `go.mod`, engine manifest và artifact thực tế mỗi
lần phát hành. License Apache-2.0 ở thư mục gốc chỉ áp dụng cho phần mã nguyên
bản của v3node; nó không thay đổi license của các thành phần dưới đây.

## Thành phần được link vào controller

| Thành phần | Phiên bản | License | Source |
| --- | --- | --- | --- |
| `google.golang.org/grpc` | v1.82.1 | Apache-2.0 | <https://github.com/grpc/grpc-go/tree/v1.82.1> |
| `google.golang.org/genproto/googleapis/rpc` | `afd174a4e478` (2026-04-14) | Apache-2.0 | <https://github.com/googleapis/go-genproto> |
| `google.golang.org/protobuf` | v1.36.11 | BSD-3-Clause | <https://github.com/protocolbuffers/protobuf-go/tree/v1.36.11> |
| `golang.org/x/net` | v0.53.0 | BSD-3-Clause | <https://go.googlesource.com/net/+/refs/tags/v0.53.0> |
| `golang.org/x/sys` | v0.43.0 | BSD-3-Clause | <https://go.googlesource.com/sys/+/refs/tags/v0.43.0> |
| `golang.org/x/text` | v0.36.0 | BSD-3-Clause | <https://go.googlesource.com/text/+/refs/tags/v0.36.0> |

Apache License 2.0 được chép đầy đủ trong [`LICENSE`](LICENSE). NOTICE của
gRPC-Go:

```text
Copyright 2014 gRPC authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

### BSD-3-Clause — protobuf-go

```text
Copyright (c) 2018 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
* Neither the name of Google Inc. nor the names of its contributors may be
  used to endorse or promote products derived from this software without
  specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

### BSD-3-Clause — golang.org/x/net, x/sys và x/text

```text
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
* Neither the name of Google LLC nor the names of its contributors may be
  used to endorse or promote products derived from this software without
  specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```

Các module `golang.org/x/*` còn phân phối tệp `PATENTS` với grant quyền patent;
release source/SBOM phải giữ nguyên tệp đó khi vendor source.

## sing-box engine tùy biến

- Upstream: <https://github.com/SagerNet/sing-box>
- Phiên bản: 1.13.18
- Commit chính xác: `45ca32dcb966f07f97fc888fe8586e359dbe8405`
- Source input SHA-256:
  `62693e51bbc42d937af923f888b8a9c197127e3ca25f3a6e01f863963b43f450`
- Thay đổi dự án:
  [`0001-expose-authenticated-user.patch`](engine-patches/sing-box/0001-expose-authenticated-user.patch)
  và
  [`0002-bounded-user-rate-limit.patch`](engine-patches/sing-box/0002-bounded-user-rate-limit.patch)
- License upstream: GPL version 3 hoặc mới hơn, kèm điều kiện bổ sung nguyên văn
  trong [`UPSTREAM_LICENSE`](engine-patches/sing-box/UPSTREAM_LICENSE).
- Toàn văn GPLv3: [`LICENSES/GPL-3.0.txt`](LICENSES/GPL-3.0.txt).

Controller không link sing-box; engine chạy thành executable/process riêng. Tuy
vậy, binary sing-box đã patch là tác phẩm phái sinh và nghĩa vụ upstream vẫn áp
dụng đầy đủ. Mỗi nơi cung cấp binary đó để tải xuống phải đồng thời cung cấp,
không thu phí thêm, exact Corresponding Source ở cùng nơi hoặc bằng phương thức
hợp lệ theo GPL. Source bundle của **chính binary đã phát hành** tối thiểu phải có:

1. toàn bộ source upstream tại commit đã pin và patch đã được áp dụng;
2. toàn bộ module source thực tế được link vào Go binary (vendor/offline source),
   cùng license, notices và patent files của chúng;
3. `go.mod`, `go.sum`, build tags, patch, build script, workflow/tool metadata và
   mọi script cần để tạo/cài executable;
4. license upstream nguyên văn, bản GPLv3 đầy đủ, copyright notices và SHA-256
   của binary lẫn source archive;
5. chỉ dẫn rõ artifact source nào tương ứng với từng binary/kiến trúc.

Không được chỉ đăng link tới upstream rồi bỏ phần patch/dependency source của
binary thực tế. Không được xóa điều kiện đặt tên/association ở cuối license
upstream. Vì điều kiện này có ảnh hưởng tới cách đặt tên artifact phái sinh,
maintainer phải hoàn tất rà soát/cho phép cần thiết trước khi public release.
Patch trong `engine-patches/sing-box/` được phân phối theo cùng điều khoản áp
dụng cho tác phẩm sing-box upstream; root Apache-2.0 không cấp lại license cho
phần đó.

## Xray engine nguyên bản

- Upstream: <https://github.com/XTLS/Xray-core>
- Phiên bản được pin cho beta: v26.3.27
- License: Mozilla Public License 2.0
- Exact source: <https://github.com/XTLS/Xray-core/tree/v26.3.27>
- License text: [`LICENSES/MPL-2.0.txt`](LICENSES/MPL-2.0.txt) và bản upstream tại
  <https://github.com/XTLS/Xray-core/blob/v26.3.27/LICENSE>

Xray được chạy như executable/process riêng và không bị sửa bởi dự án. Khi phân
phối executable, release/installer phải giữ notices, kèm bản MPL-2.0 và thông báo
cho người nhận cách lấy Source Code Form đúng phiên bản một cách hợp lý, kịp thời
và không cao hơn chi phí phân phối theo MPL-2.0 mục 3.2.

Tên, logo và trademark của sing-box, SagerNet, Xray và Project X không được cấp
quyền bởi license controller. Việc liệt kê ở đây chỉ nhằm attribution và mô tả
khả năng tương thích; không ngụ ý upstream chứng thực v3node.

Tệp này là bản ghi kỹ thuật về nguồn gốc/license, không phải tư vấn pháp lý.
