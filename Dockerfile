# Build go
FROM golang:1.26.5-alpine AS builder
WORKDIR /app
COPY . .
ENV CGO_ENABLED=0
RUN apk --update --no-cache add patch
RUN GOEXPERIMENT=jsonv2 go mod download
RUN GOEXPERIMENT=jsonv2 ./script/with-xray-core.sh go build -v -o znode

FROM alpine AS geodata
RUN apk --update --no-cache add ca-certificates curl \
    && mkdir -p /assets \
    && curl --fail --location --silent --show-error --retry 3 \
       https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat -o /assets/geoip.dat \
    && curl --fail --location --silent --show-error --retry 3 \
       https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat -o /assets/geosite.dat \
    && test "$(wc -c < /assets/geoip.dat)" -ge 1024 \
    && test "$(wc -c < /assets/geosite.dat)" -ge 1024

# Release
FROM  alpine
# Cài đặt các gói công cụ cần thiết
RUN  apk --update --no-cache add tzdata ca-certificates \
    && cp /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
RUN mkdir /etc/znode/ \
    && install -d -m 0700 /var/lib/znode
COPY --from=builder /app/znode /usr/local/bin
COPY --from=geodata /assets/geoip.dat /assets/geosite.dat /etc/znode/

ENV XRAY_LOCATION_ASSET=/etc/znode

# Immutable traffic batches live here until ZBoard durably acknowledges them.
# Keeping this as a volume prevents an image/container replacement from
# silently discarding traffic that was still awaiting delivery.
VOLUME ["/var/lib/znode"]

ENTRYPOINT [ "znode", "server", "--config", "/etc/znode/config.json"]
