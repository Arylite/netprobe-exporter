FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
ARG REVISION=unknown
ARG BUILD_DATE=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -ldflags="-s -w -X main.version=${VERSION} -X main.revision=${REVISION} -X main.buildDate=${BUILD_DATE}" \
    -o /netprobe-exporter ./cmd/netprobe-exporter

FROM alpine:3.21

# The file capability lets the exporter open raw ICMP sockets as a non-root
# user. CAP_NET_RAW is part of the default Docker capability set; drop it and
# ICMP probes fall back to the unprivileged mode described in the README.
#
# The binary is installed and given its capability in a single layer, because
# setcap rewrites the file and would otherwise store a second copy of it.
RUN --mount=from=build,source=/netprobe-exporter,target=/tmp/netprobe-exporter \
    apk add --no-cache libcap \
    && cp /tmp/netprobe-exporter /usr/local/bin/netprobe-exporter \
    && setcap cap_net_raw+ep /usr/local/bin/netprobe-exporter \
    && apk del libcap \
    && addgroup -g 10001 netprobe \
    && adduser -D -u 10001 -G netprobe netprobe

USER netprobe:netprobe
EXPOSE 9427

ENTRYPOINT ["/usr/local/bin/netprobe-exporter"]
CMD ["--config", "/etc/netprobe/netprobe.yml"]
