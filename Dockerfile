# Build and runtime both happen in containers; no Go toolchain is needed on
# the host.

ARG GO_IMAGE=golang:1.27-alpine
ARG RUNTIME_IMAGE=gcr.io/distroless/static-debian12:nonroot

# The build stage runs on the build machine's own architecture and
# cross-compiles, so multi-arch builds need no emulation.
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build
ARG TARGETOS
ARG TARGETARCH
ARG IMAGE_VERSION=dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -trimpath \
        -ldflags="-s -w -X main.version=${IMAGE_VERSION}" \
        -o /out/tr-proxy ./cmd/tr-proxy
RUN mkdir -p /out/run /out/config

FROM ${RUNTIME_IMAGE}

ARG IMAGE_TITLE="tr-proxy"
ARG IMAGE_DESCRIPTION="SOCKS5/HTTP proxy that routes by hostname or IP through multiple userspace WireGuard tunnels, upstream proxies or direct, with health monitoring and a web UI"
ARG IMAGE_LICENSES="MIT"
ARG IMAGE_SOURCE=""
ARG IMAGE_REVISION=""
ARG IMAGE_VERSION=dev

LABEL org.opencontainers.image.title="${IMAGE_TITLE}" \
      org.opencontainers.image.description="${IMAGE_DESCRIPTION}" \
      org.opencontainers.image.licenses="${IMAGE_LICENSES}" \
      org.opencontainers.image.source="${IMAGE_SOURCE}" \
      org.opencontainers.image.revision="${IMAGE_REVISION}" \
      org.opencontainers.image.version="${IMAGE_VERSION}"

COPY --from=build /out/tr-proxy /tr-proxy
# Both directories belong to the container's user, so that a named volume or
# a tmpfs created on top of them is writable without further set-up.
# /run/tr-proxy holds the workers' sockets, /config the config file.
COPY --from=build --chown=65532:65532 /out/run /run/tr-proxy
COPY --from=build --chown=65532:65532 /out/config /config
VOLUME /config

EXPOSE 8080
# Exec form: the image has no shell.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --start-interval=1s --retries=3 \
    CMD ["/tr-proxy", "healthcheck"]
ENTRYPOINT ["/tr-proxy"]
CMD ["supervisor"]
