# Build and runtime both happen in containers; no Go toolchain is needed on
# the host.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum* ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/tr-proxy ./cmd/tr-proxy

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/tr-proxy /tr-proxy
VOLUME /config
# Exec form: the image has no shell.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --start-interval=1s --retries=3 \
    CMD ["/tr-proxy", "healthcheck"]
ENTRYPOINT ["/tr-proxy"]
CMD ["supervisor"]
