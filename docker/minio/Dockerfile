# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
# Local development/test storage only. Build the exact official source release:
# https://github.com/minio/minio/releases/tag/RELEASE.2025-10-15T17-29-55Z
# This separate build context contains no Hash application or environment files.
FROM golang:1.26.10-alpine@sha256:9ce231b28998b32e116927c61aa5c406183061d4f3f2d61b292c88e7f6bdf7ca AS build
ENV GOTOOLCHAIN=local \
    CGO_ENABLED=0 \
    GOMAXPROCS=2 \
    GOMEMLIMIT=768MiB \
    GOPROXY=https://proxy.golang.org \
    GOSUMDB=sum.golang.org
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOBIN=/out go install -trimpath -p=1 github.com/minio/minio@v0.0.0-20251015172955-9e49d5e7a648 && \
    go version -m /out/minio && \
    cp /go/pkg/mod/github.com/minio/minio@v0.0.0-20251015172955-9e49d5e7a648/LICENSE /out/LICENSE.minio

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b
# Preserve the same patched runtime library floors as the Hash app image.
RUN apk add --no-cache \
        'libcrypto3>=3.5.8-r0' \
        'libssl3>=3.5.8-r0' \
        ca-certificates \
        tzdata && \
    addgroup -S -g 1000 minio && \
    adduser -S -D -H -u 1000 -G minio minio && \
    mkdir /data && chown 1000:1000 /data
LABEL org.opencontainers.image.source="https://github.com/minio/minio" \
      org.opencontainers.image.revision="9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a"
COPY --from=build /out/minio /usr/bin/minio
COPY --from=build /out/LICENSE.minio /usr/share/licenses/minio/LICENSE
ENV HOME=/tmp \
    GOMAXPROCS=2 \
    GOMEMLIMIT=768MiB
USER 1000:1000
WORKDIR /data
EXPOSE 9000 9001
ENTRYPOINT ["/usr/bin/minio"]
CMD ["server", "/data", "--console-address", ":9001"]
