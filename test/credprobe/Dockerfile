# The in-cluster credential probe used by the e2e suite (see test/credprobe).
#
# It is built from this repository rather than pulled, so a CI runner that can
# run `make test-e2e` can run these specs: there is no third-party workload
# image to publish, pin or keep available. The build copies only the module
# files and the probe itself - the probe imports nothing outside the standard
# library and its own report package, so there is nothing to download.
#
# The base images and their digests are deliberately the same as the manager's
# (see the repository root Dockerfile); refresh them together.
FROM golang:1.27.1@sha256:f44f6e88636cfb311f9ebace870ded69d943f227bb3cb27d32ffd84ea18c43ea AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace
COPY go.mod go.mod
COPY go.sum go.sum
COPY test/credprobe test/credprobe

RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -a -trimpath -ldflags="-s -w" -o credprobe ./test/credprobe

FROM gcr.io/distroless/static:nonroot@sha256:1c2c046bc09ed40fad370b599a0b1ae7987f55b01e247cf27a7c27cd97e5bbc7
LABEL org.opencontainers.image.source=https://github.com/rafpe/pod-certificate-signer
WORKDIR /
COPY --from=builder /workspace/credprobe .
# The same non-root uid the workload fixtures run as, so "readable by the
# container's user" is a claim about an unprivileged reader.
USER 65532:65532

ENTRYPOINT ["/credprobe"]
