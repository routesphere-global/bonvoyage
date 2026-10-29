ARG GO_IMAGE=golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb
ARG DISTROLESS_IMAGE=gcr.io/distroless/base-debian12@sha256:76b3162a31477bca4a245b836c624f4c4a1a3705e99b9003907d992bec2c4bca

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY api/gen ./api/gen
COPY control-plane/go.mod control-plane/go.sum ./control-plane/
RUN cd control-plane && go mod download
COPY tests/fixtures/perf05-sse ./control-plane/perf05-sse
RUN cd control-plane && go test -mod=readonly ./perf05-sse \
    && CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags='-s -w' \
      -o /out/perf05-sse ./perf05-sse

FROM ${DISTROLESS_IMAGE}
COPY --from=build /out/perf05-sse /usr/local/bin/perf05-sse
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/perf05-sse"]

