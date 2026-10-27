ARG GO_IMAGE=golang:1.23-bookworm@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db
ARG DISTROLESS_IMAGE=gcr.io/distroless/base-debian12@sha256:76b3162a31477bca4a245b836c624f4c4a1a3705e99b9003907d992bec2c4bca

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY api/gen ./api/gen
COPY control-plane/go.mod control-plane/go.sum ./control-plane/
RUN cd control-plane && go mod download
COPY tests/fixtures/http2-deadline ./control-plane/http2-deadline
RUN cd control-plane && go test -mod=readonly ./http2-deadline \
    && CGO_ENABLED=0 go build -mod=readonly -trimpath -ldflags='-s -w' -o /out/http2-deadline ./http2-deadline

FROM ${DISTROLESS_IMAGE}
COPY --from=build /out/http2-deadline /usr/local/bin/http2-deadline
ENTRYPOINT ["/usr/local/bin/http2-deadline"]
