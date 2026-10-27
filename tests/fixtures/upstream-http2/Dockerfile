ARG GO_IMAGE=golang:1.23-bookworm@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db
ARG DISTROLESS_IMAGE=gcr.io/distroless/base-debian12@sha256:76b3162a31477bca4a245b836c624f4c4a1a3705e99b9003907d992bec2c4bca

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/upstream-http2-fixture ./main.go

FROM ${DISTROLESS_IMAGE}
COPY --from=build /out/upstream-http2-fixture /usr/local/bin/upstream-http2-fixture
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/upstream-http2-fixture"]
