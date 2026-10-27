ARG GO_IMAGE=golang:1.23-bookworm@sha256:167053a2bb901972bf2c1611f8f52c44d5fe7e762e5cab213708d82c421614db
ARG DISTROLESS_IMAGE=gcr.io/distroless/base-debian12@sha256:76b3162a31477bca4a245b836c624f4c4a1a3705e99b9003907d992bec2c4bca

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/grpc-unary-fixture ./main.go

FROM ${DISTROLESS_IMAGE}
COPY --from=build /out/grpc-unary-fixture /usr/local/bin/grpc-unary-fixture
EXPOSE 8081 8443
ENTRYPOINT ["/usr/local/bin/grpc-unary-fixture"]
