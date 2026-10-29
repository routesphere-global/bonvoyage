ARG GO_IMAGE=golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb
ARG DISTROLESS_IMAGE=gcr.io/distroless/base-debian12@sha256:76b3162a31477bca4a245b836c624f4c4a1a3705e99b9003907d992bec2c4bca

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY api/gen ./api/gen
COPY tests/fixtures/phase3-scale/go.mod tests/fixtures/phase3-scale/go.sum ./tests/fixtures/phase3-scale/
WORKDIR /src/tests/fixtures/phase3-scale
RUN go mod download
COPY tests/fixtures/phase3-scale/main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /out/phase3-scale-fixture ./main.go

FROM ${DISTROLESS_IMAGE}
COPY --from=build /out/phase3-scale-fixture /usr/local/bin/phase3-scale-fixture
USER 65532:65532
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/phase3-scale-fixture"]
