ARG GO_IMAGE=golang:1.26.10-bookworm@sha256:23ce71337b726608afb1bc00986e630a05034a87a87ea1fc2cd1ae5cf33387eb
ARG DISTROLESS_IMAGE=gcr.io/distroless/base-debian12@sha256:76b3162a31477bca4a245b836c624f4c4a1a3705e99b9003907d992bec2c4bca

FROM ${GO_IMAGE} AS build
WORKDIR /src
COPY api/gen ./api/gen
COPY control-plane/go.mod control-plane/go.sum ./control-plane/
RUN cd control-plane && go mod download
COPY control-plane ./control-plane
RUN cd control-plane && go build -o /out/bonvoyage-control-plane ./cmd/bonvoyage-control-plane
RUN mkdir -p /out/state && chown 65532:65532 /out/state

FROM ${DISTROLESS_IMAGE}

LABEL org.opencontainers.image.title="RouteSphere BonVoyage Snapshot Compiler" \
      org.opencontainers.image.description="Static BonVoyage YAML-to-Protobuf compiler" \
      org.opencontainers.image.version="0.2.0" \
      org.opencontainers.image.vendor="RouteSphere"

COPY --from=build /out/bonvoyage-control-plane /usr/local/bin/bonvoyage-control-plane
COPY --from=build --chown=65532:65532 /out/state /var/lib/bonvoyage
USER 65532:65532
ENTRYPOINT ["/usr/local/bin/bonvoyage-control-plane"]
