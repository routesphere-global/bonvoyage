# syntax=docker/dockerfile:1.7

ARG BONVOYAGE_FUZZ_BASE
FROM ${BONVOYAGE_FUZZ_BASE} AS http2-fuzz-build

ARG BONVOYAGE_BUILD_JOBS=2

USER root
ENV DEBIAN_FRONTEND=noninteractive
ENV CC=clang-18
ENV CXX=clang++-18

WORKDIR /usr/src/bonvoyage

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        clang-18 cmake libclang-rt-18-dev ninja-build xxd \
    && rm -rf /var/lib/apt/lists/*

COPY dataplane/include/ dataplane/include/
COPY dataplane/src/http2_client_session.cc \
  dataplane/src/http2_client_session.cc
COPY dataplane/src/http2_session.cc dataplane/src/http2_session.cc
COPY dataplane/src/upstream_response_head_parser.cc \
  dataplane/src/upstream_response_head_parser.cc
COPY dataplane/fuzz/ dataplane/fuzz/

RUN cmake \
      -S dataplane/fuzz \
      -B build/protocol-fuzz \
      -G Ninja \
      -DCMAKE_BUILD_TYPE=RelWithDebInfo \
      "-DCMAKE_PREFIX_PATH=/opt/nghttp2;/opt/llhttp" \
    && cmake --build build/protocol-fuzz \
      --target bonvoyage-http2-session-fuzz \
        bonvoyage-http2-client-session-fuzz \
        bonvoyage-upstream-response-head-fuzz \
      --parallel "${BONVOYAGE_BUILD_JOBS}"

RUN install -D -m 0755 dataplane/fuzz/run-http2-fuzz.sh \
      /usr/local/bin/run-http2-fuzz \
    && install -D -m 0755 dataplane/fuzz/run-upstream-http1-fuzz.sh \
      /usr/local/bin/run-upstream-http1-fuzz \
    && install -d /opt/bonvoyage-http2-fuzz/corpus \
    && for seed in dataplane/fuzz/corpus/*.hex; do \
         name="$(basename "${seed}" .hex)"; \
         tr -d '[:space:]' < "${seed}" \
           | xxd -r -p > "/opt/bonvoyage-http2-fuzz/corpus/${name}"; \
       done \
    && test "$(find /opt/bonvoyage-http2-fuzz/corpus -type f | wc -l)" -ge 5 \
    && install -D -m 0644 dataplane/fuzz/http2.dict \
      /opt/bonvoyage-http2-fuzz/http2.dict \
    && install -d /opt/bonvoyage-upstream-http1-fuzz/corpus \
    && for seed in dataplane/fuzz/http1-corpus/*.hex; do \
         name="$(basename "${seed}" .hex)"; \
         tr -d '[:space:]' < "${seed}" \
           | xxd -r -p > "/opt/bonvoyage-upstream-http1-fuzz/corpus/${name}"; \
       done \
    && test "$(find /opt/bonvoyage-upstream-http1-fuzz/corpus -type f | wc -l)" -ge 3 \
    && install -D -m 0644 dataplane/fuzz/http1.dict \
      /opt/bonvoyage-upstream-http1-fuzz/http1.dict

ENTRYPOINT ["/usr/local/bin/run-http2-fuzz"]
