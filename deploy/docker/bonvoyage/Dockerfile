# syntax=docker/dockerfile:1.7

ARG UBUNTU_IMAGE=ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea

FROM ${UBUNTU_IMAGE} AS libjwt-build

ARG LIBJWT_VERSION=3.6.1
ARG LIBJWT_COMMIT=f4edfe5b2c44ac57edf00342550e81017f5329eb
ARG LIBJWT_SHA256=b483a5f77e548964553f54a0ec5f0c810cc6c0629c5ac5a03610bcced150e7be
ARG LIBJWT_PATCH_SHA256=7a554ca5ad4cd330a875d9c0fb2c91c77f7d34eab2c3bddf3c008b5c24d37190
ARG BONVOYAGE_ENABLE_SANITIZERS=OFF
ARG BUILD_JOBS=2

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        cmake gcc libc6-dev libjansson-dev libssl-dev ninja-build patch \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

ADD --checksum=sha256:b483a5f77e548964553f54a0ec5f0c810cc6c0629c5ac5a03610bcced150e7be \
    https://github.com/benmcollins/libjwt/archive/refs/tags/v3.6.1.tar.gz \
    /tmp/libjwt.tar.gz

COPY deploy/docker/bonvoyage/patches/libjwt-jwks-reject-duplicates.patch \
    /tmp/libjwt-jwks-reject-duplicates.patch

RUN case "${BONVOYAGE_ENABLE_SANITIZERS}" in \
      ''|0|[Oo][Ff][Ff]|[Nn][Oo]|[Ff][Aa][Ll][Ss][Ee]|[Nn]|[Ii][Gg][Nn][Oo][Rr][Ee]|[Nn][Oo][Tt][Ff][Oo][Uu][Nn][Dd]|*-[Nn][Oo][Tt][Ff][Oo][Uu][Nn][Dd]) sanitizer_flags='' ;; \
      *) sanitizer_flags='-fno-omit-frame-pointer -fno-sanitize-recover=undefined -fsanitize=address,undefined -Wno-error=stringop-truncation' ;; \
    esac \
    && test "${LIBJWT_VERSION}" = "3.6.1" \
    && test "${LIBJWT_COMMIT}" = "f4edfe5b2c44ac57edf00342550e81017f5329eb" \
    && echo "${LIBJWT_SHA256}  /tmp/libjwt.tar.gz" | sha256sum --check \
    && echo "${LIBJWT_PATCH_SHA256}  /tmp/libjwt-jwks-reject-duplicates.patch" \
        | sha256sum --check \
    && mkdir -p /usr/src/libjwt \
    && tar -xzf /tmp/libjwt.tar.gz --strip-components=1 -C /usr/src/libjwt \
    && grep -Fq 'set(LIBJWT_VERSION_SET' /usr/src/libjwt/cmake/LibJWTVersions.cmake \
    && grep -Fq '3 6 1' /usr/src/libjwt/cmake/LibJWTVersions.cmake \
    && patch --directory=/usr/src/libjwt --strip=1 --forward --fuzz=0 \
        --input=/tmp/libjwt-jwks-reject-duplicates.patch \
    && cmake \
      -S /usr/src/libjwt \
      -B /usr/src/libjwt/build \
      -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/opt/libjwt \
      "-DCMAKE_C_FLAGS=${sanitizer_flags}" \
      -DWITH_GNUTLS=OFF \
      -DWITH_MBEDTLS=OFF \
      -DWITH_OPENSSL=ON \
      -DWITH_LIBCURL=OFF \
      -DWITH_JSON_C=OFF \
      -DWITH_ML_DSA=OFF \
      -DWITH_TESTS=OFF \
      -DEXCLUDE_DEPRECATED=ON \
    && cmake --build /usr/src/libjwt/build --parallel "${BUILD_JOBS}" \
    && cmake --install /usr/src/libjwt/build \
    && install -D /usr/src/libjwt/LICENSE \
        /opt/libjwt/share/licenses/libjwt/LICENSE \
    && test -f /opt/libjwt/include/jwt.h \
    && test -f /opt/libjwt/lib/libjwt.a

FROM ${UBUNTU_IMAGE} AS nghttp2-build

ARG NGHTTP2_VERSION=1.70.0
ARG NGHTTP2_COMMIT=85e300c79fb6dbcfa9c1013215c8710c1c2cd3d2
ARG NGHTTP2_SHA256=aa317e2cf9dca6afa0aed68f8fad6ff303ec6982e25a78c75c0b65e2b9b3ded5
ARG NGHTTP2_PATCH_SHA256=f12e0774244c8fa060b04d57b02a467183a009081f51bb79127c408ce504a130
ARG BONVOYAGE_ENABLE_SANITIZERS=OFF
ARG BUILD_JOBS=2

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        cmake gcc libc6-dev ninja-build patch \
    && rm -rf /var/lib/apt/lists/*

ADD --checksum=sha256:aa317e2cf9dca6afa0aed68f8fad6ff303ec6982e25a78c75c0b65e2b9b3ded5 \
    https://github.com/nghttp2/nghttp2/releases/download/v1.70.0/nghttp2-1.70.0.tar.gz \
    /tmp/nghttp2.tar.gz

COPY deploy/docker/bonvoyage/patches/nghttp2-rfc9113-stream-errors.patch \
    /tmp/nghttp2-rfc9113-stream-errors.patch

RUN case "${BONVOYAGE_ENABLE_SANITIZERS}" in \
      ''|0|[Oo][Ff][Ff]|[Nn][Oo]|[Ff][Aa][Ll][Ss][Ee]|[Nn]|[Ii][Gg][Nn][Oo][Rr][Ee]|[Nn][Oo][Tt][Ff][Oo][Uu][Nn][Dd]|*-[Nn][Oo][Tt][Ff][Oo][Uu][Nn][Dd]) sanitizer_flags='' ;; \
      *) sanitizer_flags='-fno-omit-frame-pointer -fno-sanitize-recover=undefined -fsanitize=address,undefined' ;; \
    esac \
    && test "${NGHTTP2_VERSION}" = "1.70.0" \
    && test "${NGHTTP2_COMMIT}" = "85e300c79fb6dbcfa9c1013215c8710c1c2cd3d2" \
    && echo "${NGHTTP2_SHA256}  /tmp/nghttp2.tar.gz" | sha256sum --check \
    && echo "${NGHTTP2_PATCH_SHA256}  /tmp/nghttp2-rfc9113-stream-errors.patch" \
        | sha256sum --check \
    && mkdir -p /usr/src/nghttp2 \
    && tar -xzf /tmp/nghttp2.tar.gz --strip-components=1 -C /usr/src/nghttp2 \
    && grep -Fq 'project(nghttp2 VERSION 1.70.0 LANGUAGES C)' \
        /usr/src/nghttp2/CMakeLists.txt \
    && patch --directory=/usr/src/nghttp2 --strip=1 --forward --fuzz=0 \
        --input=/tmp/nghttp2-rfc9113-stream-errors.patch \
    && cmake \
      -S /usr/src/nghttp2 \
      -B /usr/src/nghttp2/build \
      -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/opt/nghttp2 \
      "-DCMAKE_C_FLAGS=${sanitizer_flags}" \
      -DENABLE_LIB_ONLY=ON \
      -DENABLE_DOC=OFF \
      -DBUILD_SHARED_LIBS=OFF \
      -DBUILD_STATIC_LIBS=ON \
      -DBUILD_TESTING=OFF \
    && cmake --build /usr/src/nghttp2/build --parallel "${BUILD_JOBS}" \
    && cmake --install /usr/src/nghttp2/build \
    && install -D /usr/src/nghttp2/COPYING \
        /opt/nghttp2/share/licenses/nghttp2/COPYING \
    && test -f /opt/nghttp2/lib/libnghttp2.a \
    && test -f /opt/nghttp2/lib/cmake/nghttp2/nghttp2Config.cmake

FROM ${UBUNTU_IMAGE} AS llhttp-build

ARG LLHTTP_VERSION=9.4.3
ARG LLHTTP_COMMIT=0e815792b167a9bd8ace259b95b7da953776c288
ARG LLHTTP_SHA256=1eb813c7437b31a87496a1cd3ed79f00746720f5e7e29c79b42c02cb69f36c39
ARG BONVOYAGE_ENABLE_SANITIZERS=OFF
ARG BUILD_JOBS=2

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        cmake gcc g++ libc6-dev ninja-build \
    && rm -rf /var/lib/apt/lists/*

ADD --checksum=sha256:1eb813c7437b31a87496a1cd3ed79f00746720f5e7e29c79b42c02cb69f36c39 \
    https://github.com/nodejs/llhttp/archive/refs/tags/release/v9.4.3.tar.gz \
    /tmp/llhttp.tar.gz

RUN case "${BONVOYAGE_ENABLE_SANITIZERS}" in \
      ''|0|[Oo][Ff][Ff]|[Nn][Oo]|[Ff][Aa][Ll][Ss][Ee]|[Nn]|[Ii][Gg][Nn][Oo][Rr][Ee]|[Nn][Oo][Tt][Ff][Oo][Uu][Nn][Dd]|*-[Nn][Oo][Tt][Ff][Oo][Uu][Nn][Dd]) sanitizer_flags='' ;; \
      *) sanitizer_flags='-fno-omit-frame-pointer -fno-sanitize-recover=undefined -fsanitize=address,undefined' ;; \
    esac \
    && test "${LLHTTP_VERSION}" = "9.4.3" \
    && test "${LLHTTP_COMMIT}" = "0e815792b167a9bd8ace259b95b7da953776c288" \
    && echo "${LLHTTP_SHA256}  /tmp/llhttp.tar.gz" | sha256sum --check \
    && mkdir -p /usr/src/llhttp \
    && tar -xzf /tmp/llhttp.tar.gz --strip-components=1 -C /usr/src/llhttp \
    && grep -Fq 'project(llhttp VERSION 9.4.3)' /usr/src/llhttp/CMakeLists.txt \
    && cmake \
      -S /usr/src/llhttp \
      -B /usr/src/llhttp/build \
      -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/opt/llhttp \
      "-DCMAKE_C_FLAGS=${sanitizer_flags}" \
      -DLLHTTP_BUILD_SHARED_LIBS=OFF \
      -DLLHTTP_BUILD_STATIC_LIBS=ON \
    && cmake --build /usr/src/llhttp/build --parallel "${BUILD_JOBS}" \
    && cmake --install /usr/src/llhttp/build \
    && install -D /usr/src/llhttp/LICENSE-MIT \
        /opt/llhttp/share/licenses/llhttp/LICENSE-MIT \
    && test -f /opt/llhttp/lib/libllhttp.a \
    && test -f /opt/llhttp/lib/cmake/llhttp/llhttpConfig.cmake

FROM ${UBUNTU_IMAGE} AS protocol-fuzz-dependencies

COPY --from=nghttp2-build /opt/nghttp2 /opt/nghttp2
COPY --from=llhttp-build /opt/llhttp /opt/llhttp

FROM ${UBUNTU_IMAGE} AS re2-build

ARG ABSEIL_VERSION=20250512.1
ARG ABSEIL_COMMIT=76bb24329e8bf5f39704eb10d21b9a80befa7c81
ARG ABSEIL_SHA256=9b7a064305e9fd94d124ffa6cc358592eb42b5da588fb4e07d09254aa40086db
ARG RE2_VERSION=2025-11-05
ARG RE2_COMMIT=927f5d53caf8111721e734cf24724686bb745f55
ARG RE2_SHA256=87f6029d2f6de8aa023654240a03ada90e876ce9a4676e258dd01ea4c26ffd67
ARG BONVOYAGE_ENABLE_SANITIZERS=OFF
ARG BUILD_JOBS=2

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        cmake g++ libc6-dev ninja-build \
    && rm -rf /var/lib/apt/lists/*

ADD --checksum=sha256:9b7a064305e9fd94d124ffa6cc358592eb42b5da588fb4e07d09254aa40086db \
    https://github.com/abseil/abseil-cpp/releases/download/20250512.1/abseil-cpp-20250512.1.tar.gz \
    /tmp/abseil.tar.gz
ADD --checksum=sha256:87f6029d2f6de8aa023654240a03ada90e876ce9a4676e258dd01ea4c26ffd67 \
    https://github.com/google/re2/releases/download/2025-11-05/re2-2025-11-05.tar.gz \
    /tmp/re2.tar.gz

# GCC UBSan cannot constant-evaluate an Abseil hash helper (abseil/abseil-cpp#1634).
# Abseil and RE2 stay under ASan; BonVoyage retains full ASan+UBSan coverage.
RUN case "${BONVOYAGE_ENABLE_SANITIZERS}" in \
      ''|0|[Oo][Ff][Ff]|[Nn][Oo]|[Ff][Aa][Ll][Ss][Ee]|[Nn]|[Ii][Gg][Nn][Oo][Rr][Ee]|*-[Nn][Oo][Tt][Ff][Oo][Uu][Nn][Dd]) sanitizer_flags='' ;; \
      *) sanitizer_flags='-fno-omit-frame-pointer -fno-sanitize-recover=undefined -fsanitize=address,undefined' ;; \
    esac \
    && test "${ABSEIL_VERSION}" = "20250512.1" \
    && test "${ABSEIL_COMMIT}" = "76bb24329e8bf5f39704eb10d21b9a80befa7c81" \
    && test "${RE2_VERSION}" = "2025-11-05" \
    && test "${RE2_COMMIT}" = "927f5d53caf8111721e734cf24724686bb745f55" \
    && echo "${ABSEIL_SHA256}  /tmp/abseil.tar.gz" | sha256sum --check \
    && echo "${RE2_SHA256}  /tmp/re2.tar.gz" | sha256sum --check \
    && mkdir -p /usr/src/abseil /usr/src/re2 \
    && tar -xzf /tmp/abseil.tar.gz --strip-components=1 -C /usr/src/abseil \
    && tar -xzf /tmp/re2.tar.gz --strip-components=1 -C /usr/src/re2 \
    && grep -Fq '#define ABSL_LTS_RELEASE_VERSION 20250512' \
        /usr/src/abseil/absl/base/config.h \
    && grep -Fq '#define ABSL_LTS_RELEASE_PATCH_LEVEL 1' \
        /usr/src/abseil/absl/base/config.h \
    && cmake \
      -S /usr/src/abseil \
      -B /usr/src/abseil/build \
      -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/opt/abseil \
      -DCMAKE_CXX_STANDARD=20 \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
      "-DCMAKE_CXX_FLAGS=${sanitizer_flags:+-fno-omit-frame-pointer -fsanitize=address}" \
      -DABSL_BUILD_TESTING=OFF \
      -DABSL_ENABLE_INSTALL=ON \
      -DABSL_PROPAGATE_CXX_STD=ON \
      -DBUILD_SHARED_LIBS=OFF \
    && cmake --build /usr/src/abseil/build --parallel "${BUILD_JOBS}" \
    && cmake --install /usr/src/abseil/build \
    && cmake \
      -S /usr/src/re2 \
      -B /usr/src/re2/build \
      -G Ninja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_INSTALL_PREFIX=/opt/re2 \
      -DCMAKE_PREFIX_PATH=/opt/abseil \
      -DCMAKE_CXX_STANDARD=20 \
      -DCMAKE_POSITION_INDEPENDENT_CODE=ON \
      "-DCMAKE_CXX_FLAGS=${sanitizer_flags:+-fno-omit-frame-pointer -fsanitize=address}" \
      -DBUILD_SHARED_LIBS=OFF \
      -DRE2_BUILD_TESTING=OFF \
      -DRE2_USE_ICU=OFF \
    && cmake --build /usr/src/re2/build --parallel "${BUILD_JOBS}" \
    && cmake --install /usr/src/re2/build \
    && install -D /usr/src/abseil/LICENSE \
        /opt/abseil/share/licenses/abseil/LICENSE \
    && install -D /usr/src/re2/LICENSE \
        /opt/re2/share/licenses/re2/LICENSE \
    && test -f /opt/re2/lib/libre2.a \
    && test -f /opt/re2/lib/cmake/re2/re2Config.cmake

FROM ${UBUNTU_IMAGE} AS cares-build

ARG BONVOYAGE_ENABLE_SANITIZERS=OFF
ARG BUILD_JOBS=2
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake gcc libc6-dev ninja-build \
    && rm -rf /var/lib/apt/lists/*

ADD --checksum=sha256:c222b6d681096f9444d2c4863d2c1174019e27cacca0a4a5c114d36dd7d7bf78 \
    https://github.com/c-ares/c-ares/releases/download/v1.34.8/c-ares-1.34.8.tar.gz \
    /tmp/c-ares.tar.gz

RUN case "${BONVOYAGE_ENABLE_SANITIZERS}" in \
      ''|0|[Oo][Ff][Ff]|[Nn][Oo]|[Ff][Aa][Ll][Ss][Ee]|[Nn]|[Ii][Gg][Nn][Oo][Rr][Ee]|[Nn][Oo][Tt][Ff][Oo][Uu][Nn][Dd]|*-[Nn][Oo][Tt][Ff][Oo][Uu][Nn][Dd]) sanitizer_flags='' ;; \
      *) sanitizer_flags='-fno-omit-frame-pointer -fno-sanitize-recover=undefined -fsanitize=address,undefined' ;; \
    esac \
    && mkdir -p /usr/src/c-ares \
    && tar -xzf /tmp/c-ares.tar.gz --strip-components=1 -C /usr/src/c-ares \
    && cmake -S /usr/src/c-ares -B /usr/src/c-ares/build -G Ninja \
      -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/opt/c-ares \
      -DCMAKE_INSTALL_LIBDIR=lib "-DCMAKE_C_FLAGS=${sanitizer_flags}" \
      -DCARES_STATIC=ON -DCARES_SHARED=OFF -DCARES_STATIC_PIC=ON \
      -DCARES_THREADS=ON -DCARES_BUILD_TOOLS=OFF -DCARES_BUILD_TESTS=OFF \
    && cmake --build /usr/src/c-ares/build --parallel "${BUILD_JOBS}" \
    && cmake --install /usr/src/c-ares/build \
    && install -D /usr/src/c-ares/LICENSE.md \
      /opt/c-ares/share/licenses/c-ares/LICENSE.md \
    && test -f /opt/c-ares/lib/libcares.a

FROM ${UBUNTU_IMAGE} AS seastar-build

ARG SEASTAR_VERSION=seastar-25.05.0
ARG SEASTAR_COMMIT=8df8212e53577e1d8477a5c901457cd61d88afc7
ARG SEASTAR_MODE=release
ARG BUILD_JOBS=2

ENV DEBIAN_FRONTEND=noninteractive
ENV CC=gcc-13
ENV CXX=g++-13
ENV PKG_CONFIG_PATH=/opt/c-ares/lib/pkgconfig

COPY --from=cares-build /opt/c-ares /opt/c-ares

# An index refresh alone does not upgrade an already satisfied transitive libudev.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates git libjansson4 libudev1 \
    && git clone --filter=blob:none --no-checkout \
        https://github.com/scylladb/seastar.git /usr/src/seastar \
    && git -C /usr/src/seastar checkout --detach "${SEASTAR_COMMIT}" \
    && test "$(git -C /usr/src/seastar rev-parse HEAD)" = "${SEASTAR_COMMIT}" \
    && test "$(git -C /usr/src/seastar describe --tags --exact-match)" = "${SEASTAR_VERSION}" \
    && /usr/src/seastar/install-dependencies.sh \
    && rm -rf /var/lib/apt/lists/*

COPY deploy/docker/bonvoyage/patches/seastar-http-client-lazy-trace.patch \
    /tmp/seastar-http-client-lazy-trace.patch
COPY deploy/docker/bonvoyage/patches/seastar-tls-server-metadata.patch \
    /tmp/seastar-tls-server-metadata.patch
COPY deploy/docker/bonvoyage/patches/seastar-tls-certificate-policy.patch \
    /tmp/seastar-tls-certificate-policy.patch
COPY deploy/docker/bonvoyage/patches/seastar-http-client-bounded-chunks.patch \
    /tmp/seastar-http-client-bounded-chunks.patch
COPY deploy/docker/bonvoyage/patches/seastar-http-client-pool-wait-observer.patch \
    /tmp/seastar-http-client-pool-wait-observer.patch
COPY deploy/docker/bonvoyage/patches/seastar-dns-disable-query-cache.patch \
    /tmp/seastar-dns-disable-query-cache.patch
COPY deploy/docker/bonvoyage/patches/seastar-ascii-case-insensitive-headers.patch \
    /tmp/seastar-ascii-case-insensitive-headers.patch
COPY deploy/docker/bonvoyage/patches/seastar-bounded-log-hook.patch \
    /tmp/seastar-bounded-log-hook.patch

ARG SEASTAR_LAZY_TRACE_PATCH_SHA256=b924fd7df2910655543d59a4550fc0d0590e6a8d131dc752b166d11f4ad99e7a
ARG SEASTAR_TLS_METADATA_PATCH_SHA256=3d0ac49a8097f7759246fbefb90b27cbcd7c8f7df30b64ca42a97b9625263cbb
ARG SEASTAR_TLS_CERTIFICATE_POLICY_PATCH_SHA256=8eca7ce0d448d05987288af53ac4282d54362e1fd11fc6d7c65b4cce1bab6f2f
ARG SEASTAR_BOUNDED_CHUNKS_PATCH_SHA256=20c7879ebb89ad3808883c7ed8cc2af1e5fc73b44a18b1973aac2de37e921ce5
ARG SEASTAR_POOL_WAIT_PATCH_SHA256=176c01ecf63925110764eba05c637882960643a3fbb4c3873acea288238e43d1
ARG SEASTAR_DNS_CACHE_PATCH_SHA256=ddf8a8e5f40839f95382541df84a48cea64aa8e0754988eb86de9bb96c50b17e
ARG SEASTAR_ASCII_HEADERS_PATCH_SHA256=b29aeced29f3e4a7ca9bf2256b68f776e6687dfd283de9c38e9c0299620e99c8
ARG SEASTAR_BOUNDED_LOG_PATCH_SHA256=7e182385e0613c0ee0801d654fa8a5d96c09751d36489c54e37eae67ee06b9a7

# Keep the local dependency delta explicit, content-addressed, and fail-closed.
RUN echo "${SEASTAR_LAZY_TRACE_PATCH_SHA256}  /tmp/seastar-http-client-lazy-trace.patch" \
      | sha256sum --check \
    && echo "${SEASTAR_TLS_METADATA_PATCH_SHA256}  /tmp/seastar-tls-server-metadata.patch" \
      | sha256sum --check \
    && echo "${SEASTAR_TLS_CERTIFICATE_POLICY_PATCH_SHA256}  /tmp/seastar-tls-certificate-policy.patch" \
      | sha256sum --check \
    && echo "${SEASTAR_BOUNDED_CHUNKS_PATCH_SHA256}  /tmp/seastar-http-client-bounded-chunks.patch" \
      | sha256sum --check \
    && echo "${SEASTAR_POOL_WAIT_PATCH_SHA256}  /tmp/seastar-http-client-pool-wait-observer.patch" \
      | sha256sum --check \
    && echo "${SEASTAR_DNS_CACHE_PATCH_SHA256}  /tmp/seastar-dns-disable-query-cache.patch" \
      | sha256sum --check \
    && echo "${SEASTAR_ASCII_HEADERS_PATCH_SHA256}  /tmp/seastar-ascii-case-insensitive-headers.patch" \
      | sha256sum --check \
    && echo "${SEASTAR_BOUNDED_LOG_PATCH_SHA256}  /tmp/seastar-bounded-log-hook.patch" \
      | sha256sum --check \
    && git -C /usr/src/seastar apply --check \
      /tmp/seastar-http-client-lazy-trace.patch \
    && git -C /usr/src/seastar apply \
      /tmp/seastar-http-client-lazy-trace.patch \
    && git -C /usr/src/seastar apply --check \
      /tmp/seastar-tls-server-metadata.patch \
    && git -C /usr/src/seastar apply \
      /tmp/seastar-tls-server-metadata.patch \
    && git -C /usr/src/seastar apply --check \
      /tmp/seastar-tls-certificate-policy.patch \
    && git -C /usr/src/seastar apply \
      /tmp/seastar-tls-certificate-policy.patch \
    && git -C /usr/src/seastar apply --check \
      /tmp/seastar-http-client-bounded-chunks.patch \
    && git -C /usr/src/seastar apply \
      /tmp/seastar-http-client-bounded-chunks.patch \
    && git -C /usr/src/seastar apply --check \
      /tmp/seastar-http-client-pool-wait-observer.patch \
    && git -C /usr/src/seastar apply \
      /tmp/seastar-http-client-pool-wait-observer.patch \
    && git -C /usr/src/seastar apply --check \
      /tmp/seastar-dns-disable-query-cache.patch \
    && git -C /usr/src/seastar apply \
      /tmp/seastar-dns-disable-query-cache.patch \
    && git -C /usr/src/seastar apply --check \
      /tmp/seastar-ascii-case-insensitive-headers.patch \
    && git -C /usr/src/seastar apply \
      /tmp/seastar-ascii-case-insensitive-headers.patch \
    && git -C /usr/src/seastar apply --check \
      /tmp/seastar-bounded-log-hook.patch \
    && git -C /usr/src/seastar apply \
      /tmp/seastar-bounded-log-hook.patch

WORKDIR /usr/src/seastar

RUN ./configure.py \
      --mode="${SEASTAR_MODE}" \
      --prefix=/opt/seastar \
      --c++-standard=20 \
      --disable-dpdk \
      --disable-cxx-modules \
      --without-tests \
      --without-apps \
      --without-demos \
      --compile-commands-json \
    && grep -Fxq 'c-ares_LIBRARY:FILEPATH=/opt/c-ares/lib/libcares.a' "build/${SEASTAR_MODE}/CMakeCache.txt" \
    && grep -Fxq 'c-ares_INCLUDE_DIR:PATH=/opt/c-ares/include' "build/${SEASTAR_MODE}/CMakeCache.txt" \
    && ninja -C "build/${SEASTAR_MODE}" -j "${BUILD_JOBS}" install

FROM seastar-build AS bonvoyage-build

ARG SEASTAR_MODE
ARG BONVOYAGE_BUILD_TYPE=RelWithDebInfo
ARG BONVOYAGE_ENABLE_SANITIZERS=OFF
ARG BONVOYAGE_BUILD_DOCUMENTATION=OFF
ARG BONVOYAGE_RUN_RUNTIME_TESTS=ON
ARG BONVOYAGE_UPSTREAM_HTTP1_CLIENT=seastar-reference
ARG BUILD_JOBS=2

WORKDIR /usr/src/bonvoyage
COPY --from=libjwt-build /opt/libjwt /opt/libjwt
COPY --from=nghttp2-build /opt/nghttp2 /opt/nghttp2
COPY --from=llhttp-build /opt/llhttp /opt/llhttp
COPY --from=re2-build /opt/abseil /opt/abseil
COPY --from=re2-build /opt/re2 /opt/re2
COPY dataplane/ ./dataplane/
COPY api/ ./api/
COPY third_party/ ./third_party/
COPY security/dependencies/nghttp2-1.70.0.json \
    /tmp/bonvoyage-dependencies/nghttp2-1.70.0.json
COPY security/dependencies/libjwt-3.6.1.json \
    /tmp/bonvoyage-dependencies/libjwt-3.6.1.json
COPY security/dependencies/seastar-25.05.0.json \
    /tmp/bonvoyage-dependencies/seastar-25.05.0.json
COPY security/dependencies/c-ares-1.34.8.json \
    /tmp/bonvoyage-dependencies/c-ares-1.34.8.json
COPY security/dependencies/abseil-20250512.1.json \
    /tmp/bonvoyage-dependencies/abseil-20250512.1.json
COPY security/dependencies/re2-2025-11-05.json \
    /tmp/bonvoyage-dependencies/re2-2025-11-05.json
COPY security/dependencies/opentelemetry-proto-1.11.0.json \
    /tmp/bonvoyage-dependencies/opentelemetry-proto-1.11.0.json
COPY security/dependencies/llhttp-9.4.3.json \
    /tmp/bonvoyage-dependencies/llhttp-9.4.3.json

# Seastar's release allocator and ASan both interpose malloc. Every CMake-truthy
# sanitizer value must therefore select Seastar's system-allocator mode.
# Its exported debug-layout macros also require the matching consumer config.
RUN case "${BONVOYAGE_ENABLE_SANITIZERS}" in \
      ''|0|[Oo][Ff][Ff]|[Nn][Oo]|[Ff][Aa][Ll][Ss][Ee]|[Nn]|[Ii][Gg][Nn][Oo][Rr][Ee]|[Nn][Oo][Tt][Ff][Oo][Uu][Nn][Dd]|*-[Nn][Oo][Tt][Ff][Oo][Uu][Nn][Dd]) ;; \
      *) if [ "${SEASTAR_MODE}" != "sanitize" ]; then \
           echo "sanitizer builds require SEASTAR_MODE=sanitize" >&2; \
           exit 2; \
         fi ;; \
    esac \
    && if [ "${SEASTAR_MODE}" = "sanitize" ] && \
          [ "${BONVOYAGE_BUILD_TYPE}" != "Sanitize" ]; then \
         echo "Seastar sanitize requires BONVOYAGE_BUILD_TYPE=Sanitize for ABI compatibility" >&2; \
         exit 2; \
       fi \
    && if [ "${BONVOYAGE_BUILD_TYPE}" = "Sanitize" ] && \
          [ "${SEASTAR_MODE}" != "sanitize" ]; then \
         echo "BONVOYAGE_BUILD_TYPE=Sanitize requires SEASTAR_MODE=sanitize" >&2; \
         exit 2; \
       fi

RUN cmake \
      -S dataplane \
      -B build/dataplane \
      -G Ninja \
      -DCMAKE_BUILD_TYPE="${BONVOYAGE_BUILD_TYPE}" \
      "-DCMAKE_PREFIX_PATH=/opt/seastar;/opt/c-ares;/opt/libjwt;/opt/nghttp2;/opt/llhttp;/opt/abseil;/opt/re2" \
      -DBONVOYAGE_ENABLE_SANITIZERS="${BONVOYAGE_ENABLE_SANITIZERS}" \
      -DBONVOYAGE_BUILD_DOCUMENTATION="${BONVOYAGE_BUILD_DOCUMENTATION}" \
      -DBONVOYAGE_RUN_RUNTIME_TESTS="${BONVOYAGE_RUN_RUNTIME_TESTS}" \
      -DBONVOYAGE_UPSTREAM_HTTP1_CLIENT="${BONVOYAGE_UPSTREAM_HTTP1_CLIENT}" \
      -DBONVOYAGE_WARNINGS_AS_ERRORS=ON \
      -DBUILD_TESTING=ON \
    && cmake --build build/dataplane --parallel "${BUILD_JOBS}" \
    && if [ "${BONVOYAGE_BUILD_DOCUMENTATION}" = "ON" ]; then \
         cmake --build build/dataplane --target dataplane-docs; \
       fi \
    && ASAN_OPTIONS=halt_on_error=1:abort_on_error=1 \
       UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
       ctest --test-dir build/dataplane --output-on-failure \
    && cmake --install build/dataplane --prefix /opt/bonvoyage

# Capture exactly the shared libraries resolved in the pinned build stage.
# Preserve binary/source identity and ownership of only the copied files so
# Syft can distinguish installed packages from redundant ELF producer notes.
COPY scripts/build-runtime-package-index.py /tmp/build-runtime-package-index.py
RUN binary=/opt/bonvoyage/bin/bonvoyage-dataplane \
    && runtime_libraries=/tmp/bonvoyage-runtime-libraries.txt \
    && install -D "$binary" \
      /opt/runtime-root/usr/local/bin/bonvoyage-dataplane \
    && if ldd "$binary" | grep -q 'libcares[.]so'; then \
         echo 'unexpected shared c-ares dependency' >&2; exit 1; \
       fi \
    && ldd "$binary" \
      | awk '$2 == "=>" && $3 ~ /^\// { print $3 } $1 ~ /^\// { print $1 }' \
      | sort -u > "$runtime_libraries" \
    && xargs -r -I '{}' cp --dereference --parents '{}' \
      /opt/runtime-root < "$runtime_libraries" \
    && find /opt/runtime-root -type f -name 'ld-linux-*.so.*' -print -quit \
      | grep -q . \
    && python3 /tmp/build-runtime-package-index.py \
      --root /opt/runtime-root --libraries "$runtime_libraries" \
    && install -D /etc/os-release /opt/runtime-root/etc/os-release \
    && install -D /etc/ssl/certs/ca-certificates.crt \
      /opt/runtime-root/etc/ssl/certs/ca-certificates.crt \
    && install -D /opt/nghttp2/share/licenses/nghttp2/COPYING \
      /opt/runtime-root/usr/share/licenses/nghttp2/COPYING \
    && install -D /opt/libjwt/share/licenses/libjwt/LICENSE \
      /opt/runtime-root/usr/share/licenses/libjwt/LICENSE \
    && install -D /usr/src/seastar/LICENSE \
      /opt/runtime-root/usr/share/licenses/seastar/LICENSE \
    && install -D /opt/c-ares/share/licenses/c-ares/LICENSE.md \
      /opt/runtime-root/usr/share/licenses/c-ares/LICENSE.md \
    && install -D /opt/abseil/share/licenses/abseil/LICENSE \
      /opt/runtime-root/usr/share/licenses/abseil/LICENSE \
    && install -D /opt/re2/share/licenses/re2/LICENSE \
      /opt/runtime-root/usr/share/licenses/re2/LICENSE \
    && install -D /usr/src/bonvoyage/third_party/opentelemetry-proto/LICENSE \
      /opt/runtime-root/usr/share/licenses/opentelemetry-proto/LICENSE \
    && install -D /opt/llhttp/share/licenses/llhttp/LICENSE-MIT \
      /opt/runtime-root/usr/share/licenses/llhttp/LICENSE-MIT \
    && install -d /opt/runtime-root/usr/share/bonvoyage \
    && cp -R /tmp/bonvoyage-dependencies \
      /opt/runtime-root/usr/share/bonvoyage/dependencies

FROM bonvoyage-build AS static-analysis

ARG BONVOYAGE_UPSTREAM_HTTP1_CLIENT=seastar-reference

RUN apt-get update \
    && apt-get install -y --no-install-recommends clang-tidy-18 \
    && rm -rf /var/lib/apt/lists/* \
    && clang-tidy-18 \
      -p build/dataplane \
      --extra-arg=-Wno-unknown-warning-option \
      --warnings-as-errors='*' \
      dataplane/benchmarks/endpoint_selector_benchmark.cc \
      dataplane/src/access_log.cc \
      dataplane/src/api_key_auth.cc \
      dataplane/src/client_identity.cc \
      dataplane/src/cors_policy.cc \
      dataplane/src/discovery_client.cc \
      dataplane/src/discovery_protocol.cc \
      dataplane/src/endpoint_maintenance.cc \
      dataplane/src/endpoint_selector.cc \
      dataplane/src/weighted_cluster_selector.cc \
      dataplane/src/gateway.cc \
      dataplane/src/grpc_protocol.cc \
      dataplane/src/header_transformations.cc \
      dataplane/src/http1_validation.cc \
      dataplane/src/http2_client_session.cc \
      dataplane/src/http2_request_validation.cc \
      dataplane/src/http2_session.cc \
      dataplane/src/jwt_auth.cc \
      dataplane/src/live_snapshot_coordinator.cc \
      dataplane/src/main.cc \
      dataplane/src/request_content_policy.cc \
      dataplane/src/retry_policy.cc \
      dataplane/src/route_admission.cc \
      dataplane/src/route_rewrite.cc \
      dataplane/src/runtime_log.cc \
      dataplane/src/runtime_log_binding.cc \
      dataplane/src/runtime_log_service.cc \
      dataplane/src/runtime_snapshot.cc \
      dataplane/src/snapshot_preparation.cc \
      dataplane/src/snapshot_preparation_coordinator.cc \
      dataplane/src/trace_context.cc \
      dataplane/src/trace_exporter.cc \
      dataplane/src/upstream_request_serializer.cc \
      dataplane/src/upstream_response_head_parser.cc \
      dataplane/src/upstream_http1_client.cc \
      dataplane/src/upstream_http2_client.cc \
      dataplane/tests/access_log_test.cc \
      dataplane/tests/access_log_runtime_test.cc \
      dataplane/tests/trace_context_test.cc \
      dataplane/tests/trace_exporter_runtime_test.cc \
      dataplane/tests/api_key_auth_test.cc \
      dataplane/tests/endpoint_selector_test.cc \
      dataplane/tests/weighted_cluster_selector_test.cc \
      dataplane/tests/client_identity_test.cc \
      dataplane/tests/cors_policy_test.cc \
      dataplane/tests/discovery_client_test.cc \
      dataplane/tests/discovery_protocol_test.cc \
      dataplane/tests/endpoint_maintenance_test.cc \
      dataplane/tests/http1_validation_test.cc \
      dataplane/tests/header_transformations_test.cc \
      dataplane/tests/grpc_protocol_test.cc \
      dataplane/tests/http2_client_session_test.cc \
      dataplane/tests/http2_request_validation_test.cc \
      dataplane/tests/http2_session_test.cc \
      dataplane/tests/jwt_auth_test.cc \
      dataplane/tests/live_snapshot_coordinator_reactor_test.cc \
      dataplane/tests/request_content_policy_test.cc \
      dataplane/tests/retry_policy_test.cc \
      dataplane/tests/route_admission_test.cc \
      dataplane/tests/route_rewrite_test.cc \
      dataplane/tests/runtime_log_test.cc \
      dataplane/tests/runtime_log_binding_test.cc \
      dataplane/tests/runtime_log_binding_reactor_test.cc \
      dataplane/tests/runtime_log_service_reactor_test.cc \
      dataplane/tests/shutdown_sequence_reactor_test.cc \
      dataplane/tests/runtime_snapshot_test.cc \
      dataplane/tests/snapshot_preparation_test.cc \
      dataplane/tests/snapshot_preparation_reactor_test.cc \
      dataplane/tests/snapshot_activation_test.cc \
      dataplane/tests/snapshot_activation_reactor_test.cc \
      dataplane/tests/source_ip_policy_test.cc \
      dataplane/tests/upstream_request_serializer_test.cc \
      dataplane/tests/upstream_response_head_parser_test.cc \
      dataplane/tests/upstream_http1_client_test.cc \
      dataplane/tests/contracts_smoke.cc \
    && if [ "${BONVOYAGE_UPSTREAM_HTTP1_CLIENT}" = "llhttp-candidate" ]; then \
         clang-tidy-18 \
           -p build/dataplane \
           --extra-arg=-Wno-unknown-warning-option \
           --warnings-as-errors='*' \
           dataplane/src/llhttp_upstream_http1_client.cc; \
       fi

# This target is a compiler and Debian assembler for the exact public source
# mounted at runtime. It deliberately contains no BonVoyage source or binary.
FROM seastar-build AS oss-deb-builder

ARG UBUNTU_SNAPSHOT=20261006T000000Z

ENV DEBIAN_FRONTEND=noninteractive
ENV CC=gcc-13
ENV CXX=g++-13
ENV PKG_CONFIG_PATH=/opt/c-ares/lib/pkgconfig

COPY --from=libjwt-build /opt/libjwt /opt/libjwt
COPY --from=nghttp2-build /opt/nghttp2 /opt/nghttp2
COPY --from=llhttp-build /opt/llhttp /opt/llhttp
COPY --from=re2-build /opt/abseil /opt/abseil
COPY --from=re2-build /opt/re2 /opt/re2

# Package-only additions come from one fail-closed Ubuntu snapshot. The
# complete installed-package and tool inventory is captured again at runtime.
RUN test "${UBUNTU_SNAPSHOT}" = "20261006T000000Z" \
    && test -s /etc/ssl/certs/ca-certificates.crt \
    && printf '%s\n' \
      'Types: deb' \
      "URIs: https://snapshot.ubuntu.com/ubuntu/${UBUNTU_SNAPSHOT}" \
      'Suites: noble noble-updates noble-backports noble-security' \
      'Components: main universe' \
      'Signed-By: /usr/share/keyrings/ubuntu-archive-keyring.gpg' \
      > /etc/apt/sources.list.d/ubuntu.sources \
    && rm -f /etc/apt/sources.list \
    && apt-get update -o APT::Update::Error-Mode=any \
    && apt-get indextargets --format '$(URI)' \
      | sed '/^$/d' | sort -u > /tmp/bonvoyage-apt-index-uris \
    && test -s /tmp/bonvoyage-apt-index-uris \
    && if grep -Ev \
      "^https://snapshot[.]ubuntu[.]com/ubuntu/${UBUNTU_SNAPSHOT}/" \
      /tmp/bonvoyage-apt-index-uris; then \
         echo 'non-snapshot Ubuntu package index rejected' >&2; \
         exit 2; \
       fi \
    && apt-get install -y --no-install-recommends \
      debhelper dpkg-dev fakeroot \
    && command -v cmake \
    && command -v ctest \
    && command -v dh \
    && command -v dpkg-buildpackage \
    && command -v g++-13 \
    && command -v git \
    && command -v ninja \
    && command -v protoc \
    && command -v python3 \
    && test -f /opt/seastar/lib/cmake/Seastar/SeastarConfig.cmake \
    && install -D -m 0644 /usr/src/seastar/LICENSE \
      /opt/seastar/share/licenses/seastar/LICENSE \
    && rm -rf /usr/src/seastar /var/lib/apt/lists/* /tmp/*

COPY scripts/oss-deb-builder-entrypoint.py \
  /usr/local/bin/bonvoyage-oss-deb-builder

RUN chmod 0755 /usr/local/bin/bonvoyage-oss-deb-builder

LABEL org.opencontainers.image.title="RouteSphere BonVoyage OSS Debian Builder" \
      org.opencontainers.image.description="Offline Linux AMD64 compiler and Debian technical-candidate assembler" \
      org.opencontainers.image.vendor="RouteSphere" \
      io.routesphere.bonvoyage.role="oss-deb-builder" \
      io.routesphere.bonvoyage.ubuntu-snapshot="20261006T000000Z" \
      io.routesphere.bonvoyage.release-authority="false"

USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/bonvoyage-oss-deb-builder"]

# This target reuses the source-free compiler foundation but emits one
# deterministic OCI image layout. It contains no BonVoyage source or binary;
# the exact public checkout is compiled, tested and assembled only at runtime.
FROM oss-deb-builder AS oss-oci-builder

USER 0:0

COPY --from=nghttp2-build /opt/nghttp2/share/licenses/nghttp2/COPYING \
  /opt/bonvoyage-oci/rootfs-static/usr/share/licenses/nghttp2/COPYING
COPY --from=libjwt-build /opt/libjwt/share/licenses/libjwt/LICENSE \
  /opt/bonvoyage-oci/rootfs-static/usr/share/licenses/libjwt/LICENSE
COPY --from=seastar-build /usr/src/seastar/LICENSE \
  /opt/bonvoyage-oci/rootfs-static/usr/share/licenses/seastar/LICENSE
COPY --from=cares-build /opt/c-ares/share/licenses/c-ares/LICENSE.md \
  /opt/bonvoyage-oci/rootfs-static/usr/share/licenses/c-ares/LICENSE.md
COPY --from=re2-build /opt/abseil/share/licenses/abseil/LICENSE \
  /opt/bonvoyage-oci/rootfs-static/usr/share/licenses/abseil/LICENSE
COPY --from=re2-build /opt/re2/share/licenses/re2/LICENSE \
  /opt/bonvoyage-oci/rootfs-static/usr/share/licenses/re2/LICENSE
COPY --from=llhttp-build /opt/llhttp/share/licenses/llhttp/LICENSE-MIT \
  /opt/bonvoyage-oci/rootfs-static/usr/share/licenses/llhttp/LICENSE-MIT

COPY security/dependencies/nghttp2-1.70.0.json \
  /opt/bonvoyage-oci/rootfs-static/usr/share/bonvoyage/dependencies/nghttp2-1.70.0.json
COPY security/dependencies/libjwt-3.6.1.json \
  /opt/bonvoyage-oci/rootfs-static/usr/share/bonvoyage/dependencies/libjwt-3.6.1.json
COPY security/dependencies/seastar-25.05.0.json \
  /opt/bonvoyage-oci/rootfs-static/usr/share/bonvoyage/dependencies/seastar-25.05.0.json
COPY security/dependencies/c-ares-1.34.8.json \
  /opt/bonvoyage-oci/rootfs-static/usr/share/bonvoyage/dependencies/c-ares-1.34.8.json
COPY security/dependencies/abseil-20250512.1.json \
  /opt/bonvoyage-oci/rootfs-static/usr/share/bonvoyage/dependencies/abseil-20250512.1.json
COPY security/dependencies/re2-2025-11-05.json \
  /opt/bonvoyage-oci/rootfs-static/usr/share/bonvoyage/dependencies/re2-2025-11-05.json
COPY security/dependencies/opentelemetry-proto-1.11.0.json \
  /opt/bonvoyage-oci/rootfs-static/usr/share/bonvoyage/dependencies/opentelemetry-proto-1.11.0.json
COPY security/dependencies/llhttp-9.4.3.json \
  /opt/bonvoyage-oci/rootfs-static/usr/share/bonvoyage/dependencies/llhttp-9.4.3.json

COPY scripts/build-oss-oci.py \
  /usr/local/lib/bonvoyage/build-oss-oci.py
COPY scripts/build-runtime-package-index.py \
  /usr/local/lib/bonvoyage/build-runtime-package-index.py
COPY scripts/oss-oci-builder-entrypoint.py \
  /usr/local/bin/bonvoyage-oss-oci-builder
COPY packaging/release/oci/oss-oci-image-contract.json \
  /usr/local/share/bonvoyage/oss-oci-image-contract.json

RUN chmod 0755 \
      /usr/local/bin/bonvoyage-oss-oci-builder \
      /usr/local/lib/bonvoyage/build-oss-oci.py \
      /usr/local/lib/bonvoyage/build-runtime-package-index.py \
    && find /opt/bonvoyage-oci/rootfs-static -type d -exec chmod 0755 '{}' + \
    && find /opt/bonvoyage-oci/rootfs-static -type f -exec chmod 0644 '{}' + \
    && test ! -e /usr/src/bonvoyage \
    && test ! -e /opt/bonvoyage/bin/bonvoyage-dataplane

LABEL org.opencontainers.image.title="RouteSphere BonVoyage OSS OCI Builder" \
      org.opencontainers.image.description="Offline Linux AMD64 compiler and deterministic OCI technical-candidate assembler" \
      org.opencontainers.image.vendor="RouteSphere" \
      io.routesphere.bonvoyage.role="oss-oci-builder" \
      io.routesphere.bonvoyage.ubuntu-snapshot="20261006T000000Z" \
      io.routesphere.bonvoyage.release-authority="false"

USER 65532:65532
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/bonvoyage-oss-oci-builder"]

FROM scratch AS runtime

ARG BONVOYAGE_UPSTREAM_HTTP1_CLIENT=seastar-reference

LABEL org.opencontainers.image.title="RouteSphere BonVoyage Dataplane" \
      org.opencontainers.image.description="Independent C++/Seastar API gateway dataplane" \
      org.opencontainers.image.version="0.2.0" \
      org.opencontainers.image.libjwt.version="3.6.1" \
      org.opencontainers.image.libjwt.commit="f4edfe5b2c44ac57edf00342550e81017f5329eb" \
      org.opencontainers.image.nghttp2.version="1.70.0" \
      org.opencontainers.image.nghttp2.commit="85e300c79fb6dbcfa9c1013215c8710c1c2cd3d2" \
      org.opencontainers.image.abseil.version="20250512.1" \
      org.opencontainers.image.abseil.commit="76bb24329e8bf5f39704eb10d21b9a80befa7c81" \
      org.opencontainers.image.re2.version="2025-11-05" \
      org.opencontainers.image.re2.commit="927f5d53caf8111721e734cf24724686bb745f55" \
      org.opencontainers.image.seastar.version="seastar-25.05.0" \
      org.opencontainers.image.seastar.commit="8df8212e53577e1d8477a5c901457cd61d88afc7" \
      io.routesphere.bonvoyage.upstream-http1-client="${BONVOYAGE_UPSTREAM_HTTP1_CLIENT}" \
      org.opencontainers.image.vendor="RouteSphere"

COPY --from=bonvoyage-build /opt/runtime-root/ /

USER 65532:65532
WORKDIR /var/lib/bonvoyage

EXPOSE 8080 8443 9090 9901

ENTRYPOINT ["/usr/local/bin/bonvoyage-dataplane"]
CMD ["--snapshot", "/etc/bonvoyage/snapshot.pb", "--admin-address", "0.0.0.0", "--metrics-address", "0.0.0.0", "--runtime-log-transport", "stderr-pipe", "--smp", "1", "--memory", "256M", "--overprovisioned"]
