# syntax=docker/dockerfile:1.7

ARG BONVOYAGE_OBSERVER_BUILD_IMAGE=bonvoyage-build:dev
ARG BONVOYAGE_RUNTIME_IMAGE=bonvoyage-dataplane:dev

FROM ${BONVOYAGE_OBSERVER_BUILD_IMAGE} AS observer-build

COPY scripts/runtime-glibc-call-trace.c /tmp/runtime-glibc-call-trace.c
COPY scripts/runtime-glibc-call-trace-selftest.c \
    /tmp/runtime-glibc-call-trace-selftest.c

RUN cc -std=gnu11 -shared -fPIC -O2 -Wall -Wextra -Werror \
      -fstack-protector-strong -D_FORTIFY_SOURCE=3 \
      -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
      -o /tmp/libbonvoyage-runtime-glibc-call-trace.so \
      /tmp/runtime-glibc-call-trace.c -ldl \
    && cc -std=gnu11 -fPIE -pie -O2 -Wall -Wextra -Werror \
      -fstack-protector-strong -D_FORTIFY_SOURCE=3 \
      -Wl,-z,relro,-z,now -Wl,-z,noexecstack \
      -o /tmp/runtime-glibc-call-trace-selftest \
      /tmp/runtime-glibc-call-trace-selftest.c

FROM ${BONVOYAGE_RUNTIME_IMAGE}

ARG BONVOYAGE_BASE_RUNTIME_IMAGE_ID=unknown
ARG BONVOYAGE_OBSERVER_BUILD_IMAGE_ID=unknown

LABEL io.routesphere.bonvoyage.diagnostic.runtime-glibc-call-trace="true" \
      io.routesphere.bonvoyage.diagnostic.base-runtime-image-id="${BONVOYAGE_BASE_RUNTIME_IMAGE_ID}" \
      io.routesphere.bonvoyage.diagnostic.observer-build-image-id="${BONVOYAGE_OBSERVER_BUILD_IMAGE_ID}"

COPY --from=observer-build --chown=0:0 --chmod=0555 \
    /tmp/libbonvoyage-runtime-glibc-call-trace.so \
    /usr/local/lib/bonvoyage-runtime-glibc-call-trace.so
COPY --from=observer-build --chown=0:0 --chmod=0555 \
    /tmp/runtime-glibc-call-trace-selftest \
    /usr/local/libexec/bonvoyage-runtime-glibc-call-trace-selftest

ENV BONVOYAGE_GLIBC_TRACE=1 \
    LD_PRELOAD=/usr/local/lib/bonvoyage-runtime-glibc-call-trace.so
