# syntax=docker/dockerfile:1.7
ARG SEASTAR_BUILD_IMAGE
FROM ${SEASTAR_BUILD_IMAGE} AS hook-build
USER root
ENV DEBIAN_FRONTEND=noninteractive BONVOYAGE_ISOLATED_LOGGING_FIXTURE=1 BONVOYAGE_ISOLATED_LOGGING_BUILD=1
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 libunistring-dev libudev-dev doxygen && rm -rf /var/lib/apt/lists/*
COPY deploy/docker/bonvoyage/patches/seastar-bounded-log-hook.patch /fixture/candidate.patch
COPY tests/fixtures/runtime-log-hook/patch.json /fixture/patch.json
COPY tests/fixtures/runtime-log-hook/build.py /fixture/build.py
RUN python3 -B /fixture/build.py library

FROM hook-build AS fixture
COPY dataplane/include/bonvoyage/runtime/runtime_log.hh /fixture/include/bonvoyage/runtime/runtime_log.hh
COPY dataplane/include/bonvoyage/runtime/runtime_log_binding.hh /fixture/include/bonvoyage/runtime/runtime_log_binding.hh
COPY dataplane/src/runtime_log.cc /fixture/runtime_log.cc
COPY dataplane/src/runtime_log_binding.cc /fixture/runtime_log_binding.cc
COPY dataplane/tests/runtime_log_binding_test.cc /fixture/runtime_log_binding_test.cc
COPY dataplane/tests/runtime_log_binding_reactor_test.cc /fixture/runtime_log_binding_reactor_test.cc
RUN python3 -B /fixture/build.py tests
COPY tests/fixtures/runtime-log-hook/verify.py /fixture/verify.py
COPY tests/fixtures/native-logging/Doxyfile /fixture/Doxyfile
ENTRYPOINT ["python3", "-B", "/fixture/verify.py"]
