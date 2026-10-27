# syntax=docker/dockerfile:1.7
# Explicit local/CI Seastar build image. This is not a release-image producer.
ARG SEASTAR_BUILD_IMAGE
FROM ${SEASTAR_BUILD_IMAGE}
USER root
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    systemd rsyslog python3 libunistring-dev libudev-dev doxygen && rm -rf /var/lib/apt/lists/*
COPY tests/fixtures/native-logging/emitter.cc /fixture/emitter.cc
COPY tests/fixtures/native-logging/pressure-emitter.cc /fixture/pressure-emitter.cc
RUN PKG_CONFIG_PATH=/opt/seastar/lib/pkgconfig \
    pkg-config --cflags --libs --static seastar > /fixture/link-flags.txt \
    && g++ -Wall -Wextra -Werror -isystem /opt/seastar/include /fixture/emitter.cc \
       $(cat /fixture/link-flags.txt) -o /fixture/emitter \
    && g++ -Wall -Wextra -Werror -isystem /opt/seastar/include /fixture/pressure-emitter.cc \
       $(cat /fixture/link-flags.txt) -O3 -DNDEBUG -o /fixture/pressure-emitter \
    && ln -s /fixture/emitter /usr/local/bin/bonvoyage-dataplane \
    && sha256sum /usr/src/seastar/src/util/log.cc /opt/seastar/lib/libseastar.a \
       /fixture/emitter > /fixture/seastar-binding.txt \
    && test "$(sha256sum /usr/src/seastar/src/util/log.cc | cut -d ' ' -f 1)" = \
       225ab42036a6e3093e5bef9c677647906d7cb04d443619b88741b0d744b696cf
RUN sha256sum /usr/src/seastar/src/util/log.cc /opt/seastar/include/seastar/util/log-cli.hh /opt/seastar/lib/libseastar.a \
    /fixture/pressure-emitter > /fixture/pressure-binding.txt
RUN g++ --version > /fixture/pressure-compiler.txt
COPY packaging/systemd/bonvoyage.service /fixture/bonvoyage.service
COPY packaging/systemd/90-bonvoyage-no-wall.conf.example /fixture/no-wall.conf
COPY tests/fixtures/native-logging/verify.py /fixture/verify.py
COPY tests/fixtures/native-logging/pressure.py /fixture/pressure.py
COPY dataplane/include/bonvoyage/runtime/runtime_log.hh /fixture/include/bonvoyage/runtime/runtime_log.hh
COPY dataplane/src/runtime_log.cc /fixture/runtime_log.cc
COPY dataplane/tests/runtime_log_test.cc /fixture/runtime_log_test.cc
RUN g++ -std=c++20 -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Werror \
    -I/fixture/include -pthread -O3 -DNDEBUG /fixture/runtime_log.cc /fixture/runtime_log_test.cc \
    -o /fixture/runtime-log-release \
    && g++ -std=c++20 -Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Werror \
    -I/fixture/include -pthread -O1 -g -fno-omit-frame-pointer -fno-sanitize-recover=undefined \
    -fsanitize=address,undefined /fixture/runtime_log.cc /fixture/runtime_log_test.cc \
    -o /fixture/runtime-log-sanitize \
    && sha256sum /fixture/runtime-log-release /fixture/runtime-log-sanitize > /fixture/runtime-log-binding.txt
COPY tests/fixtures/native-logging/transport.py /fixture/transport.py
COPY tests/fixtures/native-logging/Doxyfile /fixture/Doxyfile
ENV BONVOYAGE_ISOLATED_LOGGING_FIXTURE=1
ENTRYPOINT ["python3", "-B", "/fixture/verify.py"]
