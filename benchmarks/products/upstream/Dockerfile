ARG NGINX_IMAGE=nginx:1.30.4-alpine3.24@sha256:97d490c12ba55b4946b01546d1c3ed324e8d41ab1c9fcb2a616aa470620e5b46
FROM ${NGINX_IMAGE}

COPY nginx.conf /etc/nginx/nginx.conf

RUN mkdir -p /srv/payload \
    && dd if=/dev/zero bs=256 count=1 2>/dev/null \
      | tr '\000' x > /srv/payload/256 \
    && dd if=/dev/zero bs=8192 count=1 2>/dev/null \
      | tr '\000' x > /srv/payload/8192 \
    && dd if=/dev/zero bs=15360 count=1 2>/dev/null \
      | tr '\000' x > /srv/payload/15360 \
    && dd if=/dev/zero bs=16384 count=1 2>/dev/null \
      | tr '\000' x > /srv/payload/16384 \
    && dd if=/dev/zero bs=17408 count=1 2>/dev/null \
      | tr '\000' x > /srv/payload/17408 \
    && dd if=/dev/zero bs=32768 count=1 2>/dev/null \
      | tr '\000' x > /srv/payload/32768 \
    && dd if=/dev/zero bs=65536 count=1 2>/dev/null \
      | tr '\000' x > /srv/payload/65536 \
    && dd if=/dev/zero bs=1048576 count=1 2>/dev/null \
      | tr '\000' x > /srv/payload/1048576 \
    && printf 'ok\n' > /srv/healthz \
    && chmod -R a=rX /srv

HEALTHCHECK --interval=2s --timeout=1s --retries=20 \
  CMD wget -q -O - http://127.0.0.1:8081/healthz || exit 1
