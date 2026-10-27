# HTTP/1.1 Upstream TLS

These Phase 3 profiles isolate TLS on the gateway-to-upstream hop while the
load-generator-to-gateway hop remains cleartext. Server identity verification
is mandatory in both profiles; the mTLS profile additionally presents the
gateway client certificate. Dedicated-host runs remain required before any
performance result from these profiles is publishable.
