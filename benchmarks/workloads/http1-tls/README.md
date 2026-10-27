# HTTP/1.1 TLS

`phase3-tls.yaml` isolates TLS 1.3 record and handshake costs after the plain
HTTP baseline. The publication run uses a trusted test CA, verifies the server
name, advertises HTTP/1.1 through ALPN, and records keep-alive and connection-
churn profiles separately.
