# Kubernetes downstream TLS example

This Kustomize overlay replaces the base plaintext listener with an HTTPS
listener and mounts certificate material from a Kubernetes Secret. It contains
no private key or test certificate.

Create or obtain a certificate whose DNS SAN covers the configured virtual
host, then create the Secret without committing its input files:

```bash
kubectl create namespace bonvoyage --dry-run=client -o yaml | kubectl apply -f -
kubectl -n bonvoyage create secret generic bonvoyage-downstream-tls \
  --from-file=server-chain.pem=/secure/path/server-chain.pem \
  --from-file=server-key.pem=/secure/path/server-key.pem \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -k deploy/kubernetes/examples/tls
kubectl -n bonvoyage rollout status deployment/bonvoyage
```

The Service exposes TLS on port 443 and removes the base HTTP port. Admin and
metrics interfaces remain management-plane endpoints and must not be exposed
publicly.

This overlay secures the downstream hop only. The example cluster still uses
HTTP to `upstream:8081`; combine its listener settings with the
`examples/upstream-tls` cluster and Secret mount when both hops must be
encrypted.

For downstream mTLS, also add `client-ca.pem` to the Secret and set
`trust_bundle_secret: "client-ca.pem"` plus
`require_client_certificate: true` in `configmap.yaml`.
