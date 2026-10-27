# Kubernetes upstream TLS and mTLS example

This Kustomize overlay keeps the base HTTP listener and encrypts the
gateway-to-upstream hop. It mounts the upstream CA plus the BonVoyage client
certificate and private key from a Kubernetes Secret; no credential material
is committed in this directory.

Create the Secret from controlled files, inspect the rendered resources, and
then apply the overlay:

```bash
kubectl create namespace bonvoyage --dry-run=client -o yaml | kubectl apply -f -
kubectl -n bonvoyage create secret generic bonvoyage-upstream-tls \
  --from-file=backend-ca.pem=/secure/path/backend-ca.pem \
  --from-file=gateway-client.pem=/secure/path/gateway-client.pem \
  --from-file=gateway-client-key.pem=/secure/path/gateway-client-key.pem \
  --dry-run=client -o yaml | kubectl apply -f -
kubectl kustomize deploy/kubernetes/examples/upstream-tls
kubectl apply -k deploy/kubernetes/examples/upstream-tls
kubectl -n bonvoyage rollout status deployment/bonvoyage
```

The upstream certificate DNS SAN must cover
`backend.internal.example.com`. Change both `server_name` and the endpoint
address when the production service identity differs. To use one-way TLS,
remove the two client credential fields from the ConfigMap and omit those two
files from the Secret.

Credential rotation is startup-bound in this phase. Create a revisioned Secret
and perform a controlled rollout; do not mutate private-key files in place.
