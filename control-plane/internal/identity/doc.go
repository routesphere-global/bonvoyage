// Package identity provides the standalone BonVoyage node identity authority
// and its durable, security-sensitive repository.
//
// The package deliberately keeps enrollment secrets and CA private keys out of
// durable node records. Enrollment and credential activation are committed as
// one repository transaction, while certificate issuance constructs the node
// SPIFFE identity from trusted configuration rather than CSR-supplied names.
package identity
