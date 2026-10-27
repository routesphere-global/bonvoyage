// Package nodecredentials owns node-local discovery credential generation,
// validation, and crash-conscious publication.
//
// Private keys are generated locally and never accepted from a server. A
// server-issued bundle becomes publishable only after its certificate profile,
// SPIFFE identity, trust chain, response metadata, clock bounds, and local key
// binding have all been validated. Publication retains immutable generations
// and updates the stable Seastar-facing files only after the candidate is
// durably sealed.
package nodecredentials
