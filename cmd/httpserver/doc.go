// Package main (cmd/httpserver) implements the registry server for the TEE Registry System.
//
// The registry server provides HTTP endpoints for TEE instance registration with
// attestation verification, certificate issuance, and configuration provisioning.
// It integrates with blockchain-based identity verification, content-addressed
// storage backends, and secure key management systems.
//
// The server supports two different Key Management System (KMS) implementations:
//
//   - SimpleKMS: A straightforward implementation using a 32-byte seed for
//     deterministic key derivation. Suitable for development environments.
//
//   - ShamirKMS: A more secure implementation that uses Shamir's Secret Sharing
//     for distributed master key management. In this mode, the server starts in
//     bootstrap mode first, waiting for administrators to provide their shares
//     before becoming fully operational.
//
// When using ShamirKMS, the bootstrap process follows a secure protocol where
// administrators must authenticate with their private keys, and each administrator
// is responsible for a unique share of the master key. The server only becomes
// operational once a threshold number of administrators have submitted valid shares.
//
// Configuration is handled through command-line flags, with separate settings for
// blockchain connectivity, HTTP endpoints, KMS type, logging, and performance tuning.
//
// The server implements graceful shutdown on receiving termination signals (SIGINT/SIGTERM)
// and supports health checks, metrics collection, and optional profiling endpoints.
//
// Example usage with SimpleKMS:
//
//     registry-server --rpc-addr=http://localhost:8545 \
//         --listen-addr=0.0.0.0:8080 \
//         --kms-type=simple \
//         --simple-kms-seed=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
//
// Example usage with ShamirKMS:
//
//     registry-server --rpc-addr=http://localhost:8545 \
//         --listen-addr=0.0.0.0:8080 \
//         --kms-type=shamir \
//         --shamirkms-admin-keys-file=./shamir-admins.json \
//         --shamirkms-listen-addr=0.0.0.0:8081
package main
