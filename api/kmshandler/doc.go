// Package kmshandler implements an HTTP server and client for interacting with
// an onchain-governed Trusted Execution Environment (TEE) Key Management System (KMS).
//
// This package provides handlers and clients for secure TEE instance authentication,
// cryptographic material distribution, and onboarding of new KMS instances. It integrates
// with blockchain-based governance to verify instance identity and operator authorization
// before providing cryptographic materials.
//
// Key components:
//   - Handler: Processes HTTP requests for secrets and onboarding with attestation verification
//   - Client: Communicates with KMS to obtain instance secrets and handle onboarding
//
// The handler implements a secure workflow for TEE instance provisioning:
//  1. Verifies attestation evidence against onchain registry
//  2. Validates optional operator signatures for additional authorization
//  3. Provides application private keys, signed TLS certificates, and identity information
//  4. Supports secure KMS onboarding through onchain governance
package kmshandler
