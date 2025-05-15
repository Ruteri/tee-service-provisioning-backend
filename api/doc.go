// Package api provides components for a TEE KMS with onchain governance support.
//
// The api package implements HTTP servers and handlers for key management service
// operations, including attestation verification, certificate issuance, and secure
// bootstrapping. It supports the onchain governance model of the TEE Registry System
// with proper identity verification and authorization.
//
// # Key Components
//
// - PKI Handler: Serves CA certificates and public keys for TEE applications
// - KMS Handler: Provides cryptographic materials for attested TEE instances
// - Shamir KMS: Implements secure bootstrapping with administrator shares
//
// # Security Model
//
// The API implements a robust security model with multiple layers of verification:
//
// 1. TEE Attestation: Verifies the identity of instances using DCAP or MAA reports
// 2. Onchain Authorization: Checks identity whitelisting in governance contracts
// 3. Operator Verification: Optionally verifies operator signatures for authorization
// 4. Certificate-Based Authentication: TLS mutual authentication for secure connections
//
// # PKI Flow
//
// The PKI endpoint provides public certificate authorities for TEE applications:
//
// 1. Client requests PKI for a specific contract address
// 2. Server retrieves attested CA certificate and public key from KMS
// 3. Client receives CA certificate for TLS verification and public key for encryption
//
// # Secrets Flow
//
// The secrets endpoint provides private keys and certificates for TEE instances:
//
// 1. Instance submits attestation evidence and a Certificate Signing Request
// 2. Server verifies attestation against onchain governance contract
// 3. Server checks operator authorization if operator signature is present
// 4. If authorized, server returns application private key and signed certificate
//
// # Usage
//
// The API is typically accessed by TEE instances during provisioning:
//
// - Requesting CA certificates for peer verification
// - Obtaining application private keys for secret decryption
// - Acquiring signed TLS certificates for secure communication
//
// The API is also used by administrators for KMS bootstrapping:
//
// - Generating and distributing Shamir Secret Sharing key shares
// - Collecting shares for master key reconstruction
// - Managing KMS lifecycle and recovery
//
// # Onchain Integration
//
// The API integrates with onchain governance through:
//
// - Verifying identity hashes against whitelists in governance contracts
// - Publishing PKI information to onchain discovery contracts
// - Enforcing operator permissions defined in governance contracts
//
// # Subpackages
//
// The api package is organized into several subpackages:
//
//   - kmshandler: Implements attested secrets and KMS onboarding endpoints
//   - pkihandler: Implements public-facing attested PKI interface
//   - shamir-kms: Implements Shamir's Secret Sharing backend, allowing generation
//     and recovery of secrets
//
// See the subpackages for detailed documentation on specific components.
package api
