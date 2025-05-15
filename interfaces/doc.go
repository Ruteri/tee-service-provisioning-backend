// Package interfaces defines core interfaces and types for the TEE registry
// system, separating interface definitions from implementations.
//
// The package provides interfaces for the key components of the system:
//
// # Governance Interfaces
//
// WorkloadGovernance: Handles TEE identity verification through attestation, including
// mapping attestation reports to identity hashes and verifying authorization.
//
// ProvisioningGovernance: Manages configuration mapping for TEE instances, associating
// identity hashes with configuration hashes and tracking storage backend URIs.
//
// OnchainDiscovery: Provides service discovery mechanisms, including PKI information
// retrieval and instance domain name management.
//
// # Storage Interfaces
//
// StorageBackend: Provides content-addressed storage for configurations and secrets
// across multiple backend types (file, S3, IPFS, onchain, GitHub, Vault).
//
// StorageBackendFactory: Creates storage backends from URI strings and manages
// multi-backend configurations for redundant storage.
//
// # Cryptographic Types
//
// The package also defines core cryptographic types for secure communication:
//
// - ContentID: 32-byte SHA-256 hash for content addressing
// - ContractAddress: 20-byte Ethereum address
// - AppPKI: Certificate authority and public key information for an application
// - AppSecrets: Cryptographic materials for TEE instances
// - TLSCSR/TLSCert: TLS certificate signing requests and certificates
//
// # Key Functions
//
// AttestationToIdentity: Converts attestation data to an identity hash based on
// the attestation type and governance contract implementation.
package interfaces
