// Package interfaces defines the core interfaces and types for the TEE registry system.
//
// This package provides the contracts between different components of the system
// without including implementation details. It separates the interface definitions
// from their implementations, allowing for:
//
//   - Clear separation of concerns
//   - Multiple implementations of the same interface
//   - Better testability through mock implementations
//   - Reduced coupling between components
//
// The package contains several key interfaces:
//
// # Storage Interfaces
//
//   - StorageBackend: Represents any system that can store and retrieve content-addressed data
//   - StorageBackendFactory: Creates storage backends from URI strings
//
// # Registry Interfaces
//
//   - OnchainRegistry: Provides methods for interacting with the registry smart contract
//   - RegistryFactory: Creates registry instances for different contract addresses
//
// # Key Management Interfaces
//
//   - KMS: Handles cryptographic operations like certificate signing and key management
//
// # Type Definitions
//
// The package defines various types used throughout the system:
//
//   - ContentID: A 32-byte hash that uniquely identifies content
//   - ContentType: Enum indicating what kind of content (ConfigType, SecretType)
//   - ContractAddress: A 20-byte Ethereum address
//   - DCAPReport/MAAReport: TEE attestation report structures
//   - TLSCSR/TLSCert: TLS certificate signing requests and certificates
//
// # Error Types
//
// Standard errors returned by storage operations:
//
//   - ErrContentNotFound: Content not found in the storage system
//   - ErrBackendUnavailable: Storage backend is not accessible
//   - ErrInvalidLocationURI: Storage location URI is malformed
//
// # Usage Patterns
//
// Components should depend on interfaces rather than concrete implementations:
//
//	func NewHandler(
//	    kms interfaces.KMS,
//	    storageFactory interfaces.StorageBackendFactory,
//	    registryFactory interfaces.RegistryFactory,
//	) *Handler {
//	    // ...
//	}
//
// This allows for better testability and flexibility in changing implementations.
package interfaces
