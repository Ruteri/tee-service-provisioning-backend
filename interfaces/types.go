// Package interfaces defines the core interfaces and types for the TEE registry system.
// It provides the contract between different components without implementation details.
package interfaces

import (
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ruteri/tee-service-provisioning-backend/bindings/registry"
)

// TLSCSR represents a TLS Certificate Signing Request in PEM format.
type TLSCSR []byte

// TLSCert represents a TLS Certificate in PEM format.
type TLSCert []byte

// CACert represents a Certificate Authority Certificate in PEM format.
type CACert []byte

// AppPubkey represents an application's public key in PEM format.
type AppPubkey []byte

// AppPrivkey represents an application's private key in PEM format.
type AppPrivkey []byte

// Attestation represents a cryptographic attestation of identity.
type Attestation []byte

// ContractAddress represents an Ethereum contract address (20 bytes).
type ContractAddress [20]byte

// AppDomainName represents a domain name for an application instance.
type AppDomainName string

// DCAPReport represents a Direct Capability Attestation Protocol report.
// It contains measurement registers that uniquely identify a TEE instance.
type DCAPReport = registry.RegistryDCAPReport

// DCAPEvent represents an event in the TEE runtime event log.
type DCAPEvent = registry.RegistryDCAPEvent

// MAAReport represents a Microsoft Azure Attestation report.
// It contains PCR values that uniquely identify a TEE instance.
type MAAReport = registry.RegistryMAAReport

// AppPKI represents a PKI bundle containing CA certificate, public key, and attestation.
type AppPKI = registry.RegistryAppPKI

// StorageBackendLocation represents a URI location for a content storage backend.
type StorageBackendLocation string

// InstanceConfig represents the configuration data for a TEE instance.
type InstanceConfig []byte

// KMS defines the interface for key management operations related to TEE applications.
// It handles cryptographic materials for secure communication with TEE instances.
type KMS interface {
	// GetPKI retrieves the CA certificate, app public key, and attestation for a contract.
	// The CA and public key should match those in the certificate (unless rotated).
	// The attestation is provided for transparency and verification.
	GetPKI(contractAddr ContractAddress) (AppPKI, error)

	// GetAppPrivkey returns the application private key for a contract address.
	// This method assumes attestation and identity have been verified already.
	// The instance must be connected through attested communication channels.
	GetAppPrivkey(contractAddr ContractAddress) (AppPrivkey, error)

	// SignCSR signs a certificate signing request for a verified TEE instance.
	// This method assumes attestation and identity have been verified already.
	// The instance must be connected through attested communication channels.
	SignCSR(contractAddr ContractAddress, csr TLSCSR) (TLSCert, error)
}

// OnchainRegistry defines the interface for interacting with the registry smart contract.
// It provides methods for identity verification, configuration management, and TEE orchestration.
type OnchainRegistry interface {
	// GetPKI retrieves the PKI information (CA, public key, and attestation) from the registry.
	// This combines GetCA and GetAppPubkey into one method to match the contract structure.
	GetPKI() (*AppPKI, error)

	// IsWhitelisted checks if an identity hash is in the registry's whitelist.
	// Returns true if the identity is allowed to receive configurations and keys.
	IsWhitelisted(identity [32]byte) (bool, error)

	// ComputeDCAPIdentity calculates the identity hash for a DCAP report.
	// This uses the same algorithm as the on-chain registry contract.
	ComputeDCAPIdentity(report *DCAPReport) ([32]byte, error)

	// ComputeMAAIdentity calculates the identity hash for an MAA report.
	// This uses the same algorithm as the on-chain registry contract.
	ComputeMAAIdentity(report *MAAReport) ([32]byte, error)

	// GetConfig retrieves a configuration from the registry by its hash.
	// Returns the configuration data or an error if not found.
	GetConfig(configHash [32]byte) ([]byte, error)

	// GetSecret retrieves an encrypted secret from the registry by its hash.
	// Returns the encrypted secret data or an error if not found.
	GetSecret(secretHash [32]byte) ([]byte, error)

	// IdentityConfigMap gets the config hash assigned to an identity.
	// Returns the config hash or an error if no mapping exists.
	IdentityConfigMap(identity [32]byte) ([32]byte, error)

	// AddConfig adds a new configuration to the registry.
	// Returns the content hash, transaction, and any error that occurred.
	AddConfig(data []byte) ([32]byte, *types.Transaction, error)

	// AddSecret adds a new encrypted secret to the registry.
	// Returns the content hash, transaction, and any error that occurred.
	AddSecret(data []byte) ([32]byte, *types.Transaction, error)

	// SetConfigForDCAP associates a configuration with a DCAP-attested identity.
	// Returns the transaction and any error that occurred.
	SetConfigForDCAP(report *DCAPReport, configHash [32]byte) (*types.Transaction, error)

	// SetConfigForMAA associates a configuration with an MAA-attested identity.
	// Returns the transaction and any error that occurred.
	SetConfigForMAA(report *MAAReport, configHash [32]byte) (*types.Transaction, error)

	// AllStorageBackends returns all registered storage backend URIs.
	// These backends are used for retrieving configurations and secrets.
	AllStorageBackends() ([]string, error)

	// AddStorageBackend registers a new storage backend URI.
	// Returns the transaction and any error that occurred.
	AddStorageBackend(locationURI string) (*types.Transaction, error)

	// RemoveStorageBackend unregisters a storage backend URI.
	// Returns the transaction and any error that occurred.
	RemoveStorageBackend(locationURI string) (*types.Transaction, error)

	// AllInstanceDomainNames returns all registered instance domain names.
	// These domains are used for accessing TEE instances.
	AllInstanceDomainNames() ([]string, error)

	// RegisterInstanceDomainName adds a new domain name for instances.
	// Returns the transaction and any error that occurred.
	RegisterInstanceDomainName(domain string) (*types.Transaction, error)

	// RemoveWhitelistedIdentity removes an identity from the registry whitelist.
	// Returns the transaction and any error that occurred.
	RemoveWhitelistedIdentity(identity [32]byte) (*types.Transaction, error)
}

// RegistryFactory creates OnchainRegistry instances for different contract addresses.
// This allows the system to interact with multiple registry contracts.
type RegistryFactory interface {
	// RegistryFor returns an OnchainRegistry instance for the specified contract address.
	// If the registry doesn't exist, it will be created.
	RegistryFor(ContractAddress) (OnchainRegistry, error)
}
