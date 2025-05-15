// Package registry provides an interface to interact with on-chain registry
// contracts for TEE (Trusted Execution Environment) identity verification and
// configuration management.
//
// Package registry provides an interface to interact with on-chain registry
// contracts for managing TEE (Trusted Execution Environment) identities,
// configurations, and secrets.
//
// The package implements the interfaces.OnchainRegistry interface, allowing
// applications to interact with the Registry smart contract deployed on
// Ethereum-compatible blockchains.
//
// Key features include:
//
// - Identity verification for TDX and MAA attestations
// - Whitelisting and management of TEE identities
// - Configuration template storage and retrieval
// - Encrypted secret management
// - Storage backend coordination
// - Instance domain name registration
//
// The registry operates as a binding between the TEE attestation process and
// on-chain configuration management. It verifies attestations from both Intel
// TDX-based platforms and Azure Confidential Computing (MAA) environments,
// and provides identity-specific configurations to authorized TEE instances.
//
// # Governance Interfaces
//
// The package implements three main governance interfaces:
//
// WorkloadGovernance: Handles TEE identity verification through attestation
//
//	type WorkloadGovernance interface {
//	    DCAPIdentity(report DCAPReport, events []DCAPEvent) ([32]byte, error)
//	    MAAIdentity(report MAAReport) ([32]byte, error)
//	    IdentityAllowed(identity [32]byte, operator [20]byte) (bool, error)
//	}
//
// ProvisioningGovernance: Manages configuration mapping for TEE instances
//
//	type ProvisioningGovernance interface {
//	    ConfigForIdentity(identity [32]byte, operator [20]byte) ([32]byte, error)
//	    StorageBackends() ([]string, error)
//	}
//
// OnchainDiscovery: Provides service discovery mechanisms
//
//	type OnchainDiscovery interface {
//	    PKI() (AppPKI, error)
//	    InstanceDomainNames() ([]string, error)
//	}
//
// # Transaction Operations
//
// All state-modifying operations require transaction signing. Before using methods
// that modify state, you must call SetTransactOpts with appropriate transaction
// options including a private key for signing.
//
// Read-only operations do not require transaction options and can be used
// immediately after creating a client instance.
//
// # Usage Example
//
//	// Create a new registry client
//	client, err := registry.NewOnchainRegistryClient(ethereumClient, backend, contractAddress)
//	if err != nil {
//	    log.Fatalf("Failed to create registry client: %v", err)
//	}
//
//	// Set transaction options for state-modifying operations
//	privateKey, _ := crypto.HexToECDSA("your-private-key")
//	auth, _ := bind.NewKeyedTransactorWithChainID(privateKey, chainID)
//	client.SetTransactOpts(auth)
//
//	// Read PKI information (read-only, no auth needed)
//	pki, err := client.GetPKI()
//
//	// Add an artifact (configuration or secret)
//	artifactData := []byte("your-artifact-data")
//	artifactHash, tx, err := client.AddArtifact(artifactData)
package registry
