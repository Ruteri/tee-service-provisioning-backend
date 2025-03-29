// Package registry provides an interface to interact with on-chain registry contracts
// for managing TEE (Trusted Execution Environment) identities, configurations, and secrets.
//
// The package implements the interfaces.OnchainRegistry interface, allowing applications
// to interact with the Registry smart contract deployed on Ethereum-compatible blockchains.
//
// Key features include:
//
//   - Identity verification for TDX and MAA attestations
//   - Whitelisting and management of TEE identities
//   - Configuration template storage and retrieval
//   - Encrypted secret management
//   - Storage backend coordination
//   - Instance domain name registration
//
// The registry operates as a binding between the TEE attestation process and on-chain
// configuration management. It verifies attestations from both Intel TDX-based platforms
// and Azure Confidential Computing (MAA) environments, and provides identity-specific
// configurations to authorized TEE instances.
//
// Configurations and secrets can be stored both on-chain and through external storage
// backends (such as S3, IPFS, or the local filesystem). The registry maintains references
// to these storage locations and manages access based on identity verification.
//
// # Interface Definitions
//
// The OnchainRegistry interface defines the methods for interacting with the registry contract:
//
//	type OnchainRegistry interface {
//	    // PKI methods
//	    GetPKI() (*AppPKI, error)
//
//	    // Identity verification methods
//	    IsWhitelisted(identity [32]byte) (bool, error)
//	    ComputeDCAPIdentity(report *DCAPReport) ([32]byte, error)
//	    ComputeMAAIdentity(report *MAAReport) ([32]byte, error)
//
//	    // Config and secret management
//	    GetConfig(configHash [32]byte) ([]byte, error)
//	    GetSecret(secretHash [32]byte) ([]byte, error)
//	    IdentityConfigMap(identity [32]byte) ([32]byte, error)
//	    AddConfig(data []byte) ([32]byte, *types.Transaction, error)
//	    AddSecret(data []byte) ([32]byte, *types.Transaction, error)
//	    SetConfigForDCAP(report *DCAPReport, configHash [32]byte) (*types.Transaction, error)
//	    SetConfigForMAA(report *MAAReport, configHash [32]byte) (*types.Transaction, error)
//
//	    // Storage backend management
//	    AllStorageBackends() ([]string, error)
//	    AddStorageBackend(locationURI string) (*types.Transaction, error)
//	    RemoveStorageBackend(locationURI string) (*types.Transaction, error)
//
//	    // Domain name management
//	    AllInstanceDomainNames() ([]string, error)
//	    RegisterInstanceDomainName(domain string) (*types.Transaction, error)
//
//	    // Identity management
//	    RemoveWhitelistedIdentity(identity [32]byte) (*types.Transaction, error)
//	}
//
// The RegistryFactory interface creates OnchainRegistry instances for different contract addresses:
//
//	type RegistryFactory interface {
//	    RegistryFor(ContractAddress) (OnchainRegistry, error)
//	}
//
// # Transaction Operations
//
// All state-modifying operations require transaction signing. Before using methods
// that modify state, you must call SetTransactOpts with appropriate transaction options
// including a private key for signing.
//
// Read-only operations do not require transaction options and can be used immediately
// after creating a client instance.
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
//	// Add configuration (requires transaction auth)
//	configData := []byte("your-config-data")
//	configHash, tx, err := client.AddConfig(configData)
package registry
