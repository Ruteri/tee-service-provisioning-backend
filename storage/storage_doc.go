// Package storage provides a content-addressed storage system with pluggable backends.
//
// The storage package offers a unified interface for storing and retrieving content
// identified by SHA-256 hash across multiple storage backends:
//
//   - File system storage for local development and testing
//   - S3-compatible storage for cloud deployments
//   - IPFS storage for decentralized content
//   - On-chain storage using Ethereum smart contracts
//   - GitHub storage using repository content
//   - Vault storage with TLS client certificate authentication
//
// # Storage URI Format
//
// Storage backends are specified using URI format:
//
//	[scheme]://[auth@]host[:port][/path][?params]
//
// Supported URI schemes:
//
//   - file:///var/lib/registry/configs/
//   - s3://bucket-name/prefix/?region=us-west-2
//   - ipfs://ipfs.example.com:5001/
//   - onchain://0x1234567890abcdef1234567890abcdef12345678
//   - github://owner/repo
//   - vault://vault.example.com:8200/secret/data
//
// # Content Addressing
//
// Content is stored and retrieved using content addressing, where the content
// identifier is the SHA-256 hash of the data. Different content types (configs
// and secrets) are stored in separate namespaces.
//
// # Types and Interfaces
//
// ContentID represents a unique identifier for any content in the system:
//
//	type ContentID [32]byte
//
// ContentType indicates what kind of content is being stored/retrieved:
//
//	type ContentType int
//
//	const (
//	    ConfigType ContentType = iota
//	    SecretType
//	)
//
// # On-Chain Storage
//
// The OnchainBackend stores content directly in the Registry smart contract using:
//
//   - mapping(bytes32 => bytes) configs - For configuration data
//   - mapping(bytes32 => bytes) encryptedSecrets - For encrypted secrets
//
// URI format: onchain://<contract-address>
//
// # GitHub Storage (Read-Only)
//
// The GitHubBackend fetches content directly from Git blobs in a GitHub repository:
//
//   - Uses ContentID directly as a Git blob SHA
//   - Directly accesses blob objects with no intermediate objects
//   - Maximum simplicity with minimal API calls
//   - Perfect integration with Git's object model
//
// URI format: github://owner/repo
//
// # Vault Storage with TLS Authentication
//
// The VaultBackend stores content in HashiCorp Vault using TLS client certificate authentication:
//
//   - Authentication: Uses TLS client certificates signed by the application CA from the KMS
//   - Path Structure: Uses KV v2 secret engine with path format: {mount}/data/{path}/{type}/{content_id}
//   - Content Types: Configs and secrets are stored in separate paths within Vault
//   - Security: Strong authentication and encryption for sensitive data
//
// URI format: vault://vault.example.com:8200/secret/data
//
// The client certificate must be provided when creating this backend. It should be signed
// by the application CA configured in Vault for TLS authentication.
//
// # Usage Example for On-Chain Storage
//
//	// Create a storage factory with registry factory
//	factory := storage.NewStorageBackendFactory(logger, registryFactory)
//
//	// Create an on-chain backend
//	onchainBackend, err := factory.StorageBackendFor("onchain://0x1234567890abcdef1234567890abcdef12345678")
//	if err != nil {
//	    log.Fatalf("Failed to create on-chain backend: %v", err)
//	}
//
// # Usage Example for Vault Storage with TLS Authentication
//
//	// Create a Vault backend with TLS authentication
//	vaultBackend, err := factory.StorageBackendFor("vault://vault.example.com:8200/secret/data")
//	if err != nil {
//	    log.Fatalf("Failed to create Vault backend: %v", err)
//	}
//
// # Multi-Backend Example
//
//	// Create a multi-backend from multiple locations including Vault
//	locations := []interfaces.StorageBackendLocation{
//	    "file:///var/lib/registry/",
//	    "onchain://0x1234567890abcdef1234567890abcdef12345678",
//	    "vault://vault.example.com:8200/secret/data"
//	}
//	multiBackend, err := factory.CreateMultiBackend(locations)
package storage
