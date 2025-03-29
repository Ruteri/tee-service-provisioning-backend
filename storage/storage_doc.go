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
// Creating content in this model:
//
//  1. Create a blob with your content using git hash-object
//  2. The blob SHA becomes your ContentID for retrieval
//
// Example Git commands:
//
//	# Create a blob and get its SHA (which becomes your ContentID)
//	blob_sha=$(git hash-object -w --stdin < myfile.json)
//
//	# Push to a remote repository
//	# (This step requires adding the blob to the Git tree and creating a commit)
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
// # Usage Example for GitHub Storage (Read-Only)
//
//	// Create a GitHub backend
//	githubBackend, err := factory.StorageBackendFor("github://myorg/myrepo")
//	if err != nil {
//	    log.Fatalf("Failed to create GitHub backend: %v", err)
//	}
//
//	// The ContentID is a Git tree SHA that contains exactly one blob
//
// # Multi-Backend Example
//
//	// Create a multi-backend from multiple locations including the new backends
//	locations := []interfaces.StorageBackendLocation{
//	    "file:///var/lib/registry/",
//	    "onchain://0x1234567890abcdef1234567890abcdef12345678",
//	    "github://myorg/myrepo/main"
//	}
//	multiBackend, err := factory.CreateMultiBackend(locations)
package storage
