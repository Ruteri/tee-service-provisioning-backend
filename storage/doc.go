// Package storage provides a content-addressed storage system with pluggable
// backends.
//
// The storage package offers a unified interface for storing and retrieving
// content identified by SHA-256 hash across multiple storage backends:
//
//   - File system storage for local development and testing
//   - S3-compatible storage for cloud deployments
//   - IPFS storage for decentralized content
//   - On-chain storage using Ethereum smart contracts
//   - GitHub storage using repository content
//   - Vault storage with TLS client authentication
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
// identifier is the SHA-256 hash of the data. Different content types (configs and
// secrets) are stored in separate namespaces.
//
// This content-addressed approach provides several benefits:
//
//   - Content is immutable and uniquely identified
//   - Same content can be mirrored across multiple backends
//   - Integrity can be verified by recalculating the hash
//   - Content can be referenced securely in configurations
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
// The StorageBackend interface defines methods for content operations:
//
//	type StorageBackend interface {
//	    Fetch(ctx context.Context, id ContentID, contentType ContentType) ([]byte, error)
//	    Store(ctx context.Context, data []byte, contentType ContentType) (ContentID, error)
//	    Available(ctx context.Context) bool
//	    Name() string
//	    LocationURI() string
//	}
//
// # Multi-Backend Support
//
// The MultiStorageBackend aggregates multiple backends for redundancy:
//
//   - Stores content to all available backends
//   - Fetches content from the first backend that has it
//   - Reports availability if any backend is available
//
// # Usage Example for Multiple Backends
//
//	// Create a storage factory with registry factory
//	factory := storage.NewStorageBackendFactory(logger, registryFactory)
//
//	// Create a multi-backend from multiple locations
//	locations := []interfaces.StorageBackendLocation{
//	    "file:///var/lib/registry/",
//	    "onchain://0x1234567890abcdef1234567890abcdef12345678",
//	    "vault://vault.example.com:8200/secret/data"
//	}
//	multiBackend, err := factory.CreateMultiBackend(locations)
package storage
