// Package storage provides a content-addressed storage system with pluggable backends.
//
// The storage package offers a unified interface for storing and retrieving content
// identified by SHA-256 hash across multiple storage backends:
//
//   - File system storage for local development and testing
//   - S3-compatible storage for cloud deployments
//   - IPFS storage for decentralized content
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
// Error definitions:
//
//	var (
//	    // ErrContentNotFound is returned when requested content cannot be found
//	    ErrContentNotFound = errors.New("content not found")
//	    // ErrBackendUnavailable is returned when a backend is not accessible
//	    ErrBackendUnavailable = errors.New("storage backend unavailable")
//	    // ErrInvalidLocationURI is returned when a location URI is invalid
//	    ErrInvalidLocationURI = errors.New("invalid storage location URI")
//	)
//
// The StorageBackend interface represents any system that can store and retrieve data:
//
//	type StorageBackend interface {
//	    // Fetch retrieves data by its identifier and type
//	    Fetch(ctx context.Context, id ContentID, contentType ContentType) ([]byte, error)
//
//	    // Store saves data of the specified type and returns its identifier
//	    Store(ctx context.Context, data []byte, contentType ContentType) (ContentID, error)
//
//	    // Available checks if this backend is currently accessible
//	    Available(ctx context.Context) bool
//
//	    // Name returns the backend type (for logging/monitoring)
//	    Name() string
//
//	    // LocationURI returns the URI of this backend
//	    LocationURI() string
//	}
//
// The StorageBackendFactory interface creates storage backends from URI strings:
//
//	type StorageBackendFactory interface {
//	    // StorageBackendFor creates a storage backend from a location URI
//	    StorageBackendFor(locationURI StorageBackendLocation) (StorageBackend, error)
//
//	    // CreateMultiBackend creates a multi-storage backend from a list of location URIs
//	    CreateMultiBackend(locationURIs []StorageBackendLocation) (StorageBackend, error)
//	}
//
// # Multi-Backend Storage
//
// The MultiStorageBackend aggregates multiple backends for redundancy:
//
//   - Store: Attempts to store in all available backends
//   - Fetch: Tries each backend until content is found
//   - Available: Returns true if any backend is available
//
// # Usage Example
//
//	// Create a storage factory
//	factory := storage.NewStorageBackendFactory(logger)
//
//	// Create a file backend
//	fileBackend, err := factory.StorageBackendFor("file:///var/lib/registry/")
//	if err != nil {
//	    log.Fatalf("Failed to create file backend: %v", err)
//	}
//
//	// Store content
//	data := []byte("example configuration data")
//	id, err := fileBackend.Store(context.Background(), data, interfaces.ConfigType)
//	if err != nil {
//	    log.Fatalf("Failed to store config: %v", err)
//	}
//
//	// Retrieve content
//	retrievedData, err := fileBackend.Fetch(context.Background(), id, interfaces.ConfigType)
//	if err != nil {
//	    log.Fatalf("Failed to fetch config: %v", err)
//	}
//
// # Multi-Backend Example
//
//	// Create a multi-backend from multiple locations
//	locations := []interfaces.StorageBackendLocation{
//	    "file:///var/lib/registry/",
//	    "s3://my-bucket/registry/?region=us-west-2",
//	    "ipfs://localhost:5001/",
//	}
//	multiBackend, err := factory.CreateMultiBackend(locations)
package storage
