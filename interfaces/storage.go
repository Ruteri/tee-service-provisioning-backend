// Package interfaces defines the core interfaces and types for the TEE registry system.
// It provides the contract between different components without implementation details.
package interfaces

import (
	"context"
	"crypto/tls"
	"errors"
)

// ContentID represents a unique identifier for any content in the system.
// It is a 32-byte hash of the content (SHA-256).
type ContentID [32]byte

// ContentType indicates what kind of content is being stored or retrieved.
// This allows different content types to be stored in separate namespaces.
type ContentType int

const (
	// ConfigType represents configuration data stored in the system.
	ConfigType ContentType = iota

	// SecretType represents encrypted secret data stored in the system.
	SecretType
)

var (
	// ErrContentNotFound is returned when requested content cannot be found in the storage backend.
	ErrContentNotFound = errors.New("content not found")

	// ErrBackendUnavailable is returned when a storage backend is not accessible.
	// This could be due to network issues, authentication failures, or service outages.
	ErrBackendUnavailable = errors.New("storage backend unavailable")

	// ErrInvalidLocationURI is returned when a storage location URI is malformed or unsupported.
	// URIs must follow the format: [scheme]://[auth@]host[:port][/path][?params]
	ErrInvalidLocationURI = errors.New("invalid storage location URI")
)

// StorageBackend represents any system that can store and retrieve content-addressed data.
// Implementations include file systems, S3-compatible services, and IPFS nodes.
type StorageBackend interface {
	// Fetch retrieves data by its content identifier and type.
	// Returns the data or an error if the content cannot be found or the backend is unavailable.
	Fetch(ctx context.Context, id ContentID, contentType ContentType) ([]byte, error)

	// Store saves data of the specified type and returns its content identifier.
	// The content identifier is the SHA-256 hash of the data.
	Store(ctx context.Context, data []byte, contentType ContentType) (ContentID, error)

	// Available checks if this backend is currently accessible.
	// Returns true if the backend can be used for storage operations.
	Available(ctx context.Context) bool

	// Name returns a unique identifier for this storage backend.
	// Used for logging, monitoring, and debugging purposes.
	Name() string

	// LocationURI returns the URI that uniquely identifies this storage backend.
	// The URI follows the format: [scheme]://[auth@]host[:port][/path][?params]
	LocationURI() string
}

// StorageBackendFactory creates storage backends from URI strings.
// It handles the creation logic for different backend types based on the URI scheme.
type StorageBackendFactory interface {
	// StorageBackendFor creates a storage backend from a location URI.
	// Supported schemes include: file://, s3://, and ipfs://
	// Returns an error if the URI is invalid or the backend type is unsupported.
	StorageBackendFor(locationURI StorageBackendLocation) (StorageBackend, error)

	// CreateMultiBackend creates a storage backend that aggregates multiple backends.
	// The multi-backend provides redundancy by trying operations across all backends.
	// Returns an error if no valid backends could be created from the URIs.
	CreateMultiBackend(locationURIs []StorageBackendLocation) (StorageBackend, error)

	// WithTLSAuth configures factory to use TLS certificate for authorization in TLS-enabled backends
	WithTLSAuth(func() (tls.Certificate, error)) StorageBackendFactory
}
