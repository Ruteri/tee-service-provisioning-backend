package interfaces

import (
	"context"
	"errors"
)

// ContentID represents a unique identifier for any content in the system
type ContentID [32]byte

// ContentType indicates what kind of content is being stored/retrieved
type ContentType int

const (
	ConfigType ContentType = iota
	SecretType
)

var (
	// ErrContentNotFound is returned when requested content cannot be found
	ErrContentNotFound = errors.New("content not found")
	// ErrBackendUnavailable is returned when a backend is not accessible
	ErrBackendUnavailable = errors.New("storage backend unavailable")
	// ErrInvalidLocationURI is returned when a location URI is invalid
	ErrInvalidLocationURI = errors.New("invalid storage location URI")
)

// StorageBackend represents any system that can store and retrieve data
type StorageBackend interface {
	// Fetch retrieves data by its identifier and type
	Fetch(ctx context.Context, id ContentID, contentType ContentType) ([]byte, error)

	// Store saves data of the specified type and returns its identifier
	Store(ctx context.Context, data []byte, contentType ContentType) (ContentID, error)

	// Available checks if this backend is currently accessible
	Available(ctx context.Context) bool

	// Name returns the backend type (for logging/monitoring)
	Name() string
	
	// LocationURI returns the URI of this backend
	LocationURI() string
}

// StorageBackendFactory creates storage backends from URI strings
type StorageBackendFactory interface {
	// StorageBackendFor creates a storage backend from a location URI
	StorageBackendFor(locationURI StorageBackendLocation) (StorageBackend, error)
	
	// CreateMultiBackend creates a multi-storage backend from a list of location URIs
	CreateMultiBackend(locationURIs []StorageBackendLocation) (StorageBackend, error)
}
