// Package interfaces defines the core interfaces and types for the TEE registry system.
// It provides the contract between different components without implementation details.
package interfaces

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// ContentID represents a unique identifier for any content in the system.
// It is a 32-byte hash of the content (SHA-256).
type ContentID [32]byte

// NewContentID creates a content ID from a byte array or by computing the hash of data.
func NewContentIDFromBytes(source []byte) (ContentID, error) {
	if len(source) != 32 {
		return ContentID{}, errors.New("invalid ContentID conversion from bytes: incorrect length")
	}

	var hash [32]byte
	copy(hash[:], source)
	return ContentID(hash), nil
}

func NewContentIDFromHex(source string) (ContentID, error) {
	// Remove 0x prefix if present
	clean := strings.TrimPrefix(source, "0x")
	if len(clean) != 64 {
		return ContentID{}, errors.New("invalid content ID length: hex string must be 64 characters")
	}

	// Decode hex string
	hashBytes, err := hex.DecodeString(clean)
	if err != nil {
		return ContentID{}, fmt.Errorf("invalid hex format: %w", err)
	}

	var hash [32]byte
	copy(hash[:], hashBytes)
	return ContentID(hash), nil
}

// ComputeID calculates the content ID for the given data.
func ComputeID(data []byte) ContentID {
	hash := sha256.Sum256(data)
	return ContentID(hash)
}

// String returns the hex string representation of the content ID.
func (id ContentID) String() string {
	return hex.EncodeToString(id[:])
}

// Bytes returns the raw 32-byte hash.
func (id ContentID) Bytes() []byte {
	return id[:]
}

// Equal compares two content IDs for equality.
func (id ContentID) Equal(other ContentID) bool {
	return bytes.Equal(id[:], other[:])
}

// ContentType indicates what kind of content is being stored or retrieved.
// This allows different content types to be stored in separate namespaces.
type ContentType int

const (
	// ConfigType represents configuration data stored in the system.
	ConfigType ContentType = iota

	// SecretType represents encrypted secret data stored in the system.
	SecretType
)

// String returns a string representation of the content type.
func (ct ContentType) String() string {
	switch ct {
	case ConfigType:
		return "config"
	case SecretType:
		return "secret"
	default:
		return "unknown"
	}
}

// StorageBackendLocation represents a URI location for a content storage backend.
type StorageBackendLocation struct {
	// Raw is the original URI string
	Raw string

	// Parsed components
	Scheme string
	Host   string
	Path   string
	Query  url.Values
	Auth   string
}

// NewStorageBackendLocation creates a new storage location from a URI string with validation.
func NewStorageBackendLocation(uri string) (StorageBackendLocation, error) {
	parsed, err := url.Parse(uri)
	if err != nil {
		return StorageBackendLocation{}, fmt.Errorf("invalid URI format: %w", err)
	}

	// Validate scheme is supported
	scheme := parsed.Scheme
	switch scheme {
	case "file", "s3", "ipfs", "onchain", "github", "vault":
		// Valid scheme
	default:
		return StorageBackendLocation{}, fmt.Errorf("unsupported storage scheme: %s", scheme)
	}

	// Parse authentication info if present
	var auth string
	if parsed.User != nil {
		auth = parsed.User.String()
	}

	return StorageBackendLocation{
		Raw:    uri,
		Scheme: scheme,
		Host:   parsed.Host,
		Path:   parsed.Path,
		Query:  parsed.Query(),
		Auth:   auth,
	}, nil
}

// String returns the original URI string.
func (loc StorageBackendLocation) String() string {
	return loc.Raw
}

// IsOnChain checks if this is an on-chain storage location.
func (loc StorageBackendLocation) IsOnChain() bool {
	return loc.Scheme == "onchain"
}

// IsFile checks if this is a file system storage location.
func (loc StorageBackendLocation) IsFile() bool {
	return loc.Scheme == "file"
}

// IsS3 checks if this is an S3 storage location.
func (loc StorageBackendLocation) IsS3() bool {
	return loc.Scheme == "s3"
}

// IsIPFS checks if this is an IPFS storage location.
func (loc StorageBackendLocation) IsIPFS() bool {
	return loc.Scheme == "ipfs"
}

// IsGitHub checks if this is a GitHub storage location.
func (loc StorageBackendLocation) IsGitHub() bool {
	return loc.Scheme == "github"
}

// IsVault checks if this is a Vault storage location.
func (loc StorageBackendLocation) IsVault() bool {
	return loc.Scheme == "vault"
}

// GetParam returns a query parameter value.
func (loc StorageBackendLocation) GetParam(name string) string {
	return loc.Query.Get(name)
}

// GetParamBool returns a boolean query parameter value.
func (loc StorageBackendLocation) GetParamBool(name string) bool {
	value := loc.Query.Get(name)
	return value == "true" || value == "1" || value == "yes"
}

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
	// Supported schemes include: file://, s3://, ipfs://, onchain://, github://, vault://
	// Returns an error if the URI is invalid or the backend type is unsupported.
	StorageBackendFor(locationURI StorageBackendLocation) (StorageBackend, error)

	// CreateMultiBackend creates a storage backend that aggregates multiple backends.
	// The multi-backend provides redundancy by trying operations across all backends.
	// Returns an error if no valid backends could be created from the URIs.
	CreateMultiBackend(locationURIs []StorageBackendLocation) (StorageBackend, error)

	// WithTLSAuth configures factory to use TLS certificate for authorization in TLS-enabled backends
	WithTLSAuth(func() (tls.Certificate, error)) StorageBackendFactory
}
