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

// ContentID is a 32-byte SHA-256 hash uniquely identifying content.
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

// ComputeID calculates content ID from data.
func ComputeID(data []byte) ContentID {
	hash := sha256.Sum256(data)
	return ContentID(hash)
}

// String returns hex representation.
func (id ContentID) String() string {
	return hex.EncodeToString(id[:])
}

// Bytes returns raw 32-byte hash.
func (id ContentID) Bytes() []byte {
	return id[:]
}

// Equal compares two content IDs.
func (id ContentID) Equal(other ContentID) bool {
	return bytes.Equal(id[:], other[:])
}

// ContentType indicates storage namespace.
type ContentType int

const (
	// ConfigType for configuration data
	ConfigType ContentType = iota
	// SecretType for encrypted secrets
	SecretType
)

// String returns type name.
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

// StorageBackendLocation represents URI for storage backend.
type StorageBackendLocation struct {
	Raw    string     // Original URI
	Scheme string     // Protocol
	Host   string     // Hostname
	Path   string     // Resource path
	Query  url.Values // Query parameters
	Auth   string     // Authentication info
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

// StorageBackend provides content-addressed data storage.
type StorageBackend interface {
	// Fetch retrieves data by content ID and type.
	Fetch(ctx context.Context, id ContentID, contentType ContentType) ([]byte, error)

	// Store saves data and returns its content ID.
	Store(ctx context.Context, data []byte, contentType ContentType) (ContentID, error)

	// Available checks if backend is accessible.
	Available(ctx context.Context) bool

	// Name returns identifier for logging.
	Name() string

	// LocationURI returns URI identifying this backend.
	LocationURI() string
}

// StorageBackendFactory creates storage backends.
type StorageBackendFactory interface {
	// StorageBackendFor creates backend from URI.
	// Supports file://, s3://, ipfs://, onchain://, github://, vault://
	StorageBackendFor(locationURI StorageBackendLocation) (StorageBackend, error)

	// CreateMultiBackend creates aggregated storage backend.
	CreateMultiBackend(locationURIs []StorageBackendLocation) (StorageBackend, error)

	// WithTLSAuth configures TLS client authentication.
	WithTLSAuth(func() (tls.Certificate, error)) StorageBackendFactory
}
