package storage

import (
	"fmt"
	"log/slog"
	"net/url"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ruteri/poc-tee-registry/interfaces"
)

// StorageBackendFactory creates storage backends from URI strings and manages
// multi-backend configurations for redundant storage.
type StorageBackendFactory struct {
	log             *slog.Logger
	registryFactory interfaces.RegistryFactory
}

// NewStorageBackendFactory creates a new factory instance that can create storage backends.
// If registryFactory is provided, it will be used to create OnchainBackend instances.
func NewStorageBackendFactory(logger *slog.Logger, registryFactory interfaces.RegistryFactory) *StorageBackendFactory {
	return &StorageBackendFactory{
		log:             logger,
		registryFactory: registryFactory,
	}
}

// StorageBackendFor creates a storage backend from a location URI.
// The URI format should be [scheme]://[auth@]host[:port][/path][?params]
//
// Supported schemes:
//   - file:// - Local filesystem storage
//   - s3:// - Amazon S3 or compatible object storage
//   - ipfs:// - IPFS distributed storage
//   - onchain:// - Storage on Ethereum blockchain via Registry contract
//   - github:// - Read-only storage using GitHub's Git blob API
//
// Returns an error if the URI is invalid or the scheme is unsupported.
func (sf *StorageBackendFactory) StorageBackendFor(locationURI interfaces.StorageBackendLocation) (interfaces.StorageBackend, error) {
	// Parse the URI
	u, err := url.Parse(string(locationURI))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", interfaces.ErrInvalidLocationURI, err)
	}

	// Create the appropriate backend type based on the scheme
	switch strings.ToLower(u.Scheme) {
	case "onchain":
		return sf.createOnchainBackend(u)
	case "github":
		return sf.createGitHubBackend(u)
	case "ipfs":
		return sf.createIPFSBackend(u)
	case "s3":
		return sf.createS3Backend(u)
	case "file":
		return sf.createFileBackend(u)
	default:
		return nil, fmt.Errorf("unsupported backend scheme: %s", u.Scheme)
	}
}

// CreateMultiBackend creates a multi-storage backend from a list of location URIs.
// The multi-backend aggregates all valid backends, providing redundancy for storage operations.
// It will store content to all available backends and fetch from the first one that has the content.
// Returns an error if no valid backends could be created from the provided URIs.
func (sf *StorageBackendFactory) CreateMultiBackend(locationURIs []interfaces.StorageBackendLocation) (interfaces.StorageBackend, error) {
	backends := make([]interfaces.StorageBackend, 0, len(locationURIs))

	for _, uri := range locationURIs {
		backend, err := sf.StorageBackendFor(uri)
		if err != nil {
			sf.log.Warn("Failed to create storage backend",
				"err", err,
				slog.String("locationURI", string(uri)))
			continue
		}
		backends = append(backends, backend)
	}

	if len(backends) == 0 {
		return nil, fmt.Errorf("no valid storage backends created")
	}

	return NewMultiStorageBackend(backends, sf.log), nil
}

// createOnchainBackend creates a blockchain storage backend using the Registry contract.
// URI format: onchain://0x1234567890abcdef1234567890abcdef12345678
// The host part must be a valid Ethereum contract address.
func (sf *StorageBackendFactory) createOnchainBackend(u *url.URL) (interfaces.StorageBackend, error) {
	sf.log.Debug("Creating onchain backend", slog.String("uri", u.String()))

	// Parse contract address from host part
	addrHex := u.Host
	if !common.IsHexAddress(addrHex) {
		return nil, fmt.Errorf("invalid contract address: %s", addrHex)
	}

	contractAddr := common.HexToAddress(addrHex)
	var contractAddrBytes interfaces.ContractAddress
	copy(contractAddrBytes[:], contractAddr.Bytes())

	// Ensure we have a registry factory
	if sf.registryFactory == nil {
		return nil, fmt.Errorf("registry factory not configured")
	}

	registry, err := sf.registryFactory.RegistryFor(contractAddrBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to get registry for contract: %w", err)
	}

	return NewOnchainBackend(registry, contractAddrBytes, sf.log), nil
}

// createGitHubBackend creates a read-only GitHub storage backend.
// URI format: github://owner/repo
// The backend uses Git's blob objects directly for content addressing.
func (sf *StorageBackendFactory) createGitHubBackend(u *url.URL) (interfaces.StorageBackend, error) {
	sf.log.Debug("Creating GitHub backend", slog.String("uri", u.String()))

	// Parse owner and repo from host
	parts := strings.Split(u.Host, "/")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid GitHub URI format, expected github://owner/repo")
	}

	owner := parts[0]
	repo := parts[1]

	// Create the backend
	return NewGitHubBackend(owner, repo, sf.log), nil
}

// createIPFSBackend creates an IPFS storage backend.
// URI format: ipfs://host:port/?gateway=true&timeout=30s
// The backend can connect to either an IPFS node or a gateway.
func (sf *StorageBackendFactory) createIPFSBackend(u *url.URL) (interfaces.StorageBackend, error) {
	sf.log.Debug("Creating IPFS backend", slog.String("uri", u.String()))

	// Parse host and port
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = "5001" // Default IPFS API port
	}

	// Check if this is a gateway
	query := u.Query()
	useGateway := query.Get("gateway") == "true"

	// Parse timeout
	timeout := query.Get("timeout")
	if timeout == "" {
		timeout = "30s" // Default timeout
	}

	// Create the backend
	return NewIPFSBackend(host, port, useGateway, timeout, sf.log)
}

// createS3Backend creates an S3 or S3-compatible storage backend.
// URI format: s3://[ACCESS_KEY:SECRET_KEY@]bucket-name/path/?region=us-west-2&endpoint=custom.s3.com
// The backend supports both public buckets (read-only) and authenticated access.
func (sf *StorageBackendFactory) createS3Backend(u *url.URL) (interfaces.StorageBackend, error) {
	sf.log.Debug("Creating S3 backend", slog.String("uri", u.String()))

	// Get bucket name
	bucketName := u.Host

	// Parse path - remove leading slash
	path := strings.TrimPrefix(u.Path, "/")

	// Parse region and endpoint
	query := u.Query()
	region := query.Get("region")
	if region == "" {
		region = "us-east-1" // Default region
	}

	endpoint := query.Get("endpoint")

	// Parse credentials
	var accessKey, secretKey string
	credentials := query.Get("credentials")
	if credentials != "" {
		// Use credentials from profile/environment
		sf.log.Debug("Using credentials profile", slog.String("profile", credentials))
		// Note: In a real implementation, you would look up these credentials
		// from a secure store or environment based on the profile name
	} else if u.User != nil {
		// Extract credentials from URI (less secure)
		accessKey = u.User.Username()
		secretKey, _ = u.User.Password()
		sf.log.Debug("Using embedded credentials for write access")
	} else {
		sf.log.Debug("No credentials provided, S3 bucket assumed to be public, write operations may fail")
	}

	// Create the backend
	return NewS3Backend(bucketName, path, region, endpoint, accessKey, secretKey, sf.log)
}

// createFileBackend creates a file system storage backend.
// URI format: file:///absolute/path/ or file://./relative/path/
// The backend stores content in a directory structure organized by content type.
func (sf *StorageBackendFactory) createFileBackend(u *url.URL) (interfaces.StorageBackend, error) {
	sf.log.Debug("Creating file backend", slog.String("uri", u.String()))

	// Get the path, handling relative vs absolute paths
	path := u.Path
	if u.Host != "" {
		// Handle Windows-style paths like file://C:/path
		if strings.HasPrefix(u.Host, "C:") || strings.HasPrefix(u.Host, "D:") {
			path = u.Host + path
		} else {
			path = u.Host + "/" + strings.TrimPrefix(path, "/")
		}
	}

	// Make sure path is not empty
	if path == "" {
		return nil, fmt.Errorf("empty path in file URI: %s", u.String())
	}

	// Create the backend
	return NewFileBackend(path, sf.log)
}
