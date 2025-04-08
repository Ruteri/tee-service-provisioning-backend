package storage

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// StorageBackendFactory creates storage backends from URI strings and manages
// multi-backend configurations for redundant storage.
type StorageBackendFactory struct {
	log             *slog.Logger
	registryFactory interfaces.RegistryFactory
	tlsAuthCertFn   func() (tls.Certificate, error)
}

// NewStorageBackendFactory creates a new factory instance that can create storage backends.
// If registryFactory is provided, it will be used to create OnchainBackend instances.
func NewStorageBackendFactory(logger *slog.Logger, registryFactory interfaces.RegistryFactory) *StorageBackendFactory {
	return &StorageBackendFactory{
		log:             logger,
		registryFactory: registryFactory,
	}
}

// WithTLSAuth sets tls certificate lazy function for authorization in tls-enabled backends
func (f *StorageBackendFactory) WithTLSAuth(lazyTlsAuthCert func() (tls.Certificate, error)) interfaces.StorageBackendFactory {
	nf := f
	nf.tlsAuthCertFn = lazyTlsAuthCert
	return nf
}

// StorageBackendFor creates a storage backend from a location URI.
// The URI format should be [scheme]://[auth@]host[:port][/path][?params]
//
// Returns an error if the URI is invalid or the scheme is unsupported.
func (sf *StorageBackendFactory) StorageBackendFor(locationURI interfaces.StorageBackendLocation) (interfaces.StorageBackend, error) {
	// Create the appropriate backend type based on the scheme
	switch strings.ToLower(locationURI.Scheme) {
	case "onchain":
		return sf.createOnchainBackend(locationURI)
	case "github":
		return sf.createGitHubBackend(locationURI)
	case "ipfs":
		return sf.createIPFSBackend(locationURI)
	case "s3":
		return sf.createS3Backend(locationURI)
	case "vault":
		if sf.tlsAuthCertFn == nil {
			return nil, fmt.Errorf("client certificate and key are required for Vault backend")
		}

		tlsAuthCert, err := sf.tlsAuthCertFn()
		if err != nil {
			return nil, fmt.Errorf("client certificate and key are required for Vault backend")
		}
		return sf.createVaultBackend(locationURI, tlsAuthCert)
	case "file":
		return sf.createFileBackend(locationURI)
	default:
		return nil, fmt.Errorf("unsupported backend scheme: %s", locationURI.Scheme)
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
				slog.String("locationURI", uri.String()))
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
func (sf *StorageBackendFactory) createOnchainBackend(loc interfaces.StorageBackendLocation) (interfaces.StorageBackend, error) {
	sf.log.Debug("Creating onchain backend", slog.String("uri", loc.String()))

	contractAddrBytes, err := interfaces.NewContractAddressFromHex(loc.Host)
	if err != nil {
		return nil, fmt.Errorf("invalid contract address bytes: %w", err)
	}

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
func (sf *StorageBackendFactory) createGitHubBackend(loc interfaces.StorageBackendLocation) (interfaces.StorageBackend, error) {
	sf.log.Debug("Creating GitHub backend", slog.String("uri", loc.String()))

	// Parse owner and repo from host
	parts := strings.Split(loc.Host, "/")
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
func (sf *StorageBackendFactory) createIPFSBackend(loc interfaces.StorageBackendLocation) (interfaces.StorageBackend, error) {
	sf.log.Debug("Creating IPFS backend", slog.String("uri", loc.String()))

	// Parse host and port
	hostParts := strings.Split(loc.Host, ":")
	host := hostParts[0]
	port := "5001" // Default IPFS API port
	if len(hostParts) > 1 {
		port = hostParts[1]
	}

	// Check if this is a gateway
	useGateway := loc.GetParamBool("gateway")

	// Parse timeout
	timeout := loc.GetParam("timeout")
	if timeout == "" {
		timeout = "30s" // Default timeout
	}

	// Create the backend
	return NewIPFSBackend(host, port, useGateway, timeout, sf.log)
}

// createS3Backend creates an S3 or S3-compatible storage backend.
// URI format: s3://[ACCESS_KEY:SECRET_KEY@]bucket-name/path/?region=us-west-2&endpoint=custom.s3.com
// The backend supports both public buckets (read-only) and authenticated access.
func (sf *StorageBackendFactory) createS3Backend(loc interfaces.StorageBackendLocation) (interfaces.StorageBackend, error) {
	sf.log.Debug("Creating S3 backend", slog.String("uri", loc.String()))

	// Get bucket name
	bucketName := loc.Host

	// Parse path - remove leading slash
	path := strings.TrimPrefix(loc.Path, "/")

	// Parse region and endpoint
	region := loc.GetParam("region")
	if region == "" {
		region = "us-east-1" // Default region
	}

	endpoint := loc.GetParam("endpoint")

	// Parse credentials
	var accessKey, secretKey string
	credentials := loc.GetParam("credentials")
	if credentials != "" {
		// Use credentials from profile/environment
		sf.log.Debug("Using credentials profile", slog.String("profile", credentials))
		// Note: In a real implementation, you would look up these credentials
		// from a secure store or environment based on the profile name
	} else if loc.Auth != "" {
		// Extract credentials from URI (less secure)
		authParts := strings.SplitN(loc.Auth, ":", 2)
		accessKey = authParts[0]
		if len(authParts) > 1 {
			secretKey = authParts[1]
		}
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
func (sf *StorageBackendFactory) createFileBackend(loc interfaces.StorageBackendLocation) (interfaces.StorageBackend, error) {
	sf.log.Debug("Creating file backend", slog.String("uri", loc.String()))

	// Get the path, handling relative vs absolute paths
	path := loc.Path
	if loc.Host != "" {
		// Handle Windows-style paths like file://C:/path
		if strings.HasPrefix(loc.Host, "C:") || strings.HasPrefix(loc.Host, "D:") {
			path = loc.Host + path
		} else {
			path = loc.Host + "/" + strings.TrimPrefix(path, "/")
		}
	}

	// Make sure path is not empty
	if path == "" {
		return nil, fmt.Errorf("empty path in file URI: %s", loc.String())
	}

	// Create the backend
	return NewFileBackend(path, sf.log)
}

// createVaultBackend creates a Vault storage backend with TLS client certificate authentication.
// URI format: vault://vault.example.com:8200/secret/data
// The client certificate must be signed by the application CA for TLS authentication.
func (sf *StorageBackendFactory) createVaultBackend(
	loc interfaces.StorageBackendLocation,
	tlsCert tls.Certificate,
) (interfaces.StorageBackend, error) {
	sf.log.Debug("Creating Vault backend", slog.String("uri", loc.String()))

	// Parse server address
	address := loc.Host
	if !strings.HasPrefix(address, "http") {
		// Default to HTTPS
		address = "https://" + address
	}

	// Parse path parts (mount path and data path)
	path := strings.TrimPrefix(loc.Path, "/")
	pathParts := strings.SplitN(path, "/", 2)
	if len(pathParts) < 2 {
		return nil, fmt.Errorf("invalid Vault URI format, expected vault://host:port/mount/path")
	}

	mountPath := pathParts[0]
	dataPath := pathParts[1]

	// Create the backend
	return NewVaultBackend(address, mountPath, dataPath, tlsCert, sf.log)
}
