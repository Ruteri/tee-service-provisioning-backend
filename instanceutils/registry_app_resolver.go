package instanceutils

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// RegistryAppResolver implements the AppResolver interface using the TEE registry system.
// It provides resolution of application instances and certificate management for
// secure communication between TEE instances.
type RegistryAppResolver struct {
	// registrationProvider handles TEE instance registration and certificate requests
	registrationProvider RegistrationProvider

	// registryFactory creates registry clients for different contract addresses
	registryFactory interfaces.RegistryFactory

	// Cache for application instances to reduce registry calls
	instanceCache     map[string]instanceCacheEntry
	instanceCacheLock sync.RWMutex

	// Cache TTL configuration
	cacheTTL time.Duration

	// Logger for operational insights
	log *slog.Logger
}

// instanceCacheEntry represents a cached result of instance resolution.
// It includes the list of instance addresses and an expiration timestamp.
type instanceCacheEntry struct {
	instances []string
	expiry    time.Time
}

// NewRegistryAppResolver creates a new app resolver using the registry and KMS.
// Parameters:
//   - registrationProvider: Provider for registering with the TEE registry
//   - registryFactory: Factory for creating registry clients
//   - cacheTTL: Time-to-live for cached instance information
//   - log: Logger for operational insights
//
// Returns:
//   - A configured RegistryAppResolver instance
func NewRegistryAppResolver(
	registrationProvider RegistrationProvider,
	registryFactory interfaces.RegistryFactory,
	cacheTTL time.Duration,
	log *slog.Logger,
) *RegistryAppResolver {
	// Default cache TTL to 5 minutes if not specified
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}

	return &RegistryAppResolver{
		registrationProvider: registrationProvider,
		registryFactory:      registryFactory,
		instanceCache:        make(map[string]instanceCacheEntry),
		cacheTTL:             cacheTTL,
		log:                  log,
	}
}

// GetAppMetadata retrieves the CA certificate and instance addresses for a contract.
// This implements the AppResolver interface and provides the materials needed for
// secure communication with instances of the target application.
func (r *RegistryAppResolver) GetAppMetadata(contractAddr interfaces.ContractAddress) (interfaces.CACert, []string, error) {
	registry, err := r.registryFactory.RegistryFor(contractAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get registry for %x: %w", contractAddr, err)
	}

	pki, err := registry.GetPKI()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get PKI from registry: %w", err)
	}

	// Get all registered domain names from registry
	domainNames, err := registry.AllInstanceDomainNames()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get domain names from registry: %w", err)
	}

	// TODO: resolve to IPs! domainNames are all SRV records

	return pki.Ca, domainNames, nil
}

// GetCert returns the TLS certificate for a given application.
// It creates a new CSR, registers with the provisioning system, and returns
// the resulting certificate for secure communication.
func (r *RegistryAppResolver) GetCert(contractAddr interfaces.ContractAddress) (*tls.Certificate, error) {
	privateKeyPEM, csr, err := cryptoutils.CreateCSRWithRandomKey(contractAddr.String())
	if err != nil {
		return nil, err
	}
	cert, err := r.registrationProvider.Register(contractAddr, csr)
	if err != nil {
		return nil, err
	}

	x509keypair, err := tls.X509KeyPair([]byte(cert.TLSCert), privateKeyPEM)
	if err != nil {
		return nil, err
	}

	return &x509keypair, nil
}
