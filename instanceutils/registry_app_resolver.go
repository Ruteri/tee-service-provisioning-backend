package instanceutils

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/ruteri/tee-service-provisioning-backend/api"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// RegistryAppResolver implements the AppResolver interface using the TEE registry system.
// It provides resolution of application instances and certificate management for
// secure communication between TEE instances.
type RegistryAppResolver struct {
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
//   - registryFactory: Factory for creating registry clients
//   - cacheTTL: Time-to-live for cached instance information
//   - log: Logger for operational insights
//
// Returns:
//   - A configured RegistryAppResolver instance
func NewRegistryAppResolver(
	registryFactory interfaces.RegistryFactory,
	cacheTTL time.Duration,
	log *slog.Logger,
) *RegistryAppResolver {
	// Default cache TTL to 5 minutes if not specified
	if cacheTTL == 0 {
		cacheTTL = 5 * time.Minute
	}

	return &RegistryAppResolver{
		registryFactory: registryFactory,
		instanceCache:   make(map[string]instanceCacheEntry),
		cacheTTL:        cacheTTL,
		log:             log,
	}
}

// GetAppMetadata retrieves the CA certificate and instance addresses for a contract.
// This implements the AppResolver interface and provides the materials needed for
// secure communication with instances of the target application.
func (r *RegistryAppResolver) GetAppMetadata(contractAddr interfaces.ContractAddress) (*api.MetadataResponse, error) {
	registry, err := r.registryFactory.RegistryFor(contractAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to get registry for %x: %w", contractAddr, err)
	}

	pki, err := registry.GetPKI()
	if err != nil {
		return nil, fmt.Errorf("failed to get PKI from registry: %w", err)
	}

	// Get all registered domain names from registry
	domainNames, err := registry.AllInstanceDomainNames()
	if err != nil {
		return nil, fmt.Errorf("failed to get domain names from registry: %w", err)
	}

	parsedDomainNames := []interfaces.AppDomainName{}
	for _, dn := range domainNames {
		pdn, err := interfaces.NewAppDomainName(dn)
		if err != nil {
			r.log.Debug("invalid domain", "contract", contractAddr.String(), "domain", dn, "err", err)
			continue
		}
		parsedDomainNames = append(parsedDomainNames, pdn)
	}

	return &api.MetadataResponse{
		CACert:      pki.Ca,
		AppPubkey:   pki.Pubkey,
		DomainNames: parsedDomainNames,
		Attestation: nil,
	}, nil
}

// LocalKMSRegistrationProvider implements RegistrationProvider using a local KMS.
// This is useful for testing and development environments without a remote provisioning server.
type LocalKMSRegistrationProvider struct {
	// KMS is the key management system used for certificate signing and key generation
	KMS interfaces.KMS
}

// Register uses a local KMS to sign the CSR and provide application materials.
// This implementation doesn't provide configuration, only cryptographic materials.
func (p *LocalKMSRegistrationProvider) Register(app interfaces.ContractAddress, csr []byte) (*api.RegistrationResponse, error) {
	cert, err := p.KMS.SignCSR(app, csr)
	if err != nil {
		return nil, err
	}

	appPrivkey, err := p.KMS.GetAppPrivkey(app)
	if err != nil {
		return nil, err
	}

	return &api.RegistrationResponse{
		AppPrivkey: appPrivkey,
		TLSCert:    cert,
		Config:     interfaces.InstanceConfig{},
	}, nil
}

func (p *LocalKMSRegistrationProvider) GetAppMetadata(contractAddr interfaces.ContractAddress) (*api.MetadataResponse, error) {
	pki, err := p.KMS.GetPKI(contractAddr)
	if err != nil {
		return nil, err
	}

	return &api.MetadataResponse{
		CACert:      pki.Ca,
		AppPubkey:   pki.Pubkey,
		DomainNames: nil,
		Attestation: pki.Attestation,
	}, nil
}
