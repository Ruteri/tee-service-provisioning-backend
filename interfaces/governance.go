package interfaces

import (
	"crypto/sha256"
	"fmt"

	"github.com/ethereum/go-ethereum/core/types"
	kmsbindings "github.com/ruteri/tee-service-provisioning-backend/bindings/kms"
	"github.com/ruteri/tee-service-provisioning-backend/bindings/registry"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
)

type DCAPEvent = registry.DCAPEvent
type MAAReport = registry.MAAReport
type OnboardRequest = kmsbindings.OnboardRequest
type InstanceConfig []byte

type AppPKI registry.AppPKI

// ReportData generates expected attestation report data.
func (p *AppPKI) ReportData(contractAddr ContractAddress) [64]byte {
	var expectedReportData [64]byte
	copy(expectedReportData[:20], contractAddr[:])
	certsHash := sha256.Sum256(append(p.Ca, p.Pubkey...))
	copy(expectedReportData[20:], certsHash[:])
	return expectedReportData
}

// KMS handles cryptographic operations for TEE applications.
type KMS interface {
	// GetPKI retrieves application CA certificate, public key, and attestation.
	GetPKI(contractAddr ContractAddress) (AppPKI, error)

	// AppSecrets provides all cryptographic materials for a TEE instance.
	AppSecrets(ContractAddress, TLSCSR) (*AppSecrets, error)
}

// WorkloadGovernance handles TEE identity verification through attestation.
type WorkloadGovernance interface {
	// DCAPIdentity calculates identity hash for a DCAP report.
	DCAPIdentity(report DCAPReport, events []DCAPEvent) ([32]byte, error)

	// MAAIdentity calculates identity hash for an MAA report.
	MAAIdentity(report MAAReport) ([32]byte, error)

	// IdentityAllowed checks if an identity is authorized.
	// Optionally validates the operator address.
	IdentityAllowed(identity [32]byte, operator [20]byte) (bool, error)
}

// KMSGovernance extends WorkloadGovernance with KMS management operations.
type KMSGovernance interface {
	WorkloadGovernance
	OnchainDiscovery

	// WhitelistDCAP adds a DCAP-attested identity to the whitelist.
	WhitelistDCAP(DCAPReport) (*types.Transaction, error)

	// WhitelistMAA adds an MAA-attested identity to the whitelist.
	WhitelistMAA(MAAReport) (*types.Transaction, error)

	// WhitelistIdentity adds an identity hash to the whitelist.
	WhitelistIdentity([32]byte) (*types.Transaction, error)

	// RemoveWhitelistedIdentity removes an identity from the whitelist.
	RemoveWhitelistedIdentity([32]byte) (*types.Transaction, error)

	// RequestOnboard submits an onboarding request for a new TEE instance.
	RequestOnboard(OnboardRequest) (*types.Transaction, error)

	// FetchOnboardRequest retrieves an onboarding request.
	FetchOnboardRequest([32]byte) (OnboardRequest, error)
}

// ConfigGovernance manages TEE instance configuration.
type ConfigGovernance interface {
	// ConfigForIdentity gets configuration hash for an identity.
	ConfigForIdentity(identity [32]byte, operator [20]byte) ([32]byte, error)

	// StorageBackends returns registered storage backend URIs.
	StorageBackends() ([]string, error)
}

// OnchainDiscovery provides TEE service information discovery.
type OnchainDiscovery interface {
	// PKI retrieves application PKI information.
	PKI() (AppPKI, error)

	// InstanceDomainNames returns registered instance domain names.
	InstanceDomainNames() ([]string, error)
}

// OnchainRegistry combines governance interfaces for TEE management.
type OnchainRegistry interface {
	WorkloadGovernance
	OnchainDiscovery
	ConfigGovernance

	// SetConfigForIdentity associates configuration with an identity.
	SetConfigForIdentity(identity [32]byte, artifactHash [32]byte) (*types.Transaction, error)

	// GetArtifact retrieves content by its hash.
	GetArtifact(artifactHash [32]byte) ([]byte, error)

	// RegisterInstanceDomainName adds domain for service discovery.
	RegisterInstanceDomainName(domain string) (*types.Transaction, error)

	// AddArtifact stores configuration or secret data.
	AddArtifact(data []byte) ([32]byte, *types.Transaction, error)

	// AddStorageBackend registers a storage backend URI.
	AddStorageBackend(locationURI string) (*types.Transaction, error)

	// RemoveStorageBackend unregisters a storage backend URI.
	RemoveStorageBackend(locationURI string) (*types.Transaction, error)
}

// RegistryFactory creates OnchainRegistry instances.
type RegistryFactory interface {
	// RegistryFor returns a registry for the specified contract.
	RegistryFor(ContractAddress) (OnchainRegistry, error)
}

// AttestationToIdentity converts attestation data to an identity hash.
func AttestationToIdentity(attestationType cryptoutils.AttestationType, measurements map[int]string, governance WorkloadGovernance) ([32]byte, error) {
	switch attestationType.StringID {
	case cryptoutils.MAAAttestation.StringID:
		// For MAA the measurements are simply the PCRs encoded as map[uint32][]byte
		maaReport := &MAAReport{}
		for i, v := range measurements {
			if len(v) != 32 {
				return [32]byte{}, fmt.Errorf("invalid MAA measurement value %x for pcr %d", v, i)
			}
			copy(maaReport.PCRs[i][:], v)
		}
		identity, err := governance.MAAIdentity(*maaReport)
		return identity, err
	case cryptoutils.DCAPAttestation.StringID:
		// For DCAP the measurements are RTMRs and MRTD encoded as map[uint32][]byte
		dcapReport, err := DCAPReportFromMeasurement(measurements)
		if err != nil {
			return [32]byte{}, err
		}
		identity, err := governance.DCAPIdentity(*dcapReport, nil)
		return identity, err
	default:
		return [32]byte{}, fmt.Errorf("unsupported attestation type: %s", attestationType)
	}
}
