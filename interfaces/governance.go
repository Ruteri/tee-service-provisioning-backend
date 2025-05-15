// Package interfaces defines the core interfaces and types for the TEE registry system.
// It provides the contract between different components without implementation details.
package interfaces

import (
	"crypto/sha256"
	"fmt"

	"github.com/ethereum/go-ethereum/core/types"
	kmsbindings "github.com/ruteri/tee-service-provisioning-backend/bindings/kms"
	"github.com/ruteri/tee-service-provisioning-backend/bindings/registry"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
)

// DCAPEvent represents an event in the TEE runtime event log.
type DCAPEvent = registry.DCAPEvent

// MAAReport represents a Microsoft Azure Attestation report.
// It contains PCR values that uniquely identify a TEE instance.
type MAAReport = registry.MAAReport

// AppPKI represents a PKI bundle containing CA certificate, public key, and attestation.
type AppPKI registry.AppPKI

func (p *AppPKI) ReportData(contractAddr ContractAddress) [64]byte {
	var expectedReportData [64]byte
	copy(expectedReportData[:20], contractAddr[:])
	certsHash := sha256.Sum256(append(p.Ca, p.Pubkey...))
	copy(expectedReportData[20:], certsHash[:])
	return expectedReportData
}

// InstanceConfig represents the configuration data for a TEE instance.
type InstanceConfig []byte

// KMS defines the interface for key management operations related to TEE applications.
// It handles cryptographic materials for secure communication with TEE instances.
type KMS interface {
	// GetPKI retrieves the CA certificate, app public key, and attestation for a contract.
	// The CA and public key should match those in the certificate (unless rotated).
	// The attestation is provided for transparency and verification.
	GetPKI(contractAddr ContractAddress) (AppPKI, error)

	// GetAppPrivkey returns the application private key for a contract address.
	// This method assumes attestation and identity have been verified already.
	// The instance must be connected through attested communication channels.
	GetAppPrivkey(contractAddr ContractAddress) (AppPrivkey, error)

	// SignCSR signs a certificate signing request for a verified TEE instance.
	// This method assumes attestation and identity have been verified already.
	// The instance must be connected through attested communication channels.
	SignCSR(contractAddr ContractAddress, csr TLSCSR) (TLSCert, error)

	AppSecrets(ContractAddress, TLSCSR) (*AppSecrets, error)
}

type WorkloadGovernance interface {
	// DCAPIdentity calculates the identity hash for a DCAP report.
	// This uses the same algorithm as the on-chain registry contract.
	DCAPIdentity(report DCAPReport, events []DCAPEvent) ([32]byte, error)

	// MAAIdentity calculates the identity hash for an MAA report.
	// This uses the same algorithm as the on-chain registry contract.
	MAAIdentity(report MAAReport) ([32]byte, error)

	// IdentityAllowed returns whether identity is allowed by governance
	IdentityAllowed(identity [32]byte, operator [20]byte) (bool, error)
}

type OnboardRequest = kmsbindings.OnboardRequest

type KMSGovernance interface {
	WorkloadGovernance
	OnchainDiscovery

	WhitelistDCAP(DCAPReport) (*types.Transaction, error)
	WhitelistMAA(MAAReport) (*types.Transaction, error)
	WhitelistIdentity([32]byte) (*types.Transaction, error)
	RemoveWhitelistedIdentity([32]byte) (*types.Transaction, error)

	RequestOnboard(OnboardRequest) (*types.Transaction, error)
	FetchOnboardRequest([32]byte) (OnboardRequest, error)
}

type PorvisioningGovernance interface {
	// ConfigForIdentity gets the artifact hash assigned to an identity.
	// Returns the artifact hash or an error if no mapping exists.
	ConfigForIdentity(identity [32]byte, operator [20]byte) ([32]byte, error)

	// StorageBackends returns all registered storage backend URIs.
	// These backends are used for retrieving artifacts.
	StorageBackends() ([]string, error)
}

type OnchainDiscovery interface {
	// GetPKI retrieves the PKI information (CA, public key, and attestation) from the registry.
	PKI() (AppPKI, error)

	// AllInstanceDomainNames returns all registered instance domain names.
	// These domains are used for accessing TEE instances.
	InstanceDomainNames() ([]string, error)
}

// OnchainRegistry defines the interface for interacting with the registry smart contract.
// It provides methods for identity verification, artifact management, and TEE orchestration.
type OnchainRegistry interface {
	WorkloadGovernance
	OnchainDiscovery
	PorvisioningGovernance

	// SetConfigForIdentity associates an artifact with an identity.
	// Returns the transaction and any error that occurred.
	SetConfigForIdentity(identity [32]byte, artifactHash [32]byte) (*types.Transaction, error)

	// GetArtifact retrieves an artifact from the registry by its hash.
	// Returns the artifact data or an error if not found.
	GetArtifact(artifactHash [32]byte) ([]byte, error)

	// RegisterInstanceDomainName adds a new domain name for instances.
	// Returns the transaction and any error that occurred.
	RegisterInstanceDomainName(domain string) (*types.Transaction, error)

	// AddArtifact adds a new artifact to the registry.
	// This can be configuration data, encrypted secrets, or any other content.
	// Returns the content hash, transaction, and any error that occurred.
	AddArtifact(data []byte) ([32]byte, *types.Transaction, error)

	// AddStorageBackend registers a new storage backend URI.
	// Returns the transaction and any error that occurred.
	AddStorageBackend(locationURI string) (*types.Transaction, error)

	// RemoveStorageBackend unregisters a storage backend URI.
	// Returns the transaction and any error that occurred.
	RemoveStorageBackend(locationURI string) (*types.Transaction, error)
}

// RegistryFactory creates OnchainRegistry instances for different contract addresses.
// This allows the system to interact with multiple registry contracts.
type RegistryFactory interface {
	// RegistryFor returns an OnchainRegistry instance for the specified contract address.
	// If the registry doesn't exist, it will be created.
	RegistryFor(ContractAddress) (OnchainRegistry, error)
}

// AttestationToIdentity converts attestation data to an identity hash.
// It uses the appropriate computation method based on attestation type.
//
// Parameters:
//   - attestationType: The type of attestation (MAA or DCAP)
//   - measurements: Map of measurement registers and their values
//   - governance: Governance client for computing identity hashes
//
// Returns:
//   - The computed identity hash
//   - Error if attestation type is unsupported or computation fails
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
