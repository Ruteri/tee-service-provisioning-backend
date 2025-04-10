// Package interfaces defines the core interfaces and types for the TEE registry system.
// It provides the contract between different components without implementation details.
package interfaces

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ruteri/tee-service-provisioning-backend/bindings/registry"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
)

type TLSCSR = cryptoutils.TLSCSR
type TLSCert = cryptoutils.TLSCert
type CACert = cryptoutils.CACert
type AppPubkey = cryptoutils.AppPubkey
type AppPrivkey = cryptoutils.AppPrivkey

// Attestation represents a cryptographic attestation of identity.
type Attestation []byte

// NewAttestation creates a new attestation object with basic validation.
func NewAttestation(data []byte) (Attestation, error) {
	if len(data) == 0 {
		return Attestation{}, errors.New("attestation data cannot be empty")
	}
	return Attestation(data), nil
}

// ContractAddress represents an Ethereum contract address.
type ContractAddress [20]byte

// NewContractAddress creates a new contract address from a byte array or hex string.
func NewContractAddressFromBytes(addr []byte) (ContractAddress, error) {
	if len(addr) != 20 {
		return ContractAddress{}, errors.New("invalid address length: must be 20 bytes")
	}
	return ContractAddress(common.BytesToAddress(addr)), nil
}

func NewContractAddressFromHex(addr string) (ContractAddress, error) {
	// Remove 0x prefix if present
	clean := strings.TrimPrefix(addr, "0x")
	if len(clean) != 40 {
		return ContractAddress{}, errors.New("invalid address length: hex string must be 40 characters")
	}

	// Validate hex format
	if _, err := hex.DecodeString(clean); err != nil {
		return ContractAddress{}, fmt.Errorf("invalid hex format: %w", err)
	}

	return ContractAddress(common.HexToAddress(addr)), nil
}

// String returns the hex string representation of the contract address.
func (addr ContractAddress) String() string {
	return hex.EncodeToString(addr[:])
}

// Bytes returns the raw 20-byte address.
func (addr ContractAddress) Bytes() []byte {
	return addr[:]
}

// Equal compares two contract addresses for equality.
func (addr ContractAddress) Equal(other ContractAddress) bool {
	return addr == other
}

// AppCommonName represents a common name for an application certificates.
type AppCommonName string

// NewAppCommonName creates a new common name with validation.
func NewAppCommonName(addr ContractAddress) AppCommonName {
	return AppCommonName(addr.String() + ".app")
}

// String returns the domain name as a string.
func (name AppCommonName) String() string {
	return string(name)
}

// String returns the domain name as a string.
func (name AppCommonName) Address() (ContractAddress, error) {
	if len(name) != 44 {
		return ContractAddress{}, errors.New("invalid app cn")
	}
	return NewContractAddressFromHex(string(name[:40]))
}

// AppDomainName represents a domain name for an application instance.
type AppDomainName string

// NewAppDomainName creates a new domain name with validation.
func NewAppDomainName(domain string) (AppDomainName, error) {
	// Basic domain name validation (simplified version)
	domainRegex := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,}|$|:[0-9]{2,6}$)?`)
	if !domainRegex.MatchString(domain) {
		return AppDomainName(""), errors.New("invalid domain name format")
	}

	return AppDomainName(domain), nil
}

// String returns the domain name as a string.
func (name AppDomainName) String() string {
	return string(name)
}

// Validate checks if the domain name has a valid format.
func (name AppDomainName) Validate() error {
	_, err := NewAppDomainName(string(name))
	return err
}

// Validate checks if the domain name has a valid format.
func (name AppCommonName) Validate() error {
	_, err := name.Address()
	return err
}

// DCAPReport represents a Direct Capability Attestation Protocol report.
// It contains measurement registers that uniquely identify a TEE instance.
type DCAPReport struct {
	MrTd          [48]byte
	RTMRs         [4][48]byte
	MrOwner       [48]byte
	MrConfigId    [48]byte
	MrConfigOwner [48]byte
}

func DCAPReportFromMeasurement(measurements map[int]string) (*DCAPReport, error) {
	dcapReport := &DCAPReport{}

	mrtdHex, ok := measurements[0]
	if !ok {
		return nil, fmt.Errorf("mrtd missing")
	}
	mrtd, err := hex.DecodeString(mrtdHex)
	if err != nil {
		return nil, fmt.Errorf("could not decode mrtd measurement value %x: %w", mrtdHex, err)
	}
	if len(mrtd) != 48 {
		return nil, fmt.Errorf("invalid mrtd measurement value %x", mrtd)
	}

	copy(dcapReport.MrTd[:], mrtd)

	for rtmr := range 3 {
		rtmrHex, ok := measurements[1+rtmr]
		if !ok {
			return nil, fmt.Errorf("rtmr %d missing", rtmr)
		}
		rtmrBytes, err := hex.DecodeString(rtmrHex)
		if err != nil {
			return nil, fmt.Errorf("could not decode rtmr %d measurement value %x: %w", rtmr, rtmrHex, err)
		}
		if len(rtmrBytes) != 48 {
			return nil, fmt.Errorf("invalid rtmr %d value %x", rtmr, rtmrBytes)
		}
		copy(dcapReport.RTMRs[rtmr][:], rtmrBytes)
	}
	return dcapReport, nil
}

// DCAPEvent represents an event in the TEE runtime event log.
type DCAPEvent = registry.DCAPEvent

// MAAReport represents a Microsoft Azure Attestation report.
// It contains PCR values that uniquely identify a TEE instance.
type MAAReport = registry.MAAReport

// AppPKI represents a PKI bundle containing CA certificate, public key, and attestation.
type AppPKI = registry.AppPKI

// InstanceConfig represents the configuration data for a TEE instance.
type InstanceConfig json.RawMessage

// NewInstanceConfig creates a new instance configuration with basic validation.
func NewInstanceConfig(data []byte) (InstanceConfig, error) {
	if len(data) == 0 {
		return InstanceConfig{}, errors.New("configuration data cannot be empty")
	}

	// Basic format validation - check if it's valid JSON
	if !json.Valid(data) {
		// If not JSON, could be YAML or other format
		// For now, we'll just accept it, but this could be expanded
		// to add more specific validation for other formats
	}

	return InstanceConfig(data), nil
}

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
}

// OnchainRegistry defines the interface for interacting with the registry smart contract.
// It provides methods for identity verification, artifact management, and TEE orchestration.
type OnchainRegistry interface {
	// GetPKI retrieves the PKI information (CA, public key, and attestation) from the registry.
	GetPKI() (*AppPKI, error)

	// ComputeDCAPIdentity calculates the identity hash for a DCAP report.
	// This uses the same algorithm as the on-chain registry contract.
	ComputeDCAPIdentity(report *DCAPReport) ([32]byte, error)

	// ComputeMAAIdentity calculates the identity hash for an MAA report.
	// This uses the same algorithm as the on-chain registry contract.
	ComputeMAAIdentity(report *MAAReport) ([32]byte, error)

	// GetArtifact retrieves an artifact from the registry by its hash.
	// Returns the artifact data or an error if not found.
	GetArtifact(artifactHash [32]byte) ([]byte, error)

	// IdentityConfigMap gets the artifact hash assigned to an identity.
	// Returns the artifact hash or an error if no mapping exists.
	IdentityConfigMap(identity [32]byte) ([32]byte, error)

	// AddArtifact adds a new artifact to the registry.
	// This can be configuration data, encrypted secrets, or any other content.
	// Returns the content hash, transaction, and any error that occurred.
	AddArtifact(data []byte) ([32]byte, *types.Transaction, error)

	// SetConfigForDCAP associates an artifact with a DCAP-attested identity.
	// Returns the transaction and any error that occurred.
	SetConfigForDCAP(report *DCAPReport, artifactHash [32]byte) (*types.Transaction, error)

	// SetConfigForMAA associates an artifact with an MAA-attested identity.
	// Returns the transaction and any error that occurred.
	SetConfigForMAA(report *MAAReport, artifactHash [32]byte) (*types.Transaction, error)

	// AllStorageBackends returns all registered storage backend URIs.
	// These backends are used for retrieving artifacts.
	AllStorageBackends() ([]string, error)

	// AddStorageBackend registers a new storage backend URI.
	// Returns the transaction and any error that occurred.
	AddStorageBackend(locationURI string) (*types.Transaction, error)

	// RemoveStorageBackend unregisters a storage backend URI.
	// Returns the transaction and any error that occurred.
	RemoveStorageBackend(locationURI string) (*types.Transaction, error)

	// AllInstanceDomainNames returns all registered instance domain names.
	// These domains are used for accessing TEE instances.
	AllInstanceDomainNames() ([]string, error)

	// RegisterInstanceDomainName adds a new domain name for instances.
	// Returns the transaction and any error that occurred.
	RegisterInstanceDomainName(domain string) (*types.Transaction, error)
}

// RegistryFactory creates OnchainRegistry instances for different contract addresses.
// This allows the system to interact with multiple registry contracts.
type RegistryFactory interface {
	// RegistryFor returns an OnchainRegistry instance for the specified contract address.
	// If the registry doesn't exist, it will be created.
	RegistryFor(ContractAddress) (OnchainRegistry, error)
}
