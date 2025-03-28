package interfaces

import (
	"github.com/ruteri/poc-tee-registry/bindings/registry"
)

// Type definitions
type TLSCSR []byte
type TLSCert []byte
type CACert []byte
type AppPubkey []byte
type AppPrivkey []byte
type Attestation []byte
type ContractAddress [20]byte
type AppDomainName string

type DCAPReport = registry.RegistryDCAPReport
type DCAPEvent = registry.RegistryDCAPEvent
type MAAReport = registry.RegistryMAAReport
type AppPKI = registry.RegistryAppPKI

type StorageBackendLocation string
type InstanceConfig []byte

// KMS defines the interface for key management operations
type KMS interface {
	// GetPKI *derives* the CA certificate, app pubkey and attests them for a given contract
	// CA and pubkey should match the ones in the certificate (must match unless rotated)
	// Anyone should be able to fetch the PKI through an attested channel, therefore the attestation is only provided as trace/transparency
	GetPKI(contractAddr ContractAddress) (AppPKI, error)

	// GetAppPrivkey returns the application private key (interface assumes attestation and identity have been verified already)
	// The instance must be connected to through attested communication channels, whether directly or indirectly!
	GetAppPrivkey(contractAddr ContractAddress) (AppPrivkey, error)

	// SignCSR signs a certificate signing request (interface assumes attestation and identity have been verified already)
	// The instance must be connected to through attested communication channels, whether directly or indirectly!
	SignCSR(contractAddr ContractAddress, csr TLSCSR) (TLSCert, error)
}

// OnchainRegistry defines the interface for interacting with the registry smart contract
type OnchainRegistry interface {
    // PKI methods
    GetPKI() (*AppPKI, error) // Combines GetCA and GetAppPubkey into one method to match contract
    
    // Identity verification methods
    IsWhitelisted(identity [32]byte) (bool, error)
    ComputeDCAPIdentity(report *DCAPReport) ([32]byte, error)
    ComputeMAAIdentity(report *MAAReport) ([32]byte, error) // Added for MAA support
    
    // Config and secret management
    GetConfig(configHash [32]byte) ([]byte, error)
    GetSecret(secretHash [32]byte) ([]byte, error)
    IdentityConfigMap(identity [32]byte) ([32]byte, error)
    AddConfig(data []byte) ([32]byte, error)
    AddSecret(data []byte) ([32]byte, error)
    SetConfigForDCAP(report *DCAPReport, configHash [32]byte) error
    SetConfigForMAA(report *MAAReport, configHash [32]byte) error // Added for MAA support
    
    // Storage backend management
    AllStorageBackends() ([]string, error) // Returns string URIs, matches contract name
    AddStorageBackend(locationURI string) error // Takes string URI directly
    RemoveStorageBackend(locationURI string) error // Takes string URI directly
    
    // Domain name management
    AllInstanceDomainNames() ([]string, error) // Changed return type to match contract
    RegisterInstanceDomainName(domain string) error
    
    // Identity management
    RemoveWhitelistedIdentity(identity [32]byte) error
}

type RegistryFactory interface {
	RegistryFor(ContractAddress) (OnchainRegistry, error)
}
