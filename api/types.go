package api

import (
	"fmt"

	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

const (
	// AttestationTypeHeader specifies the TEE attestation mechanism used.
	// Supported values: "azure-tdx", "qemu-tdx"
	AttestationTypeHeader = "X-Flashbots-Attestation-Type"

	// MeasurementHeader contains a JSON-encoded map of measurement values.
	// Format: {"0":"00", "1":"01", ...} mapping register index to hex value.
	MeasurementHeader = "X-Flashbots-Measurement"

	// Supported attestation types
	AzureTDX = "azure-tdx" // Azure confidential computing with TDX
	QemuTDX  = "qemu-tdx"  // Any DCAP-compatible TDX implementation
)

// RegistrationProvider defines the interface for TEE instance registration services.
// It abstracts the process of registering a TEE instance with the provisioning system.
type RegistrationProvider interface {
	// Register sends a CSR to the provisioning server and returns the registration response.
	// Parameters:
	//   - app: The contract address identifying the application
	//   - csr: Certificate Signing Request in PEM format
	// Returns:
	//   - Registration response containing cryptographic materials and configuration
	//   - Error if registration fails
	Register(app interfaces.ContractAddress, csr []byte) (*RegistrationResponse, error)
}

// RegistrationResponse contains the cryptographic materials and configuration
// returned by the provisioning server after successful registration.
type RegistrationResponse struct {
	// AppPrivkey is the private key for the application (for secrets decryption)
	AppPrivkey interfaces.AppPrivkey `json:"app_privkey"`

	// TLSCert is the signed TLS certificate for secure communication
	TLSCert interfaces.TLSCert `json:"tls_cert"`

	// Config is the resolved instance configuration with decrypted secrets
	Config interfaces.InstanceConfig `json:"config"`
}

type MetadataProvider interface {
	GetAppMetadata(contractAddr interfaces.ContractAddress) (*MetadataResponse, error)
}

// MetadataResponse contains the certificate authority and application domain names
// that can be used to connect to an application
type MetadataResponse struct {
	// CACert is the certificate authority that is expected for the application
	CACert interfaces.CACert `json:"ca_cert"`

	// AppPubkey is the applications public key used for encrypting secrets
	AppPubkey interfaces.AppPubkey `json:"app_pubkey"`

	// DomainNames is the domain names that should be resolved to get app instances
	DomainNames []interfaces.AppDomainName `json:"domain_names"`

	// Attestation is the quote for AppAddress||sha256(CACert||AppPubkey) (52 bytes)
	Attestation interfaces.Attestation `json:"attestaion"`
}

// AttestationToIdentity converts attestation data to an identity hash.
// It uses the appropriate computation method based on attestation type.
//
// Parameters:
//   - attestationType: The type of attestation (AzureTDX or QemuTDX)
//   - measurements: Map of measurement registers and their values
//   - registry: Registry client for computing identity hashes
//
// Returns:
//   - The computed identity hash
//   - Error if attestation type is unsupported or computation fails
func AttestationToIdentity(attestationType string, measurements map[string]string, registry interfaces.OnchainRegistry) ([32]byte, error) {
	switch attestationType {
	case AzureTDX:
		// For MAA the measurements are simply the PCRs encoded as map[uint32][]byte
		// Create an empty MAA report - this is a placeholder, you'll need to fill it properly
		maaReport := &interfaces.MAAReport{}
		return registry.ComputeMAAIdentity(maaReport)
	case QemuTDX:
		// For DCAP the measurements are RTMRs and MRTD encoded as map[uint32][]byte
		// Create an empty DCAP report - this is a placeholder, you'll need to fill it properly
		dcapReport := &interfaces.DCAPReport{}
		return registry.ComputeDCAPIdentity(dcapReport)
	default:
		return [32]byte{}, fmt.Errorf("unsupported attestation type: %s", attestationType)
	}
}
