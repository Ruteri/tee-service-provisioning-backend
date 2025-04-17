package api

import (
	"crypto/sha256"
	"encoding/asn1"
	"fmt"

	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
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

type AdminGetShareResponse struct {
	ShareIndex     int    `json:"share_index"`
	EncryptedShare string `json:"encrypted_share"` // base64 encoded
}

type RegistryProvider interface {
	MetadataProvider
	RegistrationProvider
}

var OIDOperatorSignature asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66704, 98670, 17}

// AttestationToIdentity converts attestation data to an identity hash.
// It uses the appropriate computation method based on attestation type.
//
// Parameters:
//   - attestationType: The type of attestation (MAA or DCAP)
//   - measurements: Map of measurement registers and their values
//   - registry: Registry client for computing identity hashes
//
// Returns:
//   - The computed identity hash
//   - Error if attestation type is unsupported or computation fails
func AttestationToIdentity(attestationType cryptoutils.AttestationType, measurements map[int]string, registry interfaces.OnchainRegistry) ([32]byte, error) {
	switch attestationType.StringID {
	case cryptoutils.MAAAttestation.StringID:
		// For MAA the measurements are simply the PCRs encoded as map[uint32][]byte
		maaReport := &interfaces.MAAReport{}
		for i, v := range measurements {
			if len(v) != 32 {
				return [32]byte{}, fmt.Errorf("invalid MAA measurement value %x for pcr %d", v, i)
			}
			copy(maaReport.PCRs[i][:], v)
		}
		identity, err := registry.ComputeMAAIdentity(maaReport)
		return identity, err
	case cryptoutils.DCAPAttestation.StringID:
		// For DCAP the measurements are RTMRs and MRTD encoded as map[uint32][]byte
		dcapReport, err := interfaces.DCAPReportFromMeasurement(measurements)
		if err != nil {
			return [32]byte{}, err
		}
		identity, err := registry.ComputeDCAPIdentity(dcapReport)
		return identity, err
	default:
		return [32]byte{}, fmt.Errorf("unsupported attestation type: %s", attestationType)
	}
}

func ReportData(contractAddr interfaces.ContractAddress, CACert interfaces.CACert, AppPubkey interfaces.AppPubkey) [64]byte {
	var expectedReportData [64]byte
	copy(expectedReportData[:20], contractAddr[:])
	certsHash := sha256.Sum256(append(CACert, AppPubkey...))
	copy(expectedReportData[20:], certsHash[:])
	return expectedReportData
}
