package instanceutils

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ruteri/tee-service-provisioning-backend/httpserver"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/stretchr/testify/mock"
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

// ProvisioningClient implements RegistrationProvider for HTTP-based communication
// with the TEE registry provisioning server.
type ProvisioningClient struct {
	// ServerAddr is the base URL of the provisioning server
	ServerAddr string

	// SetAttestationType is used to set the attestation type header
	// This is primarily for testing/development; in production it's derived from the TEE
	SetAttestationType string

	// SetAttestationMeasurement is used to set the attestation measurement header
	// This is primarily for testing/development; in production it's derived from the TEE
	SetAttestationMeasurement string
}

// RegistrationResponse contains the cryptographic materials and configuration
// returned by the provisioning server after successful registration.
type RegistrationResponse struct {
	// AppPrivkey is the private key for the application (for secrets decryption)
	AppPrivkey string `json:"app_privkey"`

	// TLSCert is the signed TLS certificate for secure communication
	TLSCert string `json:"tls_cert"`

	// Config is the resolved instance configuration with decrypted secrets
	Config string `json:"config"`
}

// Register sends a CSR to the provisioning server to register the TEE instance.
// The server verifies attestation evidence and returns cryptographic materials and configuration.
func (p *ProvisioningClient) Register(app interfaces.ContractAddress, csr []byte) (*RegistrationResponse, error) {
	url := fmt.Sprintf("%s/api/attested/register/%x", p.ServerAddr, app)
	registrationReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(csr))
	if err != nil {
		return nil, err
	}

	registrationReq.Header.Set("Content-Type", "application/octet-stream")
	if p.SetAttestationType != "" {
		registrationReq.Header.Set(httpserver.AttestationTypeHeader, p.SetAttestationType)
	}
	if p.SetAttestationMeasurement != "" {
		registrationReq.Header.Set(httpserver.MeasurementHeader, p.SetAttestationMeasurement)
	}

	registrationResp, err := http.DefaultClient.Do(registrationReq)
	if err != nil {
		return nil, fmt.Errorf("could not request registration endpoint: %w", err)
	} else if registrationResp.StatusCode != 200 {
		bodyBytes, err := io.ReadAll(registrationResp.Body)
		if err != nil {
			return nil, fmt.Errorf("registration endpoint returned non-200 response: %d", registrationResp.StatusCode)
		} else {
			return nil, fmt.Errorf("registration endpoint returned error %d: %s", registrationResp.StatusCode, string(bodyBytes))
		}
	}

	var parsedResponse RegistrationResponse
	err = json.NewDecoder(registrationResp.Body).Decode(&parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("could not parse registration response: %w", err)
	}

	return &parsedResponse, nil
}

// LocalKMSRegistrationProvider implements RegistrationProvider using a local KMS.
// This is useful for testing and development environments without a remote provisioning server.
type LocalKMSRegistrationProvider struct {
	// KMS is the key management system used for certificate signing and key generation
	KMS interfaces.KMS
}

// Register uses a local KMS to sign the CSR and provide application materials.
// This implementation doesn't provide configuration, only cryptographic materials.
func (p *LocalKMSRegistrationProvider) Register(app interfaces.ContractAddress, csr []byte) (*RegistrationResponse, error) {
	cert, err := p.KMS.SignCSR(app, csr)
	if err != nil {
		return nil, err
	}

	appPrivkey, err := p.KMS.GetAppPrivkey(app)
	if err != nil {
		return nil, err
	}

	return &RegistrationResponse{
		AppPrivkey: string(appPrivkey),
		TLSCert:    string(cert),
		Config:     "",
	}, nil
}

// MockRegistrationProvider implements a mock RegistrationProvider for testing.
type MockRegistrationProvider struct {
	mock.Mock
}

// Register implements the RegistrationProvider interface for testing.
// The behavior is determined by how the mock is configured in tests.
func (m *MockRegistrationProvider) Register(app interfaces.ContractAddress, csr []byte) (*RegistrationResponse, error) {
	args := m.Called(app, csr)
	return args.Get(0).(*RegistrationResponse), args.Error(1)
}
