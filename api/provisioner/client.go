package provisioner

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ruteri/tee-service-provisioning-backend/api"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/stretchr/testify/mock"
)

// ProvisioningClient implements RegistrationProvider and MetadataProvider with remote TEE registry provisioning server.
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

// Register sends a CSR to the provisioning server to register the TEE instance.
// The server verifies attestation evidence and returns cryptographic materials and configuration.
func (p *ProvisioningClient) Register(app interfaces.ContractAddress, csr []byte) (*api.RegistrationResponse, error) {
	url := fmt.Sprintf("%s/api/attested/register/%s", p.ServerAddr, app)
	registrationReq, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(csr))
	if err != nil {
		return nil, err
	}

	registrationReq.Header.Set("Content-Type", "application/octet-stream")
	if p.SetAttestationType != "" {
		registrationReq.Header.Set(api.AttestationTypeHeader, p.SetAttestationType)
	}
	if p.SetAttestationMeasurement != "" {
		registrationReq.Header.Set(api.MeasurementHeader, p.SetAttestationMeasurement)
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

	var parsedResponse api.RegistrationResponse
	err = json.NewDecoder(registrationResp.Body).Decode(&parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("could not parse registration response: %w", err)
	}

	return &parsedResponse, nil
}

func (p *ProvisioningClient) GetAppMetadata(app interfaces.ContractAddress) (*api.MetadataResponse, error) {
	url := fmt.Sprintf("%s/api/public/app_metadata/%s", p.ServerAddr, app)
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/octet-stream")
	if p.SetAttestationType != "" {
		req.Header.Set(api.AttestationTypeHeader, p.SetAttestationType)
	}
	if p.SetAttestationMeasurement != "" {
		req.Header.Set(api.MeasurementHeader, p.SetAttestationMeasurement)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not request metadata endpoint: %w", err)
	} else if resp.StatusCode != 200 {
		bodyBytes, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("metadata endpoint returned non-200 response: %d", resp.StatusCode)
		} else {
			return nil, fmt.Errorf("metadata endpoint returned error %d: %s", resp.StatusCode, string(bodyBytes))
		}
	}

	var parsedResponse api.MetadataResponse
	err = json.NewDecoder(resp.Body).Decode(&parsedResponse)
	if err != nil {
		return nil, fmt.Errorf("could not parse metadata response: %w", err)
	}

	return &parsedResponse, nil
}

// MockRegistrationProvider implements mock RegistrationProvider and MetadataProvider for testing.
type MockProvider struct {
	mock.Mock
}

// Register implements the RegistrationProvider interface for testing.
// The behavior is determined by how the mock is configured in tests.
func (m *MockProvider) Register(app interfaces.ContractAddress, csr []byte) (*api.RegistrationResponse, error) {
	args := m.Called(app, csr)
	return args.Get(0).(*api.RegistrationResponse), args.Error(1)
}

// Register implements the RegistrationProvider interface for testing.
// The behavior is determined by how the mock is configured in tests.
func (m *MockProvider) GetAppMetadata(app interfaces.ContractAddress) (*api.MetadataResponse, error) {
	args := m.Called(app)
	return args.Get(0).(*api.MetadataResponse), args.Error(1)
}
