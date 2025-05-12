package kmshandler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ruteri/tee-service-provisioning-backend/api"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// SecretsProvider implements a client for retrieving cryptographic materials from the KMS.
// It handles communication with the KMS server including the attestation headers required
// for TEE identity verification.
type SecretsProvider struct {
	Client                     *http.Client

	// DebugAttestationTypeHeader allows manually setting the attestation type header.
	// This is primarily for testing and development, and should not be used in production.
	DebugAttestationTypeHeader string
	
	// DebugMeasurementsHeader allows manually setting the measurements header.
	// This is primarily for testing and development, and should not be used in production.
	DebugMeasurementsHeader string
}

// DefaultSecretsProvider is a pre-configured SecretsProvider instance with default HTTP client.
// It can be used directly for most applications without additional configuration.
var DefaultSecretsProvider = &SecretsProvider{
	Client: http.DefaultClient,
}

// AppSecrets sends a request to the KMS server to obtain cryptographic materials for a TEE instance.
// It submits the CSR and attestation evidence, and returns the application private key and signed certificate.
func (p *SecretsProvider) AppSecrets(url string, contractAddr interfaces.ContractAddress, csr interfaces.TLSCSR) (*api.SecretsResponse, error) {
	req, err := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("%s/api/attested/secrets/%s", url, contractAddr.String()),
		bytes.NewReader(csr),
	)
	if err != nil {
		return nil, fmt.Errorf("could not initialize request: %w", err)
	}

	if p.DebugAttestationTypeHeader != "" {
		req.Header.Set(cryptoutils.AttestationTypeHeader, p.DebugAttestationTypeHeader)
	}

	if p.DebugMeasurementsHeader != "" {
		req.Header.Set(cryptoutils.MeasurementHeader, p.DebugMeasurementsHeader)
	}

	if p.Client == nil {
		p.Client = http.DefaultClient
	}

	resp, err := p.Client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not request kms: %w", err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read kms response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("kms returned %d: %s", resp.StatusCode, string(body))
	}

	var secretsResp api.SecretsResponse
	err = json.Unmarshal(body, &secretsResp)
	if err != nil {
		return nil, fmt.Errorf("could not parse kms response: %w", err)
	}

	return &secretsResp, nil
}
