package kmshandler

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	simplekms "github.com/ruteri/tee-service-provisioning-backend/kms"
)

// SecretsProvider implements a client for retrieving cryptographic materials from the KMS.
// It handles communication with the KMS server including the attestation headers required
// for TEE identity verification.
type SecretsProvider struct {
	Client *http.Client

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

// Note: the onboard request must already be on the chain!
func (p *SecretsProvider) OnboardKMS(url string, onboardHash [32]byte, kms *simplekms.SimpleKMS, privkey interfaces.AppPrivkey) ([]byte, error) {
	var client *http.Client = p.Client
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Get(fmt.Sprintf("%s/api/attested/onboard/%s", url, hex.EncodeToString(onboardHash[:])))
	if err != nil {
		return nil, fmt.Errorf("could not send onboarding request: %w", err)
	}

	body, err := io.ReadAll(resp.Body)
	defer resp.Body.Close()

	if err != nil {
		return nil, fmt.Errorf("could not read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("onboarding server responded with %d: %s", resp.StatusCode, string(body))
	}

	return body, nil
}

// AppSecrets sends a request to the KMS server to obtain cryptographic materials for a TEE instance.
// It submits the CSR and attestation evidence, and returns the application private key and signed certificate.
func (p *SecretsProvider) AppSecrets(url string, contractAddr interfaces.ContractAddress, csr interfaces.TLSCSR) (*interfaces.AppSecrets, error) {
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

	var client *http.Client = p.Client
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
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

	var secretsResp interfaces.AppSecrets
	err = json.Unmarshal(body, &secretsResp)
	if err != nil {
		return nil, fmt.Errorf("could not parse kms response: %w", err)
	}

	return &secretsResp, nil
}
