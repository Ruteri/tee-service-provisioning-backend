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

// SecretsProvider implements a client for retrieving cryptographic materials from the
// onchain-governed KMS. It handles secure communication with the KMS server including
// the attestation headers required for TEE identity verification.
//
// The client supports:
// - Retrieving application secrets (private keys and certificates)
// - Onboarding new KMS instances through onchain governance
// - Debug options for attestation headers in development environments
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

// OnboardKMS retrieves KMS seed material for a new KMS instance through onchain governance.
// This method is used during KMS bootstrapping to securely distribute master key material
// to authorized instances.
//
// Parameters:
//   - url: The KMS server URL
//   - onboardHash: The hash identifying the onchain onboarding request
//   - kms: The local KMS instance that will receive the seed
//   - privkey: The application private key for authentication
//
// The onboard request must be previously registered and approved on the blockchain
// before calling this method.
//
// Returns:
//   - Encrypted seed material that can be used to initialize the KMS
//   - Error if onboarding fails
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
// It submits the CSR and attestation evidence, and returns the application private key,
// signed certificate, and other identity materials.
//
// Parameters:
//   - url: The KMS server URL
//   - contractAddr: The contract address identifying the application
//   - csr: Certificate Signing Request in PEM format
//
// The client automatically includes attestation evidence headers for production environments.
// For development and testing, attestation headers can be manually set using the
// DebugAttestationTypeHeader and DebugMeasurementsHeader fields.
//
// Returns:
//   - AppSecrets containing private key, TLS certificate, operator address, and attestation evidence
//   - Error if the request fails or authorization is denied
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
