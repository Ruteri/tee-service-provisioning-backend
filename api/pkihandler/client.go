package pkihandler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// PKI retrieves attested PKI information for a specified contract address from a remote PKI service.
// This function serves as a client for the onchain-governed PKI service, making HTTP requests to obtain
// certificate authorities and public keys that can be used for secure communication with TEE instances.
//
// The PKI information is backed by blockchain-based governance that ensures only authorized
// certificate authorities are used for TEE instance verification.
//
// Parameters:
//   - url: Base URL of the PKI service (e.g., "https://registry.example.com")
//   - contractAddr: Contract address identifying the application on the blockchain
//
// Returns:
//   - AppPKI containing the CA certificate, application public key, and attestation
//   - Error if the request fails or response parsing fails
//
// The returned attestation should be verified against the onchain registry by the caller
// to ensure the authenticity of the PKI information before using it for certificate validation.
func PKI(url string, contractAddr interfaces.ContractAddress) (*interfaces.AppPKI, error) {
	req, err := http.NewRequest(
		http.MethodGet,
		fmt.Sprintf("%s/api/public/pki/%s", url, contractAddr.String()),
		nil,
	)
	if err != nil {
		return nil, fmt.Errorf("could not initialize request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("could not request pki: %w", err)
	}

	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("could not read pki response: %w", err)
	}

	var pkiResp PKIResponse
	err = json.Unmarshal(body, &pkiResp)
	if err != nil {
		return nil, fmt.Errorf("could not parse pki response: %w", err)
	}

	// TODO: verify the attestation against onchain kms governance

	return &interfaces.AppPKI{
		Pubkey:      pkiResp.AppPubkey,
		Ca:          pkiResp.CACert,
		Attestation: pkiResp.Attestation,
	}, nil
}
