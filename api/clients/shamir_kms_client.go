package clients

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
)

// AdminShareClient provides methods for securely retrieving and submitting shares.
// It handles authentication, encryption/decryption, and signature operations.
type AdminShareClient struct {
	baseURL    string
	adminID    string
	privateKey *ecdsa.PrivateKey
	httpClient *http.Client
}

// NewAdminShareClient creates a new client for secure share operations.
//
// Parameters:
//   - baseURL: The base URL of the admin API (e.g., "http://localhost:8080/admin")
//   - adminID: The administrator's ID
//   - privateKey: The administrator's ECDSA private key
//   - timeout: Request timeout duration (optional, default 30 seconds)
//
// Returns:
//   - Configured AdminShareClient instance
func NewAdminShareClient(baseURL, adminID string, privateKey *ecdsa.PrivateKey, timeout ...time.Duration) *AdminShareClient {
	clientTimeout := 30 * time.Second
	if len(timeout) > 0 {
		clientTimeout = timeout[0]
	}

	// Ensure base URL doesn't end with slash
	baseURL = strings.TrimSuffix(baseURL, "/")

	return &AdminShareClient{
		baseURL:    baseURL,
		adminID:    adminID,
		privateKey: privateKey,
		httpClient: &http.Client{
			Timeout: clientTimeout,
		},
	}
}

// GetStatus queries the current status of the KMS bootstrap process.
//
// Returns:
//   - Status object containing state, threshold, etc.
//   - Error if the request fails
func (c *AdminShareClient) GetStatus() (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/status", c.baseURL)

	req, err := CreateSignedAdminRequest("GET", url, nil, c.adminID, c.privateKey)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("status request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status request failed with code %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse status response: %w", err)
	}

	return result, nil
}

// InitGenerate initiates the master key generation and share distribution.
//
// Parameters:
//   - threshold: Minimum number of shares required to reconstruct the master key
//   - totalShares: Total number of shares to generate
//
// Returns:
//   - Response containing share assignments and instructions
//   - Error if the request fails
func (c *AdminShareClient) InitGenerate(threshold, totalShares int) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/init/generate", c.baseURL)

	reqBody := map[string]interface{}{
		"threshold":    threshold,
		"total_shares": totalShares,
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := CreateSignedAdminRequest("POST", url, reqJSON, c.adminID, c.privateKey)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("init generate request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("init generate failed with code %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// InitRecover initiates the recovery process.
//
// Parameters:
//   - threshold: Minimum number of shares required to reconstruct the master key
//
// Returns:
//   - Response with recovery instructions
//   - Error if the request fails
func (c *AdminShareClient) InitRecover(threshold int) (map[string]interface{}, error) {
	url := fmt.Sprintf("%s/init/recover", c.baseURL)

	reqBody := map[string]interface{}{
		"threshold": threshold,
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := CreateSignedAdminRequest("POST", url, reqJSON, c.adminID, c.privateKey)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("init recover request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("init recover failed with code %d", resp.StatusCode)
	}

	var result map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	return result, nil
}

// GetShare retrieves the admin's encrypted share.
// Only the designated admin can retrieve their share.
//
// Returns:
//   - Share index
//   - Decrypted share bytes (ready for use in recovery)
//   - Error if retrieval or decryption fails
func (c *AdminShareClient) GetShare() (int, []byte, error) {
	url := fmt.Sprintf("%s/share", c.baseURL)

	req, err := CreateSignedAdminRequest("GET", url, nil, c.adminID, c.privateKey)
	if err != nil {
		return 0, nil, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("get share request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, nil, fmt.Errorf("get share failed with code %d", resp.StatusCode)
	}

	var result struct {
		ShareIndex     int    `json:"share_index"`
		EncryptedShare string `json:"encrypted_share"`
		Message        string `json:"message"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return 0, nil, fmt.Errorf("failed to parse response: %w", err)
	}

	// Decode the encrypted share
	encryptedShareBytes, err := base64.StdEncoding.DecodeString(result.EncryptedShare)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to decode encrypted share: %w", err)
	}

	// Decrypt the share with the admin's private key
	privateKeyPEM, err := privateKeyToPEM(c.privateKey)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to convert private key to PEM: %w", err)
	}

	decryptedShare, err := cryptoutils.DecryptWithPrivateKey(privateKeyPEM, encryptedShareBytes)
	if err != nil {
		return 0, nil, fmt.Errorf("failed to decrypt share: %w", err)
	}

	return result.ShareIndex, decryptedShare, nil
}

// SubmitShare submits the admin's share during recovery.
//
// Parameters:
//   - shareIndex: The index of the share
//   - shareData: The raw share data (will be signed automatically)
//
// Returns:
//   - Response message
//   - Error if submission fails
func (c *AdminShareClient) SubmitShare(shareIndex int, shareData []byte) (string, error) {
	url := fmt.Sprintf("%s/share", c.baseURL)

	// Sign the share
	hash := sha256.Sum256(shareData)
	signature, err := ecdsa.SignASN1(rand.Reader, c.privateKey, hash[:])
	if err != nil {
		return "", fmt.Errorf("failed to sign share: %w", err)
	}

	// Prepare request body
	reqBody := map[string]interface{}{
		"share_index": shareIndex,
		"share":       base64.StdEncoding.EncodeToString(shareData),
		"signature":   base64.StdEncoding.EncodeToString(signature),
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := CreateSignedAdminRequest("POST", url, reqJSON, c.adminID, c.privateKey)
	if err != nil {
		return "", err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("submit share request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("submit share failed with code %d", resp.StatusCode)
	}

	var result struct {
		Message string `json:"message"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	return result.Message, nil
}

// privateKeyToPEM converts an ECDSA private key to PEM format.
func privateKeyToPEM(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	return privateKeyPEM, nil
}
