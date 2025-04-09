package clients

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/ruteri/tee-service-provisioning-backend/api/handlers"
)

// AdminClient provides methods for interacting with the admin API.
// It handles authentication, request signing, and response parsing.
type AdminClient struct {
	baseURL    string
	adminID    string
	privateKey *ecdsa.PrivateKey
	httpClient *http.Client
}

// NewAdminClient creates a new admin client for interacting with the admin API.
//
// Parameters:
//   - baseURL: The base URL of the admin API (e.g., "http://localhost:8081")
//   - adminID: The administrator's ID
//   - privateKey: The administrator's ECDSA private key
//   - timeout: Request timeout duration (optional, default 30 seconds)
//
// Returns:
//   - Configured AdminClient instance
func NewAdminClient(baseURL, adminID string, privateKey *ecdsa.PrivateKey, timeout ...time.Duration) *AdminClient {
	clientTimeout := 30 * time.Second
	if len(timeout) > 0 {
		clientTimeout = timeout[0]
	}

	return &AdminClient{
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
//   - Status string (e.g., "initial", "recovering", "complete")
//   - Error if the request fails
func (c *AdminClient) GetStatus() (string, error) {
	url := fmt.Sprintf("%s/status", c.baseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("status request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("status request failed with code %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		State string `json:"state"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("failed to parse status response: %w", err)
	}

	return result.State, nil
}

// InitGenerate initiates the master key generation and share distribution.
//
// Parameters:
//   - threshold: Minimum number of shares required to reconstruct the master key
//   - totalShares: Total number of shares to generate
//
// Returns:
//   - Map of share indexes to base64-encoded shares
//   - Error if the request fails
func (c *AdminClient) InitGenerate(threshold, totalShares int) (map[int]string, error) {
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
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("init generate failed with code %d: %s", resp.StatusCode, string(body))
	}

	var result struct {
		Message string `json:"message"`
		Shares  []struct {
			Index int    `json:"index"`
			Share string `json:"share"`
		} `json:"shares"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to parse init generate response: %w", err)
	}

	// Convert to map for easier access
	shares := make(map[int]string)
	for _, share := range result.Shares {
		shares[share.Index] = share.Share
	}

	return shares, nil
}

// InitRecover initiates the recovery process.
//
// Parameters:
//   - threshold: Minimum number of shares required to reconstruct the master key
//
// Returns:
//   - Error if the request fails
func (c *AdminClient) InitRecover(threshold int) error {
	url := fmt.Sprintf("%s/init/recover", c.baseURL)

	reqBody := map[string]interface{}{
		"threshold": threshold,
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := CreateSignedAdminRequest("POST", url, reqJSON, c.adminID, c.privateKey)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("init recover request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("init recover failed with code %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// SubmitShare submits a share during the recovery process.
//
// Parameters:
//   - shareIndex: The index of the share
//   - shareBase64: The base64-encoded share
//   - signature: The share signature, or nil to generate a new signature
//
// Returns:
//   - Error if the request fails
func (c *AdminClient) SubmitShare(shareIndex int, shareBase64 string, signature []byte) error {
	url := fmt.Sprintf("%s/share", c.baseURL)

	// Decode the share to sign it if no signature provided
	share, err := base64.StdEncoding.DecodeString(shareBase64)
	if err != nil {
		return fmt.Errorf("invalid share encoding: %w", err)
	}

	// If no signature provided, create one
	if signature == nil {
		hash := sha256.Sum256(share)
		signature, err = ecdsa.SignASN1(rand.Reader, c.privateKey, hash[:])
		if err != nil {
			return fmt.Errorf("failed to sign share: %w", err)
		}
	}

	// Prepare the request
	reqBody := map[string]interface{}{
		"share_index": shareIndex,
		"share":       shareBase64,
		"signature":   base64.StdEncoding.EncodeToString(signature),
	}

	reqJSON, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("failed to marshal request body: %w", err)
	}

	req, err := CreateSignedAdminRequest("POST", url, reqJSON, c.adminID, c.privateKey)
	if err != nil {
		return err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("submit share request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("submit share failed with code %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

// FetchShare fetches a share during the generation process.
//
// Returns:
//   - share index
//   - encrypted share
//   - Error if the request fails
func (c *AdminClient) FetchShare() (handlers.AdminGetShareResponse, error) {
	url := fmt.Sprintf("%s/share", c.baseURL)

	req, err := CreateSignedAdminRequest("GET", url, nil, c.adminID, c.privateKey)
	if err != nil {
		return handlers.AdminGetShareResponse{}, err
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return handlers.AdminGetShareResponse{}, fmt.Errorf("submit share request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return handlers.AdminGetShareResponse{}, fmt.Errorf("submit share failed with code %d: %s", resp.StatusCode, string(body))
	}

	var parsedResp handlers.AdminGetShareResponse
	err = json.NewDecoder(resp.Body).Decode(&parsedResp)
	if err != nil {
		return handlers.AdminGetShareResponse{}, err
	}

	return parsedResp, err
}

// WaitForCompletion polls the KMS status until it reaches the "complete" state
// or the context is cancelled.
//
// Parameters:
//   - timeout: Maximum duration to wait
//   - interval: Polling interval
//
// Returns:
//   - Error if waiting times out or the context is cancelled
func (c *AdminClient) WaitForCompletion(timeout, interval time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		status, err := c.GetStatus()
		if err != nil {
			return fmt.Errorf("failed to get KMS status: %w", err)
		}

		if status == "complete" {
			return nil
		}

		time.Sleep(interval)
	}

	return fmt.Errorf("timeout waiting for KMS bootstrap completion")
}

// CreateSignedAdminRequest creates a new HTTP request with admin authentication headers.
//
// This function:
//   - Creates an HTTP request with the specified method, URL, and body
//   - Signs the request path and body using the admin's private key
//   - Sets the appropriate authentication headers
//
// The signature is created by:
//  1. Concatenating the request path with the request body (if any)
//  2. Computing the SHA-256 hash of this message
//  3. Signing the hash with the admin's private key using ECDSA
//  4. Base64-encoding the signature
//
// Parameters:
//   - method: HTTP method (e.g., "GET", "POST")
//   - reqUrl: The request URL
//   - body: The request body (can be nil)
//   - adminID: The administrator's ID
//   - privateKey: The administrator's ECDSA private key
//
// Returns:
//   - The signed HTTP request
//   - Error if request creation or signing fails
func CreateSignedAdminRequest(method, reqUrl string, body []byte, adminID string, privateKey *ecdsa.PrivateKey) (*http.Request, error) {
	var req *http.Request
	var err error

	// Create the request with the specified body
	if body != nil {
		req, err = http.NewRequest(method, reqUrl, bytes.NewReader(body))
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
	} else {
		req, err = http.NewRequest(method, reqUrl, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create request: %w", err)
		}
	}

	// Extract the path from the URL
	// We need just the path for signing, not the full URL
	parsedURL, err := url.Parse(reqUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %w", err)
	}

	// Set the admin ID header
	req.Header.Set("X-Admin-ID", adminID)

	// Prepare the message to sign (path + body)
	message := parsedURL.Path
	if body != nil {
		message += string(body)
	}

	// Compute the hash of the message
	hash := sha256.Sum256([]byte(message))

	// Sign the hash with the admin's private key
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign request: %w", err)
	}

	// Base64 encode the signature and set the header
	signatureStr := base64.StdEncoding.EncodeToString(signature)
	req.Header.Set("X-Admin-Signature", signatureStr)

	return req, nil
}

// SignAdminRequest adds authentication headers to an existing HTTP request.
//
// This is useful when you already have a request object and need to add
// admin authentication to it.
//
// Parameters:
//   - req: The HTTP request to sign
//   - adminID: The administrator's ID
//   - privateKey: The administrator's ECDSA private key
//
// Returns:
//   - Error if signing fails
func SignAdminRequest(req *http.Request, adminID string, privateKey *ecdsa.PrivateKey) error {
	if req == nil {
		return errors.New("request cannot be nil")
	}

	// Set the admin ID header
	req.Header.Set("X-Admin-ID", adminID)

	// Prepare the message to sign (path + body)
	message := req.URL.Path

	// If there's a body, read it
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}

		// Restore the body for the actual request
		req.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

		// Add body to the message
		message += string(bodyBytes)
	}

	// Compute the hash of the message
	hash := sha256.Sum256([]byte(message))

	// Sign the hash with the admin's private key
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	if err != nil {
		return fmt.Errorf("failed to sign request: %w", err)
	}

	// Base64 encode the signature and set the header
	signatureStr := base64.StdEncoding.EncodeToString(signature)
	req.Header.Set("X-Admin-Signature", signatureStr)

	return nil
}
