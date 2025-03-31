package httpserver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ruteri/poc-tee-registry/cryptoutils"
	"github.com/ruteri/poc-tee-registry/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test utilities

// generateAdminKeyPairs generates n admin key pairs for testing
func generateAdminKeyPairs(t *testing.T, n int) (map[string]*ecdsa.PrivateKey, map[string][]byte) {
	adminPrivKeys := make(map[string]*ecdsa.PrivateKey, n)
	adminPubKeyPEMs := make(map[string][]byte, n)

	for i := 0; i < n; i++ {
		adminID := fmt.Sprintf("admin%d", i+1)

		// Generate key pair
		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err, "Failed to generate ECDSA key")
		adminPrivKeys[adminID] = privateKey

		// Export public key
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
		require.NoError(t, err, "Failed to marshal public key")

		pubKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		})
		adminPubKeyPEMs[adminID] = pubKeyPEM
	}

	return adminPrivKeys, adminPubKeyPEMs
}

// createTestServer creates a test server with the admin handler
func createTestServer(t *testing.T, handler *AdminHandler) *httptest.Server {
	r := chi.NewRouter()
	r.Mount("/admin", handler.AdminRouter())
	return httptest.NewServer(r)
}

// createSignedRequest creates a signed request for testing
func createSignedRequest(t *testing.T, method, url string, body []byte, adminID string, privateKey *ecdsa.PrivateKey) *http.Request {
	req, err := CreateSignedAdminRequest(method, url, body, adminID, privateKey)
	require.NoError(t, err, "Failed to create signed request")
	return req
}

// Basic tests

func TestNewAdminHandler(t *testing.T) {
	_, adminPubKeys := generateAdminKeyPairs(t, 3)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)
	assert.NotNil(t, handler, "Handler should not be nil")
	assert.Equal(t, StateInitial, handler.state, "Initial state should be StateInitial")
	assert.Len(t, handler.adminPubKeys, 3, "Should have 3 admin keys")
	assert.NotNil(t, handler.completeChan, "Complete channel should be initialized")
}

func TestAdminHandler_GetKMS_WhenNotComplete(t *testing.T) {
	_, adminPubKeys := generateAdminKeyPairs(t, 3)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)
	kmsImpl := handler.GetKMS()
	assert.Nil(t, kmsImpl, "KMS should be nil when not complete")
}

func TestAdminHandler_WaitForBootstrap_WithTimeout(t *testing.T) {
	_, adminPubKeys := generateAdminKeyPairs(t, 3)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Create a context with short timeout
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	// Wait should time out
	err := handler.WaitForBootstrap(ctx)
	assert.Error(t, err, "WaitForBootstrap should time out")
	assert.Contains(t, err.Error(), "context deadline exceeded")
}

func TestAdminHandler_WaitForBootstrap_Completion(t *testing.T) {
	_, adminPubKeys := generateAdminKeyPairs(t, 3)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Simulate completion in a separate goroutine
	go func() {
		time.Sleep(100 * time.Millisecond)
		close(handler.completeChan)
	}()

	// Create a context with longer timeout
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// Wait should succeed
	err := handler.WaitForBootstrap(ctx)
	assert.NoError(t, err, "WaitForBootstrap should succeed")
}

// Authentication tests

func TestAdminHandler_verifyAdmin_Success(t *testing.T) {
	adminPrivKeys, adminPubKeys := generateAdminKeyPairs(t, 1)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Create a test request with a path and body
	body := []byte(`{"test":"value"}`)
	req, err := http.NewRequest("POST", "/admin/test", bytes.NewReader(body))
	require.NoError(t, err)

	// Add admin ID and prepare for signing
	adminID := "admin1"
	privateKey := adminPrivKeys[adminID]

	// Create the message to sign
	message := "/admin/test" + string(body)
	hash := sha256.Sum256([]byte(message))

	// Sign the hash with the admin's private key
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
	require.NoError(t, err)

	// Set the headers
	req.Header.Set("X-Admin-ID", adminID)
	req.Header.Set("X-Admin-Signature", base64.StdEncoding.EncodeToString(signature))

	// Verify the admin
	verifiedAdminID, ok := handler.verifyAdmin(req)
	assert.True(t, ok, "Admin verification should succeed")
	assert.Equal(t, adminID, verifiedAdminID, "Admin ID should match")
}

func TestAdminHandler_verifyAdmin_MissingHeaders(t *testing.T) {
	_, adminPubKeys := generateAdminKeyPairs(t, 1)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Create a test request without headers
	req, err := http.NewRequest("GET", "/admin/test", nil)
	require.NoError(t, err)

	// Verify the admin - should fail due to missing headers
	_, ok := handler.verifyAdmin(req)
	assert.False(t, ok, "Admin verification should fail due to missing headers")
}

func TestAdminHandler_verifyAdmin_UnknownAdmin(t *testing.T) {
	adminPrivKeys, adminPubKeys := generateAdminKeyPairs(t, 1)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Create a test request
	req, err := http.NewRequest("GET", "/admin/test", nil)
	require.NoError(t, err)

	// Set unknown admin ID
	req.Header.Set("X-Admin-ID", "unknown-admin")

	// Create signature with a valid key (doesn't matter for this test)
	message := "/admin/test"
	hash := sha256.Sum256([]byte(message))
	signature, err := ecdsa.SignASN1(rand.Reader, adminPrivKeys["admin1"], hash[:])
	require.NoError(t, err)

	req.Header.Set("X-Admin-Signature", base64.StdEncoding.EncodeToString(signature))

	// Verify the admin - should fail due to unknown admin
	_, ok := handler.verifyAdmin(req)
	assert.False(t, ok, "Admin verification should fail due to unknown admin")
}

func TestAdminHandler_verifyAdmin_InvalidSignature(t *testing.T) {
	adminPrivKeys, adminPubKeys := generateAdminKeyPairs(t, 1)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Create a test request
	req, err := http.NewRequest("GET", "/admin/test", nil)
	require.NoError(t, err)

	// Set valid admin ID
	adminID := "admin1"
	req.Header.Set("X-Admin-ID", adminID)

	// Create signature with a different message
	wrongMessage := "/wrong/path"
	hash := sha256.Sum256([]byte(wrongMessage))
	signature, err := ecdsa.SignASN1(rand.Reader, adminPrivKeys[adminID], hash[:])
	require.NoError(t, err)

	req.Header.Set("X-Admin-Signature", base64.StdEncoding.EncodeToString(signature))

	// Verify the admin - should fail due to invalid signature
	_, ok := handler.verifyAdmin(req)
	assert.False(t, ok, "Admin verification should fail due to invalid signature")
}

// Status endpoint test

func TestAdminHandler_handleStatus(t *testing.T) {
	_, adminPubKeys := generateAdminKeyPairs(t, 1)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Create a request to the status endpoint
	req := httptest.NewRequest("GET", "/admin/status", nil)
	w := httptest.NewRecorder()

	// Call the handler directly
	handler.handleStatus(w, req)

	// Check the response
	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err := json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	assert.Equal(t, "initial", result["state"])

	// Change the state and test again
	handler.mu.Lock()
	handler.state = StateGeneratingShares
	handler.threshold = 3
	handler.totalShares = 5
	handler.mu.Unlock()

	w = httptest.NewRecorder()
	handler.handleStatus(w, req)

	resp = w.Result()
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	assert.Equal(t, "generating_shares", result["state"])
	assert.Equal(t, float64(3), result["threshold"])
	assert.Equal(t, float64(5), result["total_shares"])
}

// Init generate tests

func TestAdminHandler_handleInitGenerate(t *testing.T) {
	adminPrivKeys, adminPubKeys := generateAdminKeyPairs(t, 5)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Set up test server
	server := createTestServer(t, handler)
	defer server.Close()

	// Create request body
	reqBody := map[string]interface{}{
		"threshold":    3,
		"total_shares": 5,
	}
	reqJSON, err := json.Marshal(reqBody)
	require.NoError(t, err)

	// Create signed request
	adminID := "admin1"
	req := createSignedRequest(
		t,
		"POST",
		server.URL+"/admin/init/generate",
		reqJSON,
		adminID,
		adminPrivKeys[adminID],
	)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check response
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	// Verify response contents
	assert.Contains(t, result, "message")
	assert.Contains(t, result, "share_assignments")
	assert.Equal(t, float64(3), result["threshold"])
	assert.Equal(t, float64(5), result["total_shares"])

	// Verify handler state
	assert.Equal(t, StateGeneratingShares, handler.state)
	assert.NotNil(t, handler.shamirKMS)
	assert.Equal(t, 3, handler.threshold)
	assert.Equal(t, 5, handler.totalShares)
	assert.Len(t, handler.adminShares, 5)
}

func TestAdminHandler_handleInitGenerate_InvalidParameters(t *testing.T) {
	adminPrivKeys, adminPubKeys := generateAdminKeyPairs(t, 5)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Set up test server
	server := createTestServer(t, handler)
	defer server.Close()

	// Test cases
	testCases := []struct {
		name     string
		reqBody  map[string]interface{}
		expected int
	}{
		{
			name: "threshold < 2",
			reqBody: map[string]interface{}{
				"threshold":    1,
				"total_shares": 5,
			},
			expected: http.StatusBadRequest,
		},
		{
			name: "total_shares < threshold",
			reqBody: map[string]interface{}{
				"threshold":    3,
				"total_shares": 2,
			},
			expected: http.StatusBadRequest,
		},
		{
			name: "too many shares",
			reqBody: map[string]interface{}{
				"threshold":    3,
				"total_shares": 10, // More than available admins
			},
			expected: http.StatusBadRequest,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			reqJSON, err := json.Marshal(tc.reqBody)
			require.NoError(t, err)

			adminID := "admin1"
			req := createSignedRequest(
				t,
				"POST",
				server.URL+"/admin/init/generate",
				reqJSON,
				adminID,
				adminPrivKeys[adminID],
			)

			client := &http.Client{}
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			assert.Equal(t, tc.expected, resp.StatusCode)
		})
	}
}

func TestAdminHandler_handleInitGenerate_AlreadyInProgress(t *testing.T) {
	adminPrivKeys, adminPubKeys := generateAdminKeyPairs(t, 5)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Set state to not initial
	handler.mu.Lock()
	handler.state = StateGeneratingShares
	handler.mu.Unlock()

	// Set up test server
	server := createTestServer(t, handler)
	defer server.Close()

	// Create request body
	reqBody := map[string]interface{}{
		"threshold":    3,
		"total_shares": 5,
	}
	reqJSON, err := json.Marshal(reqBody)
	require.NoError(t, err)

	// Create signed request
	adminID := "admin1"
	req := createSignedRequest(
		t,
		"POST",
		server.URL+"/admin/init/generate",
		reqJSON,
		adminID,
		adminPrivKeys[adminID],
	)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return error
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// Get share tests

func TestAdminHandler_handleGetShare(t *testing.T) {
	adminPrivKeys, adminPubKeys := generateAdminKeyPairs(t, 5)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Generate shares first
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	shamirKMS, shares, err := kms.NewShamirKMS(masterKey, 3, 5)
	require.NoError(t, err)

	// Register admins with KMS
	for _, pubKeyPEM := range adminPubKeys {
		err = shamirKMS.RegisterAdmin(pubKeyPEM)
		require.NoError(t, err, "Failed to register admin with KMS")
	}

	// Prepare for share distribution
	adminIDs := []string{"admin1", "admin2", "admin3", "admin4", "admin5"}

	// Create secure shares
	for i, share := range shares {
		adminID := adminIDs[i]
		pubKeyPEM := adminPubKeys[adminID]

		// Encrypt the share with the admin's public key
		encryptedShare, err := cryptoutils.EncryptWithPublicKey(pubKeyPEM, share)
		require.NoError(t, err)

		// Store the encrypted share
		handler.adminShares[adminID] = &SecureShare{
			AdminID:        adminID,
			ShareIndex:     i,
			EncryptedShare: encryptedShare,
			Retrieved:      false,
		}
	}

	// Setup handler state
	handler.mu.Lock()
	handler.shamirKMS = shamirKMS
	handler.threshold = 3
	handler.totalShares = 5
	handler.state = StateGeneratingShares
	handler.mu.Unlock()

	// Set up test server
	server := createTestServer(t, handler)
	defer server.Close()

	// Test that each admin can get their own share
	for _, adminID := range adminIDs {
		t.Run("Admin_"+adminID, func(t *testing.T) {
			req := createSignedRequest(
				t,
				"GET",
				server.URL+"/admin/share",
				nil,
				adminID,
				adminPrivKeys[adminID],
			)

			client := &http.Client{}
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			// Check response
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var result map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&result)
			require.NoError(t, err)

			// Verify response contents
			assert.Contains(t, result, "share_index")
			assert.Contains(t, result, "encrypted_share")

			// Verify share is now marked as retrieved
			handler.mu.RLock()
			share := handler.adminShares[adminID]
			assert.True(t, share.Retrieved, "Share should be marked as retrieved")
			handler.mu.RUnlock()

			// Test decryption of the share
			encryptedShareB64 := result["encrypted_share"].(string)
			encryptedShare, err := base64.StdEncoding.DecodeString(encryptedShareB64)
			require.NoError(t, err)

			// Convert private key to PEM
			privateKeyBytes, err := x509.MarshalECPrivateKey(adminPrivKeys[adminID])
			require.NoError(t, err)

			privateKeyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "EC PRIVATE KEY",
				Bytes: privateKeyBytes,
			})

			// Decrypt the share
			decryptedShare, err := cryptoutils.DecryptWithPrivateKey(privateKeyPEM, encryptedShare)
			require.NoError(t, err, "Share decryption should succeed")
			assert.NotEmpty(t, decryptedShare, "Decrypted share should not be empty")
		})
	}

	// Verify that all shares are retrieved and state is updated
	assert.Equal(t, StateComplete, handler.state, "State should be complete after all shares retrieved")
	assert.NotNil(t, <-handler.completeChan, "Complete channel should be closed")
}

func TestAdminHandler_handleGetShare_NotGeneratingState(t *testing.T) {
	adminPrivKeys, adminPubKeys := generateAdminKeyPairs(t, 1)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Set up test server
	server := createTestServer(t, handler)
	defer server.Close()

	// Create signed request
	adminID := "admin1"
	req := createSignedRequest(
		t,
		"GET",
		server.URL+"/admin/share",
		nil,
		adminID,
		adminPrivKeys[adminID],
	)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return error because not in generating state
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAdminHandler_handleGetShare_NoAssignedShare(t *testing.T) {
	adminPrivKeys, adminPubKeys := generateAdminKeyPairs(t, 2)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Set state but don't assign shares
	handler.mu.Lock()
	handler.state = StateGeneratingShares
	handler.mu.Unlock()

	// Set up test server
	server := createTestServer(t, handler)
	defer server.Close()

	// Create signed request
	adminID := "admin1"
	req := createSignedRequest(
		t,
		"GET",
		server.URL+"/admin/share",
		nil,
		adminID,
		adminPrivKeys[adminID],
	)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return error because admin has no assigned share
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

// Recovery tests

func TestAdminHandler_handleInitRecover(t *testing.T) {
	adminPrivKeys, adminPubKeys := generateAdminKeyPairs(t, 5)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Set up test server
	server := createTestServer(t, handler)
	defer server.Close()

	// Create request body
	reqBody := map[string]interface{}{
		"threshold": 3,
	}
	reqJSON, err := json.Marshal(reqBody)
	require.NoError(t, err)

	// Create signed request
	adminID := "admin1"
	req := createSignedRequest(
		t,
		"POST",
		server.URL+"/admin/init/recover",
		reqJSON,
		adminID,
		adminPrivKeys[adminID],
	)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Check response
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result map[string]interface{}
	err = json.NewDecoder(resp.Body).Decode(&result)
	require.NoError(t, err)

	// Verify response contents
	assert.Contains(t, result, "message")
	assert.Contains(t, result, "threshold")
	assert.Equal(t, float64(3), result["threshold"])

	// Verify handler state
	assert.Equal(t, StateRecovering, handler.state)
	assert.NotNil(t, handler.shamirKMS)
	assert.Equal(t, 3, handler.threshold)
	assert.Equal(t, 5, handler.totalShares) // Should be number of admins
}

func TestAdminHandler_handleInitRecover_InvalidParameters(t *testing.T) {
	adminPrivKeys, adminPubKeys := generateAdminKeyPairs(t, 5)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Set up test server
	server := createTestServer(t, handler)
	defer server.Close()

	// Create request body with invalid threshold
	reqBody := map[string]interface{}{
		"threshold": 1, // Less than 2 is invalid
	}
	reqJSON, err := json.Marshal(reqBody)
	require.NoError(t, err)

	// Create signed request
	adminID := "admin1"
	req := createSignedRequest(
		t,
		"POST",
		server.URL+"/admin/init/recover",
		reqJSON,
		adminID,
		adminPrivKeys[adminID],
	)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return error
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

func TestAdminHandler_handleSubmitShare(t *testing.T) {
	adminPrivKeys, adminPubKeys := generateAdminKeyPairs(t, 5)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Generate master key and shares for testing
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	_, shares, err := kms.NewShamirKMS(masterKey, 3, 5)
	require.NoError(t, err)

	// Create recovery KMS
	shamirKMS := kms.NewShamirKMSRecovery(3)

	// Register admins with KMS
	for _, pubKeyPEM := range adminPubKeys {
		err = shamirKMS.RegisterAdmin(pubKeyPEM)
		require.NoError(t, err, "Failed to register admin with KMS")
	}

	// Set up handler for recovery
	handler.mu.Lock()
	handler.shamirKMS = shamirKMS
	handler.threshold = 3
	handler.totalShares = 5
	handler.state = StateRecovering
	handler.mu.Unlock()

	// Set up test server
	server := createTestServer(t, handler)
	defer server.Close()

	// Submit shares from 3 admins
	adminIDs := []string{"admin1", "admin2", "admin3"}

	for i, adminID := range adminIDs {
		t.Run("Submit_"+adminID, func(t *testing.T) {
			// Sign the share
			hash := sha256.Sum256(shares[i])
			signature, err := ecdsa.SignASN1(rand.Reader, adminPrivKeys[adminID], hash[:])
			require.NoError(t, err)

			// Create request body
			reqBody := map[string]interface{}{
				"share_index": i,
				"share":       base64.StdEncoding.EncodeToString(shares[i]),
				"signature":   base64.StdEncoding.EncodeToString(signature),
			}
			reqJSON, err := json.Marshal(reqBody)
			require.NoError(t, err)

			// Create signed request
			req := createSignedRequest(
				t,
				"POST",
				server.URL+"/admin/share",
				reqJSON,
				adminID,
				adminPrivKeys[adminID],
			)

			// Send the request
			client := &http.Client{}
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			// Check response
			assert.Equal(t, http.StatusOK, resp.StatusCode)

			var result map[string]interface{}
			err = json.NewDecoder(resp.Body).Decode(&result)
			require.NoError(t, err)

			// For the final share, the KMS should be unlocked
			if i == 2 {
				assert.Equal(t, StateComplete, handler.state, "State should be complete after threshold shares")
				assert.Contains(t, result["message"], "successfully")
			} else {
				assert.Equal(t, StateRecovering, handler.state, "State should still be recovering")
				assert.Contains(t, result["message"], "waiting")
			}
		})
	}

	// Verify final state
	assert.Equal(t, StateComplete, handler.state)
	assert.True(t, handler.shamirKMS.IsUnlocked(), "KMS should be unlocked")
	assert.NotNil(t, <-handler.completeChan, "Complete channel should be closed")
}

func TestAdminHandler_handleSubmitShare_NotRecovering(t *testing.T) {
	adminPrivKeys, adminPubKeys := generateAdminKeyPairs(t, 1)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Set up test server
	server := createTestServer(t, handler)
	defer server.Close()

	// Create request body
	reqBody := map[string]interface{}{
		"share_index": 0,
		"share":       base64.StdEncoding.EncodeToString([]byte("test-share")),
		"signature":   base64.StdEncoding.EncodeToString([]byte("test-signature")),
	}
	reqJSON, err := json.Marshal(reqBody)
	require.NoError(t, err)

	// Create signed request
	adminID := "admin1"
	req := createSignedRequest(
		t,
		"POST",
		server.URL+"/admin/share",
		reqJSON,
		adminID,
		adminPrivKeys[adminID],
	)

	// Send the request
	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Should return error because not in recovering state
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
}

// Utility function tests

func TestLoadAdminKeys(t *testing.T) {
	// Generate key pairs
	_, pubKey1Str, err := GenerateAdminKeyPair()
	require.NoError(t, err)

	_, pubKey2Str, err := GenerateAdminKeyPair()
	require.NoError(t, err)

	// Create test JSON
	jsonData := fmt.Sprintf(`{
		"admins": [
			{
				"id": "admin1",
				"pubkey": %q
			},
			{
				"id": "admin2",
				"pubkey": %q
			}
		]
	}`, pubKey1Str, pubKey2Str)

	// Load the keys
	adminKeys, err := LoadAdminKeys(strings.NewReader(jsonData))
	require.NoError(t, err)

	// Verify the keys were loaded correctly
	assert.Len(t, adminKeys, 2, "Should load 2 admin keys")
	assert.Contains(t, adminKeys, "admin1", "Should contain admin1")
	assert.Contains(t, adminKeys, "admin2", "Should contain admin2")
	assert.Equal(t, []byte(pubKey1Str), adminKeys["admin1"], "Pubkey1 should match")
	assert.Equal(t, []byte(pubKey2Str), adminKeys["admin2"], "Pubkey2 should match")
}

func TestGenerateAdminKeyPair(t *testing.T) {
	privKeyStr, pubKeyStr, err := GenerateAdminKeyPair()
	require.NoError(t, err, "Key generation should succeed")

	// Verify private key
	assert.Contains(t, privKeyStr, "EC PRIVATE KEY", "Private key should be in PEM format")

	privKeyBlock, _ := pem.Decode([]byte(privKeyStr))
	require.NotNil(t, privKeyBlock, "Private key PEM should decode")

	privateKey, err := x509.ParseECPrivateKey(privKeyBlock.Bytes)
	require.NoError(t, err, "Private key should parse")
	assert.Equal(t, elliptic.P256(), privateKey.Curve, "Should use P256 curve")

	// Verify public key
	assert.Contains(t, pubKeyStr, "PUBLIC KEY", "Public key should be in PEM format")

	pubKeyBlock, _ := pem.Decode([]byte(pubKeyStr))
	require.NotNil(t, pubKeyBlock, "Public key PEM should decode")

	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBlock.Bytes)
	require.NoError(t, err, "Public key should parse")

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	assert.True(t, ok, "Public key should be ECDSA")
	assert.Equal(t, elliptic.P256(), ecdsaPubKey.Curve, "Should use P256 curve")

	// Verify the keys correspond to each other
	pub1X, pub1Y := privateKey.PublicKey.X, privateKey.PublicKey.Y
	pub2X, pub2Y := ecdsaPubKey.X, ecdsaPubKey.Y

	assert.Equal(t, pub1X, pub2X, "Public key X coordinates should match")
	assert.Equal(t, pub1Y, pub2Y, "Public key Y coordinates should match")
}

func TestComputeFingerprint(t *testing.T) {
	_, pubKeyStr, err := GenerateAdminKeyPair()
	require.NoError(t, err)

	fingerprint, err := ComputeFingerprint([]byte(pubKeyStr))
	require.NoError(t, err, "Fingerprint computation should succeed")

	// Verify fingerprint is a valid hex string of correct length (SHA-256 = 32 bytes = 64 hex chars)
	assert.Len(t, fingerprint, 64, "Fingerprint should be 64 hex characters")
	_, err = hex.DecodeString(fingerprint)
	assert.NoError(t, err, "Fingerprint should be valid hex")

	// Compute again to verify determinism
	fingerprint2, err := ComputeFingerprint([]byte(pubKeyStr))
	require.NoError(t, err)
	assert.Equal(t, fingerprint, fingerprint2, "Fingerprint should be deterministic")

	// Compute for different key to verify uniqueness
	_, pubKeyStr2, err := GenerateAdminKeyPair()
	require.NoError(t, err)

	fingerprint3, err := ComputeFingerprint([]byte(pubKeyStr2))
	require.NoError(t, err)
	assert.NotEqual(t, fingerprint, fingerprint3, "Fingerprints should be unique for different keys")
}

func TestParsePrivateKey(t *testing.T) {
	// Generate a key pair
	privKeyStr, _, err := GenerateAdminKeyPair()
	require.NoError(t, err)

	// Parse the private key
	privateKey, err := ParsePrivateKey([]byte(privKeyStr))
	require.NoError(t, err, "Private key parsing should succeed")
	assert.NotNil(t, privateKey, "Parsed private key should not be nil")
	assert.Equal(t, elliptic.P256(), privateKey.Curve, "Should use P256 curve")

	// Test with invalid PEM
	_, err = ParsePrivateKey([]byte("not-a-valid-pem"))
	assert.Error(t, err, "Should fail with invalid PEM")

	// Test with wrong key type
	wrongKeyPEM := `-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0cQBxMAYfka3QKS2VhCUo/rI3y+lsVGjcrM2bZHXCi6/D4aX
OVLfZ7xJxQhxUYwM5OFpHVfJGKB+MsIlEQALnsFaGZ9VNlb5K9kFPAIqSAL48Nar
...
-----END RSA PRIVATE KEY-----`

	_, err = ParsePrivateKey([]byte(wrongKeyPEM))
	assert.Error(t, err, "Should fail with wrong key type")
}

// End-to-end tests

func TestAdminHandler_EndToEnd_GenerateAndRetrieve(t *testing.T) {
	adminPrivKeys, adminPubKeys := generateAdminKeyPairs(t, 3)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Set up test server
	server := createTestServer(t, handler)
	defer server.Close()

	// Step 1: Initialize generation
	reqBody := map[string]interface{}{
		"threshold":    2,
		"total_shares": 3,
	}
	reqJSON, err := json.Marshal(reqBody)
	require.NoError(t, err)

	adminID := "admin1"
	req := createSignedRequest(
		t,
		"POST",
		server.URL+"/admin/init/generate",
		reqJSON,
		adminID,
		adminPrivKeys[adminID],
	)

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Step 2: Each admin retrieves their share
	retrievedShares := make(map[string][]byte)
	retrievedIndices := make(map[string]int)

	for adminID, privateKey := range adminPrivKeys {
		req := createSignedRequest(
			t,
			"GET",
			server.URL+"/admin/share",
			nil,
			adminID,
			privateKey,
		)

		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var result map[string]interface{}
		err = json.NewDecoder(resp.Body).Decode(&result)
		resp.Body.Close()
		require.NoError(t, err)

		encryptedShareB64 := result["encrypted_share"].(string)
		encryptedShare, err := base64.StdEncoding.DecodeString(encryptedShareB64)
		require.NoError(t, err)

		// Convert private key to PEM
		privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
		require.NoError(t, err)

		privateKeyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privateKeyBytes,
		})

		// Decrypt the share
		decryptedShare, err := cryptoutils.DecryptWithPrivateKey(privateKeyPEM, encryptedShare)
		require.NoError(t, err)

		retrievedShares[adminID] = decryptedShare
		retrievedIndices[adminID] = int(result["share_index"].(float64))
	}

	// Verify state at the end
	assert.Equal(t, StateComplete, handler.state, "State should be complete")
	assert.True(t, handler.shamirKMS.IsUnlocked(), "KMS should be unlocked")
}

func TestAdminHandler_EndToEnd_RecoveryFlow(t *testing.T) {
	adminPrivKeys, adminPubKeys := generateAdminKeyPairs(t, 3)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	handler := NewAdminHandler(logger, adminPubKeys)

	// Set up test server
	server := createTestServer(t, handler)
	defer server.Close()

	// Step 1: Generate a master key and shares outside the handler
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)

	_, shares, err := kms.NewShamirKMS(masterKey, 2, 3)
	require.NoError(t, err)

	// Step 2: Initialize recovery
	reqBody := map[string]interface{}{
		"threshold": 2,
	}
	reqJSON, err := json.Marshal(reqBody)
	require.NoError(t, err)

	adminID := "admin1"
	req := createSignedRequest(
		t,
		"POST",
		server.URL+"/admin/init/recover",
		reqJSON,
		adminID,
		adminPrivKeys[adminID],
	)

	client := &http.Client{}
	resp, err := client.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp.Body.Close()

	// Step 3: Submit shares from two admins
	adminIDs := []string{"admin1", "admin2"}

	for i, adminID := range adminIDs {
		// Sign the share
		hash := sha256.Sum256(shares[i])
		signature, err := ecdsa.SignASN1(rand.Reader, adminPrivKeys[adminID], hash[:])
		require.NoError(t, err)

		reqBody := map[string]interface{}{
			"share_index": i,
			"share":       base64.StdEncoding.EncodeToString(shares[i]),
			"signature":   base64.StdEncoding.EncodeToString(signature),
		}
		reqJSON, err := json.Marshal(reqBody)
		require.NoError(t, err)

		req := createSignedRequest(
			t,
			"POST",
			server.URL+"/admin/share",
			reqJSON,
			adminID,
			adminPrivKeys[adminID],
		)

		resp, err := client.Do(req)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
		resp.Body.Close()
	}

	// Verify state at the end
	assert.Equal(t, StateComplete, handler.state, "State should be complete")
	assert.True(t, handler.shamirKMS.IsUnlocked(), "KMS should be unlocked")
}
