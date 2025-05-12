package pkihandler

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/ruteri/tee-service-provisioning-backend/api"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/ruteri/tee-service-provisioning-backend/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test HandlePki with Real KMS
func TestHandlePki_WithRealKMS(t *testing.T) {
	// Create logger with no output for tests
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create a real KMS instance for integration testing
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}

	realKMS, err := kms.NewSimpleKMS(masterKey)
	require.NoError(t, err)

	// Set up test data
	contractAddr, _ := interfaces.NewContractAddressFromHex("0123456789abcdef0123")

	// Create handler
	handler := NewHandler(realKMS, logger)

	// Create test request
	req := httptest.NewRequest(
		http.MethodGet,
		fmt.Sprintf("/api/public/pki/%s", contractAddr.String()),
		nil,
	)

	// Create response recorder
	w := httptest.NewRecorder()

	// Call handler
	mux := chi.NewRouter()
	handler.RegisterRoutes(mux)
	mux.ServeHTTP(w, req)

	// Verify response
	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var result api.PKIResponse
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	err = json.Unmarshal(respBody, &result)
	require.NoError(t, err, string(respBody))

	// Verify response contains valid data
	assert.NotEmpty(t, result.CACert)
	assert.NotEmpty(t, result.AppPubkey)
	assert.NotEmpty(t, result.Attestation)

	// Verify that the returned CA cert is PEM-encoded and has a valid structure
	assert.True(t, len(result.CACert) > 0)
	assert.Contains(t, string(result.CACert), "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, string(result.CACert), "-----END CERTIFICATE-----")

	// Verify that the returned public key is PEM-encoded and has a valid structure
	assert.True(t, len(result.AppPubkey) > 0)
	assert.Contains(t, string(result.AppPubkey), "-----BEGIN PUBLIC KEY-----")
	assert.Contains(t, string(result.AppPubkey), "-----END PUBLIC KEY-----")
}
