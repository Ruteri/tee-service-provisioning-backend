package kmshandler

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-chi/chi/v5"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/ruteri/tee-service-provisioning-backend/kms"
	"github.com/ruteri/tee-service-provisioning-backend/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// setupTestEnvironment creates common test components
func setupTestEnvironment(t *testing.T) (*slog.Logger, interfaces.KMS) {
	// Create logger with no output for tests
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Set up real KMS
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)
	kmsInstance, err := kms.NewSimpleKMS(masterKey)
	require.NoError(t, err)

	return logger, kmsInstance
}

func getTestMeasurements() string {
	var bytesPrefix [47]byte
	m, _ := json.Marshal(map[int]string{
		0: hex.EncodeToString(append(bytesPrefix[:], 0)),
		1: hex.EncodeToString(append(bytesPrefix[:], 1)),
		2: hex.EncodeToString(append(bytesPrefix[:], 2)),
		3: hex.EncodeToString(append(bytesPrefix[:], 3)),
		4: hex.EncodeToString(append(bytesPrefix[:], 4)),
	})
	return string(m)
}

// Test HandleSecrets - Success Path
func TestHandleSecrets_Success(t *testing.T) {
	logger, kmsInstance := setupTestEnvironment(t)

	// Set up mock registry factory
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Set up test data
	contractAddr, _ := interfaces.NewContractAddressFromHex("0123456789abcdef0123")
	identity := [32]byte{1, 2, 3, 4}

	// Setup mock expectations for registry
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("DCAPIdentity", mock.Anything).Return(identity, nil)
	mockRegistry.On("IdentityAllowed", identity, mock.Anything).Return(true, nil)

	// Create handler
	handler := NewHandler(kmsInstance, contractAddr, nil, mockRegistryFactory, logger)

	// Create test CSR
	_, csr, err := cryptoutils.CreateCSRWithRandomKey(interfaces.NewAppCommonName(contractAddr).String())
	require.NoError(t, err)

	// Create request with contract address in URL
	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/attested/secrets/%s", contractAddr.String()),
		bytes.NewReader(csr),
	)
	req.Header.Set(cryptoutils.AttestationTypeHeader, cryptoutils.DCAPAttestation.StringID)
	req.Header.Set(cryptoutils.MeasurementHeader, getTestMeasurements())

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

	var result interfaces.AppSecrets
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	err = json.Unmarshal(respBody, &result)
	require.NoError(t, err, string(respBody))

	// Verify response contains expected fields
	assert.NotEmpty(t, result.AppPrivkey)
	assert.NotEmpty(t, result.TLSCert)

	// Verify registry mock expectations were met
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

// Test HandleSecrets - Identity Not Allowed
func TestHandleSecrets_IdentityNotAllowlisted(t *testing.T) {
	logger, kmsInstance := setupTestEnvironment(t)

	// Set up mock registry factory
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Set up test data
	contractAddr, _ := interfaces.NewContractAddressFromHex("0123456789abcdef0123")
	identity := [32]byte{1, 2, 3, 4}

	// Setup mock expectations for failure case
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("DCAPIdentity", mock.Anything).Return(identity, nil)
	mockRegistry.On("IdentityAllowed", identity, mock.Anything).Return(false, nil)

	// Create handler
	handler := NewHandler(kmsInstance, contractAddr, nil, mockRegistryFactory, logger)

	// Create test CSR
	_, csr, err := cryptoutils.CreateCSRWithRandomKey(interfaces.NewAppCommonName(contractAddr).String())
	require.NoError(t, err)

	// Create request with contract address in URL
	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/attested/secrets/%s", contractAddr.String()),
		bytes.NewReader(csr),
	)
	req.Header.Set(cryptoutils.AttestationTypeHeader, cryptoutils.DCAPAttestation.StringID)
	req.Header.Set(cryptoutils.MeasurementHeader, getTestMeasurements())

	// Create response recorder
	w := httptest.NewRecorder()

	// Call handler
	mux := chi.NewRouter()
	handler.RegisterRoutes(mux)
	mux.ServeHTTP(w, req)

	// Verify response
	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "identity not allowed")

	// Verify expectations
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

// TestHandleSecrets_WithOperatorSignature tests the secrets retrieval process
// when an operator signature is included in the CSR.
func TestHandleSecrets_WithOperatorSignature(t *testing.T) {
	logger, kmsInstance := setupTestEnvironment(t)

	// Set up mock registry factory
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Set up test data
	contractAddr, _ := interfaces.NewContractAddressFromHex("0123456789abcdef0123")
	identity := [32]byte{1, 2, 3, 4}

	// Setup mock expectations for registry - note the operatorAddress parameter
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("DCAPIdentity", mock.Anything).Return(identity, nil)

	// Create handler
	handler := NewHandler(kmsInstance, contractAddr, nil, mockRegistryFactory, logger)

	// Create a private key for the instance
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create CSR template with the correct CN
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: interfaces.NewAppCommonName(contractAddr).String(),
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	// Create the CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	require.NoError(t, err)

	// Parse CSR to extract public key info
	parsedCSR, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	// Create operator's private key for signing
	operatorKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	require.NoError(t, err)

	// Sign the CSR's public key info with operator's key
	operatorSignature, err := crypto.Sign(cryptoutils.DERPubkeyHash(parsedCSR.RawSubjectPublicKeyInfo), operatorKey)
	require.NoError(t, err)

	// Get the operator's Ethereum address from public key to verify our test
	derivedOperatorAddr := crypto.PubkeyToAddress(operatorKey.PublicKey)

	var operatorAddress [20]byte
	copy(operatorAddress[:], derivedOperatorAddr.Bytes())

	mockRegistry.On("IdentityAllowed", identity, operatorAddress).Return(true, nil)

	// Create a new CSR template with the signature extension
	templateWithSig := template
	templateWithSig.ExtraExtensions = []pkix.Extension{
		{
			Id:    cryptoutils.OIDOperatorSignature,
			Value: operatorSignature,
		},
	}

	// Create the final CSR with signature extension
	csrWithSigDER, err := x509.CreateCertificateRequest(rand.Reader, &templateWithSig, privateKey)
	require.NoError(t, err)

	// Encode CSR in PEM format
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrWithSigDER,
	})

	// Create request with contract address in URL
	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/attested/secrets/%s", contractAddr.String()),
		bytes.NewReader(csrPEM),
	)
	req.Header.Set(cryptoutils.AttestationTypeHeader, cryptoutils.DCAPAttestation.StringID)
	req.Header.Set(cryptoutils.MeasurementHeader, getTestMeasurements())

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

	var result interfaces.AppSecrets
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	err = json.Unmarshal(respBody, &result)
	require.NoError(t, err, string(respBody))

	// Verify response contains expected fields
	assert.NotEmpty(t, result.AppPrivkey)
	assert.NotEmpty(t, result.TLSCert)

	// Verify registry mock expectations were met
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

// TestHandleSecrets_UnauthorizedOperator tests rejection when an operator
// without necessary permissions attempts to sign a CSR
func TestHandleSecrets_UnauthorizedOperator(t *testing.T) {
	logger, kmsInstance := setupTestEnvironment(t)

	// Set up mock registry factory
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Set up test data
	contractAddr, _ := interfaces.NewContractAddressFromHex("0123456789abcdef0123")
	identity := [32]byte{1, 2, 3, 4}

	// Setup mock expectations - operator is not authorized for this identity
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("DCAPIdentity", mock.Anything).Return(identity, nil)

	// Create handler
	handler := NewHandler(kmsInstance, contractAddr, nil, mockRegistryFactory, logger)

	// Create a private key for the instance
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Create CSR template
	template := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: interfaces.NewAppCommonName(contractAddr).String(),
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	// Create the CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &template, privateKey)
	require.NoError(t, err)

	// Parse CSR to extract public key info
	parsedCSR, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	// Create operator's private key
	operatorKey, err := ecdsa.GenerateKey(crypto.S256(), rand.Reader)
	require.NoError(t, err)

	// Get the operator's address
	derivedOperatorAddr := crypto.PubkeyToAddress(operatorKey.PublicKey)
	var operatorAddress [20]byte
	copy(operatorAddress[:], derivedOperatorAddr.Bytes())
	mockRegistry.On("IdentityAllowed", identity, operatorAddress).Return(false, nil)

	// Sign the CSR's public key info
	operatorSignature, err := crypto.Sign(cryptoutils.DERPubkeyHash(parsedCSR.RawSubjectPublicKeyInfo), operatorKey)
	require.NoError(t, err)

	// Create CSR with signature extension
	templateWithSig := template
	templateWithSig.ExtraExtensions = []pkix.Extension{
		{
			Id:    cryptoutils.OIDOperatorSignature,
			Value: operatorSignature,
		},
	}

	csrWithSigDER, err := x509.CreateCertificateRequest(rand.Reader, &templateWithSig, privateKey)
	require.NoError(t, err)

	// Encode CSR in PEM format
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrWithSigDER,
	})

	// Create request
	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/attested/secrets/%s", contractAddr.String()),
		bytes.NewReader(csrPEM),
	)
	req.Header.Set(cryptoutils.AttestationTypeHeader, cryptoutils.DCAPAttestation.StringID)
	req.Header.Set(cryptoutils.MeasurementHeader, getTestMeasurements())

	// Create response recorder
	w := httptest.NewRecorder()

	// Call handler
	mux := chi.NewRouter()
	handler.RegisterRoutes(mux)
	mux.ServeHTTP(w, req)

	// Verify response - should be rejected
	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "identity not allowed")

	// Verify expectations
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

// Test handling of invalid request input
func TestHandleSecrets_InvalidInput(t *testing.T) {
	logger, kmsInstance := setupTestEnvironment(t)

	identity := [32]byte{1, 2, 3, 4}

	// Set up mock registry factory
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)
	mockRegistry.On("DCAPIdentity", mock.Anything).Return(identity, nil)
	mockRegistry.On("IdentityAllowed", identity, mock.Anything).Return(true, nil)
	mockRegistryFactory.On("RegistryFor", mock.Anything).Return(mockRegistry, nil)

	// Create handler
	handler := NewHandler(kmsInstance, interfaces.ContractAddress{}, nil, mockRegistryFactory, logger)

	testCases := []struct {
		name         string
		contractAddr string
		csrData      []byte
		headers      map[string]string
		wantStatus   int
		wantBody     string
	}{
		{
			name:         "Empty CSR",
			contractAddr: hex.EncodeToString([]byte("0123456789abcdef0123")),
			csrData:      []byte{},
			headers: map[string]string{
				cryptoutils.AttestationTypeHeader: cryptoutils.DCAPAttestation.StringID,
				cryptoutils.MeasurementHeader:     getTestMeasurements(),
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   "Empty CSR",
		},
		{
			name:         "Invalid Contract Address",
			contractAddr: "invalid-address",
			csrData:      []byte("dummy-csr"),
			headers: map[string]string{
				cryptoutils.AttestationTypeHeader: cryptoutils.DCAPAttestation.StringID,
				cryptoutils.MeasurementHeader:     getTestMeasurements(),
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   "invalid contract address",
		},
		{
			name:         "Missing Attestation Type",
			contractAddr: hex.EncodeToString([]byte("0123456789abcdef0123")),
			csrData:      []byte("dummy-csr"),
			headers: map[string]string{
				cryptoutils.MeasurementHeader: getTestMeasurements(),
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   "invalid measurements",
		},
		{
			name:         "Missing Measurements",
			contractAddr: hex.EncodeToString([]byte("0123456789abcdef0123")),
			csrData:      []byte("dummy-csr"),
			headers: map[string]string{
				cryptoutils.AttestationTypeHeader: cryptoutils.DCAPAttestation.StringID,
			},
			wantStatus: http.StatusBadRequest,
			wantBody:   "invalid measurements",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create request
			req := httptest.NewRequest(
				http.MethodPost,
				fmt.Sprintf("/api/attested/secrets/%s", tc.contractAddr),
				bytes.NewReader(tc.csrData),
			)

			// Add headers
			for k, v := range tc.headers {
				req.Header.Set(k, v)
			}

			// Create response recorder
			w := httptest.NewRecorder()

			// Call handler
			mux := chi.NewRouter()
			handler.RegisterRoutes(mux)
			mux.ServeHTTP(w, req)

			// Verify response
			resp := w.Result()
			defer resp.Body.Close()

			assert.Equal(t, tc.wantStatus, resp.StatusCode)

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			assert.Contains(t, string(body), tc.wantBody)
		})
	}
}
