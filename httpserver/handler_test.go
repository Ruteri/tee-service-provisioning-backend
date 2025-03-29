package httpserver

import (
	"bytes"
	"context"
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
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/go-chi/chi/v5"
	"github.com/ruteri/poc-tee-registry/interfaces"
	"github.com/ruteri/poc-tee-registry/kms"
	"github.com/ruteri/poc-tee-registry/registry"
	"github.com/ruteri/poc-tee-registry/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// Test HandleRegister - Success Path
func TestHandleRegister_Success(t *testing.T) {
	// Create temporary storage directory
	tempDir, err := os.MkdirTemp("", "file-storage-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create logger with no output for tests
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Set up real KMS
	masterKey := make([]byte, 32)
	_, err = rand.Read(masterKey)
	require.NoError(t, err)
	kmsInstance, err := kms.NewSimpleKMS(masterKey)
	require.NoError(t, err)

	// Set up real storage factory
	storageFactory := storage.NewStorageBackendFactory(logger)

	// Initialize a file storage backend
	fileBackend, err := storage.NewFileBackend(tempDir, logger)
	require.NoError(t, err)

	// Set up mock registry factory (we still need this since it depends on blockchain)
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Set up test data
	contractAddr := interfaces.ContractAddress(common.HexToAddress("0123456789abcdef0123"))
	identity := [32]byte{1, 2, 3, 4}
	configTemplate := []byte(`{"app":"test","settings":{"timeout":30}}`)

	// Store the config in file storage
	ctx := context.Background()
	configHash, err := fileBackend.Store(ctx, configTemplate, interfaces.ConfigType)
	require.NoError(t, err)

	// Setup mock expectations for registry
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("ComputeDCAPIdentity", mock.Anything).Return(identity, nil)
	mockRegistry.On("IsWhitelisted", identity).Return(true, nil)
	mockRegistry.On("IdentityConfigMap", identity).Return([32]byte(configHash), nil)
	mockRegistry.On("AllStorageBackends").Return([]string{fileBackend.LocationURI()}, nil)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	// Create test CSR
	csr, err := CreateCSR()
	require.NoError(t, err)
	
	// Create request with contract address in URL
	contractAddrHex := hex.EncodeToString(contractAddr[:])
	req := httptest.NewRequest(
		http.MethodPost, 
		fmt.Sprintf("/api/attested/register/%s", contractAddrHex), 
		bytes.NewReader(csr),
	)
	req.Header.Set(AttestationTypeHeader, qemuTDX)
	
	// Use JSON-encoded measurement map
	measurementsMap := map[string]string{
		"0": "00",
		"1": "01",
		"2": "02",
		"3": "03",
		"4": "04",
	}
	measurementsJSON, err := json.Marshal(measurementsMap)
	require.NoError(t, err)
	req.Header.Set(MeasurementHeader, string(measurementsJSON))

	// Create response recorder
	w := httptest.NewRecorder()

	// Call handler
	mux := chi.NewRouter()
	mux.Post("/api/attested/register/{contract_address}", handler.HandleRegister)
	mux.ServeHTTP(w, req)

	// Verify response
	resp := w.Result()
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	
	var result map[string]interface{}
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	err = json.Unmarshal(respBody, &result)
	require.NoError(t, err, string(respBody))
	
	// Verify response contains expected fields
	assert.Contains(t, result, "app_privkey")
	assert.Contains(t, result, "tls_cert")
	assert.Contains(t, result, "config")
	
	// Verify registry mock expectations were met
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

// Test HandleRegister - Identity Not Whitelisted
func TestHandleRegister_IdentityNotWhitelisted(t *testing.T) {
	// Create temporary storage directory
	tempDir, err := os.MkdirTemp("", "file-storage-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create logger with no output for tests
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Set up real KMS
	masterKey := make([]byte, 32)
	_, err = rand.Read(masterKey)
	require.NoError(t, err)
	kmsInstance, err := kms.NewSimpleKMS(masterKey)
	require.NoError(t, err)

	// Set up real storage factory
	storageFactory := storage.NewStorageBackendFactory(logger)

	// Set up mock registry factory (we still need this since it depends on blockchain)
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Set up test data
	contractAddr := interfaces.ContractAddress(common.HexToAddress("0123456789abcdef0123"))
	identity := [32]byte{1, 2, 3, 4}

	// Setup mock expectations for failure case
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("ComputeDCAPIdentity", mock.Anything).Return(identity, nil)
	mockRegistry.On("IsWhitelisted", identity).Return(false, nil)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	// Create test CSR
	csr, err := CreateCSR()
	require.NoError(t, err)

	// Create request with contract address in URL
	contractAddrHex := hex.EncodeToString(contractAddr[:])
	req := httptest.NewRequest(
		http.MethodPost, 
		fmt.Sprintf("/api/attested/register/%s", contractAddrHex), 
		bytes.NewReader(csr),
	)
	req.Header.Set(AttestationTypeHeader, qemuTDX)
	
	// Use JSON-encoded measurement map
	measurementsMap := map[string]string{
		"0": "00",
		"1": "01",
		"2": "02",
		"3": "03",
		"4": "04",
	}
	measurementsJSON, err := json.Marshal(measurementsMap)
	require.NoError(t, err)
	req.Header.Set(MeasurementHeader, string(measurementsJSON))

	// Create response recorder
	w := httptest.NewRecorder()

	// Call handler
	mux := chi.NewRouter()
	mux.Post("/api/attested/register/{contract_address}", handler.HandleRegister)
	mux.ServeHTTP(w, req)

	// Verify response
	resp := w.Result()
	defer resp.Body.Close()
	
	assert.Equal(t, http.StatusUnauthorized, resp.StatusCode)
	
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "identity not whitelisted")
	
	// Verify expectations
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

// Test HandleAppMetadata - Success Path
func TestHandleAppMetadata_Success(t *testing.T) {
	// Create logger with no output for tests
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Set up real KMS
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err)
	kmsInstance, err := kms.NewSimpleKMS(masterKey)
	require.NoError(t, err)

	// Set up real storage factory
	storageFactory := storage.NewStorageBackendFactory(logger)

	// Set up mock registry factory (we still need this since it depends on blockchain)
	mockRegistryFactory := new(registry.MockRegistryFactory)

	// Set up test data
	contractAddr := interfaces.ContractAddress(common.HexToAddress("0123456789abcdef0123"))

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	// Create test request with contract address in URL
	contractAddrHex := hex.EncodeToString(contractAddr[:])
	req := httptest.NewRequest(
		http.MethodGet, 
		fmt.Sprintf("/api/public/app_metadata/%s", contractAddrHex), 
		nil,
	)

	// Create response recorder
	w := httptest.NewRecorder()

	// Call handler
	mux := chi.NewRouter()
	mux.Get("/api/public/app_metadata/{contract_address}", handler.HandleAppMetadata)
	mux.ServeHTTP(w, req)

	// Verify response
	resp := w.Result()
	defer resp.Body.Close()
	
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	
	var result map[string]interface{}
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	err = json.Unmarshal(respBody, &result)
	require.NoError(t, err, string(respBody))
	
	// Verify response contains expected fields
	assert.Contains(t, result, "ca_cert")
	assert.Contains(t, result, "app_pubkey")
	assert.Contains(t, result, "attestation")
}

// Test with Real File Storage Backend for Config Template with References
func TestHandleRegister_WithFileStorage_ConfigReferences(t *testing.T) {
	// Create temporary storage directory
	tempDir, err := os.MkdirTemp("", "file-storage-references-*")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	// Create logger
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Setup real storage backend
	fileBackend, err := storage.NewFileBackend(tempDir, logger)
	require.NoError(t, err)

	// Setup real KMS
	masterKey := make([]byte, 32)
	_, err = rand.Read(masterKey)
	require.NoError(t, err)
	kmsInstance, err := kms.NewSimpleKMS(masterKey)
	require.NoError(t, err)

	// Setup mock registry
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Setup real storage factory
	storageFactory := storage.NewStorageBackendFactory(logger)

	// Setup test data
	contractAddr := interfaces.ContractAddress(common.HexToAddress("0123456789abcdef0123"))
	identity := [32]byte{1, 2, 3, 4}

	// Store configuration components in the file system
	ctx := context.Background()
	
	// Store config reference
	configData := []byte(`{"database":"postgres","port":5432}`)
	configID, err := fileBackend.Store(ctx, configData, interfaces.ConfigType)
	require.NoError(t, err)
	
	// Store secret reference
	secretData := []byte(`{"username":"admin","password":"secure123"}`)
	secretID, err := fileBackend.Store(ctx, secretData, interfaces.SecretType)
	require.NoError(t, err)
	
	// Create config template with references
	configTemplate := []byte(fmt.Sprintf(`{
		"app": "test-application",
		"version": "1.0",
		"database_config": "__CONFIG_REF_%x",
		"credentials": "__SECRET_REF_%x"
	}`, configID, secretID))
	
	// Store the template
	configHash, err := fileBackend.Store(ctx, configTemplate, interfaces.ConfigType)
	require.NoError(t, err)

	// Setup mock expectations
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("ComputeDCAPIdentity", mock.Anything).Return(identity, nil)
	mockRegistry.On("IsWhitelisted", identity).Return(true, nil)
	mockRegistry.On("IdentityConfigMap", identity).Return([32]byte(configHash), nil)
	mockRegistry.On("AllStorageBackends").Return([]string{fileBackend.LocationURI()}, nil)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	// Create test CSR
	csr, err := CreateCSR()
	require.NoError(t, err)

	// Create request with contract address in URL
	contractAddrHex := hex.EncodeToString(contractAddr[:])
	req := httptest.NewRequest(
		http.MethodPost, 
		fmt.Sprintf("/api/attested/register/%s", contractAddrHex), 
		bytes.NewReader(csr),
	)
	req.Header.Set(AttestationTypeHeader, qemuTDX)
	
	// Use JSON-encoded measurement map
	measurementsMap := map[string]string{
		"0": "00",
		"1": "01",
		"2": "02",
		"3": "03",
		"4": "04",
	}
	measurementsJSON, err := json.Marshal(measurementsMap)
	require.NoError(t, err)
	req.Header.Set(MeasurementHeader, string(measurementsJSON))

	// Create response recorder
	w := httptest.NewRecorder()

	// Call handler
	mux := chi.NewRouter()
	mux.Post("/api/attested/register/{contract_address}", handler.HandleRegister)
	mux.ServeHTTP(w, req)

	// Verify response
	resp := w.Result()
	defer resp.Body.Close()
	
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	
	var result map[string]interface{}
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	err = json.Unmarshal(respBody, &result)
	require.NoError(t, err, string(respBody))
	
	// Verify response has expected fields
	assert.Contains(t, result, "app_privkey")
	assert.Contains(t, result, "tls_cert")
	assert.Contains(t, result, "config")
	
	// The config should contain the resolved references
	configStr, ok := result["config"].(string)
	assert.True(t, ok)
	assert.Contains(t, configStr, "database")
	assert.Contains(t, configStr, "username")
	
	// Verify registry mock expectations were met
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

func CreateCSR() ([]byte, error) {
	  // Generate a new ECDSA private key
  privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
  if err != nil {
    fmt.Println("Error generating private key:", err)
    return nil, err
  }

  // Create a CSR template
  csrTemplate := x509.CertificateRequest{
    Subject: pkix.Name{
      CommonName:   "example.com",
      Organization: []string{"Example Organization"},
    },
    SignatureAlgorithm: x509.ECDSAWithSHA256,
  }

  // Create a CSR using the private key and template
  csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
  if err != nil {
    fmt.Println("Error creating CSR:", err)
    return nil, err
  }

  // Encode the CSR in PEM format
  csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
  return csrPEM, nil
}
