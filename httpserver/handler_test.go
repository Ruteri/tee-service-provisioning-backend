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
	"github.com/ruteri/poc-tee-registry/cryptoutils"
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
	csr, err := createTestCSR()
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
	csr, err := createTestCSR()
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

// TestConfigReferenceResolution tests that the handler correctly resolves
// config and secret references in a template.
func TestConfigReferenceResolution(t *testing.T) {
	// Create temporary storage directory
	tempDir, err := os.MkdirTemp("", "reference-test-")
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

	// Set up real storage backend
	fileBackend, err := storage.NewFileBackend(tempDir, logger)
	require.NoError(t, err)

	// Set up real storage factory
	storageFactory := storage.NewStorageBackendFactory(logger)

	// Set up mock registry factory
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Set up contract address and identity
	contractAddr := interfaces.ContractAddress(common.HexToAddress("0123456789abcdef0123"))
	identity := [32]byte{1, 2, 3, 4}

	// Store test data in the storage backend
	ctx := context.Background()

	// 1. Store database config
	dbConfig := []byte(`{
		"host": "db.example.com",
		"port": 5432,
		"database": "appdb"
	}`)
	dbConfigHash, err := fileBackend.Store(ctx, dbConfig, interfaces.ConfigType)
	require.NoError(t, err)

	// 2. Store logging config
	loggingConfig := []byte(`{
		"level": "info",
		"format": "json",
		"output": "stdout"
	}`)
	loggingConfigHash, err := fileBackend.Store(ctx, loggingConfig, interfaces.ConfigType)
	require.NoError(t, err)

	// 3. Create template with references to the above items
	templateStr := fmt.Sprintf(`{
		"app": "test-application",
		"version": "1.0.0",
		"database": "__CONFIG_REF_%x",
		"logging": "__CONFIG_REF_%x",
		"settings": {
			"max_connections": 100,
			"timeout": 30
		}
	}`, dbConfigHash, loggingConfigHash)

	// Store the template
	templateBytes := []byte(templateStr)
	templateHash, err := fileBackend.Store(ctx, templateBytes, interfaces.ConfigType)
	require.NoError(t, err)

	// Set up mock expectations
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("ComputeDCAPIdentity", mock.Anything).Return(identity, nil)
	mockRegistry.On("IsWhitelisted", identity).Return(true, nil)
	mockRegistry.On("IdentityConfigMap", identity).Return([32]byte(templateHash), nil)
	mockRegistry.On("AllStorageBackends").Return([]string{fileBackend.LocationURI()}, nil)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	// Create test CSR
	csr, err := createTestCSR()
	require.NoError(t, err)

	// Create test request
	contractAddrHex := hex.EncodeToString(contractAddr[:])
	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/attested/register/%s", contractAddrHex),
		bytes.NewReader(csr),
	)
	req.Header.Set(AttestationTypeHeader, qemuTDX)

	// Set up measurements header
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

	require.Equal(t, http.StatusOK, resp.StatusCode)

	// Parse the response
	var result map[string]interface{}
	responseBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	err = json.Unmarshal(responseBody, &result)
	require.NoError(t, err)

	// Verify the config contains the resolved references
	configStr, ok := result["config"].(string)
	require.True(t, ok)

	// Parse the resolved config
	var resolvedConfig map[string]interface{}
	err = json.Unmarshal([]byte(configStr), &resolvedConfig)
	require.NoError(t, err, string(configStr))

	// Verify database config was resolved
	database, ok := resolvedConfig["database"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "db.example.com", database["host"])
	assert.Equal(t, float64(5432), database["port"])
	assert.Equal(t, "appdb", database["database"])

	// Verify logging config was resolved
	logging, ok := resolvedConfig["logging"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "info", logging["level"])
	assert.Equal(t, "json", logging["format"])
	assert.Equal(t, "stdout", logging["output"])

	// Verify original settings are still there
	settings, ok := resolvedConfig["settings"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(100), settings["max_connections"])
	assert.Equal(t, float64(30), settings["timeout"])

	// Verify original app and version fields are preserved
	assert.Equal(t, "test-application", resolvedConfig["app"])
	assert.Equal(t, "1.0.0", resolvedConfig["version"])

	// Verify mock expectations were met
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

// Helper function to create a test CSR
func createTestCSR() ([]byte, error) {
	// Generate a new ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	// Create a CSR template
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"Test Organization"},
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	// Create a CSR using the private key and template
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return nil, err
	}

	// Encode the CSR in PEM format
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})
	return csrPEM, nil
}

// TestServerSideDecryption tests that pre-encrypted secrets are correctly
// decrypted by the handler and included as plaintext in the config
func TestServerSideDecryption(t *testing.T) {
	// Create temporary storage directory
	tempDir, err := os.MkdirTemp("", "server-decryption-test-")
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

	// Setup storage factory
	storageFactory := storage.NewStorageBackendFactory(logger)

	// Setup mock registry
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Setup test data
	contractAddr := interfaces.ContractAddress{}
	copy(contractAddr[:], []byte("0123456789abcdef0123"))
	identity := [32]byte{1, 2, 3, 4}

	// Store test data
	ctx := context.Background()

	// Get the application's public key for pre-encryption
	pki, err := kmsInstance.GetPKI(contractAddr)
	require.NoError(t, err)

	// Create and pre-encrypt a secret
	secretData := []byte(`{"username":"admin","password":"secure123"}`)
	encryptedSecret, err := cryptoutils.EncryptWithPublicKey(pki.Pubkey, secretData)
	require.NoError(t, err)

	// Store the pre-encrypted secret
	secretID, err := fileBackend.Store(ctx, encryptedSecret, interfaces.SecretType)
	require.NoError(t, err)

	// Create config template with secret reference
	configTemplate := []byte(fmt.Sprintf(`{
		"app": "test-app",
		"version": "1.0.0",
		"credentials": "__SECRET_REF_%x",
		"settings": {
			"timeout": 30
		}
	}`, secretID))

	// Store the template
	configHash, err := fileBackend.Store(ctx, configTemplate, interfaces.ConfigType)
	require.NoError(t, err)

	// Setup mock expectations
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("IsWhitelisted", identity).Return(true, nil)
	mockRegistry.On("IdentityConfigMap", identity).Return([32]byte(configHash), nil)
	mockRegistry.On("AllStorageBackends").Return([]string{fileBackend.LocationURI()}, nil)
	mockRegistry.On("ComputeDCAPIdentity", mock.Anything).Return(identity, nil)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	// Create test request data
	attestationType := qemuTDX
	measurements := map[string]string{"0": "00", "1": "01"}
	csr, err := createTestCSR()
	require.NoError(t, err)

	// Call handleRegister
	_, _, processedConfig, err := handler.handleRegister(ctx, attestationType, measurements, contractAddr, csr)
	require.NoError(t, err)

	// Parse the processed config
	var config map[string]interface{}
	err = json.Unmarshal(processedConfig, &config)
	require.NoError(t, err)

	// Check that credentials have been decrypted and are now a JSON object
	credentials, ok := config["credentials"].(map[string]interface{})
	require.True(t, ok, "credentials should be a JSON object, not a string")

	// Verify the decrypted credentials match the original
	assert.Equal(t, "admin", credentials["username"])
	assert.Equal(t, "secure123", credentials["password"])

	// Verify other fields remain unchanged
	assert.Equal(t, "test-app", config["app"])
	assert.Equal(t, "1.0.0", config["version"])

	settings, ok := config["settings"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(30), settings["timeout"])

	// Verify mock expectations were met
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

// TestComplexConfigWithServerDecryption tests a complex configuration with
// multiple pre-encrypted secrets at different levels, all decrypted by the server
func TestComplexConfigWithServerDecryption(t *testing.T) {
	// Create temporary storage directory
	tempDir, err := os.MkdirTemp("", "complex-server-decryption-test-")
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

	// Setup storage factory
	storageFactory := storage.NewStorageBackendFactory(logger)

	// Setup mock registry
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Setup test data
	contractAddr := interfaces.ContractAddress{}
	copy(contractAddr[:], []byte("0123456789abcdef0123"))
	identity := [32]byte{1, 2, 3, 4}

	// Get the application's public key for pre-encryption
	pki, err := kmsInstance.GetPKI(contractAddr)
	require.NoError(t, err)

	// Store test data
	ctx := context.Background()

	// Create and pre-encrypt multiple secrets
	dbCredentials := []byte(`{"username":"dbuser","password":"dbpass123"}`)
	encryptedDbCred, err := cryptoutils.EncryptWithPublicKey(pki.Pubkey, dbCredentials)
	require.NoError(t, err)

	apiCredentials := []byte(`{"api_key":"abcdef123456","api_secret":"secretxyz"}`)
	encryptedApiCred, err := cryptoutils.EncryptWithPublicKey(pki.Pubkey, apiCredentials)
	require.NoError(t, err)

	// Store the pre-encrypted secrets
	dbCredID, err := fileBackend.Store(ctx, encryptedDbCred, interfaces.SecretType)
	require.NoError(t, err)

	apiCredID, err := fileBackend.Store(ctx, encryptedApiCred, interfaces.SecretType)
	require.NoError(t, err)

	// Store a nested config
	databaseConfig := []byte(fmt.Sprintf(`{
		"host": "db.example.com",
		"port": 5432,
		"db_name": "appdb",
		"credentials": "__SECRET_REF_%x"
	}`, dbCredID))

	dbConfigID, err := fileBackend.Store(ctx, databaseConfig, interfaces.ConfigType)
	require.NoError(t, err)

	// Create main config template with references
	configTemplate := []byte(fmt.Sprintf(`{
		"app": "complex-app",
		"version": "2.0.0",
		"database": "__CONFIG_REF_%x",
		"api": {
			"url": "https://api.example.com",
			"version": "v2",
			"credentials": "__SECRET_REF_%x"
		},
		"settings": {
			"timeout": 30,
			"retries": 3
		}
	}`, dbConfigID, apiCredID))

	// Store the template
	configHash, err := fileBackend.Store(ctx, configTemplate, interfaces.ConfigType)
	require.NoError(t, err)

	// Setup mock expectations
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("IsWhitelisted", identity).Return(true, nil)
	mockRegistry.On("IdentityConfigMap", identity).Return([32]byte(configHash), nil)
	mockRegistry.On("AllStorageBackends").Return([]string{fileBackend.LocationURI()}, nil)
	mockRegistry.On("ComputeDCAPIdentity", mock.Anything).Return(identity, nil)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	// Create test request data
	attestationType := qemuTDX
	measurements := map[string]string{"0": "00", "1": "01"}
	csr, err := createTestCSR()
	require.NoError(t, err)

	// Call handleRegister
	_, _, processedConfig, err := handler.handleRegister(ctx, attestationType, measurements, contractAddr, csr)
	require.NoError(t, err)

	// Parse the processed config
	var config map[string]interface{}
	err = json.Unmarshal(processedConfig, &config)
	require.NoError(t, err)

	// Check database section
	database, ok := config["database"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "db.example.com", database["host"])
	assert.Equal(t, float64(5432), database["port"])

	// Database credentials should be decrypted and a JSON object
	dbCreds, ok := database["credentials"].(map[string]interface{})
	require.True(t, ok, "database credentials should be a JSON object")
	assert.Equal(t, "dbuser", dbCreds["username"])
	assert.Equal(t, "dbpass123", dbCreds["password"])

	// API credentials should be decrypted and a JSON object
	api, ok := config["api"].(map[string]interface{})
	require.True(t, ok)
	apiCreds, ok := api["credentials"].(map[string]interface{})
	require.True(t, ok, "API credentials should be a JSON object")
	assert.Equal(t, "abcdef123456", apiCreds["api_key"])
	assert.Equal(t, "secretxyz", apiCreds["api_secret"])

	// Verify mock expectations were met
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

// TestDecryptionFailure tests handling of decryption failures
func TestDecryptionFailure(t *testing.T) {
	// Create temporary storage directory
	tempDir, err := os.MkdirTemp("", "decryption-failure-test-")
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

	// Setup storage factory
	storageFactory := storage.NewStorageBackendFactory(logger)

	// Setup mock registry
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Setup test data
	contractAddr := interfaces.ContractAddress{}
	copy(contractAddr[:], []byte("0123456789abcdef0123"))
	identity := [32]byte{1, 2, 3, 4}

	// Store test data
	ctx := context.Background()

	// Create wrong key to encrypt with
	wrongKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	wrongPubKeyBytes, err := x509.MarshalPKIXPublicKey(&wrongKey.PublicKey)
	require.NoError(t, err)
	wrongPubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: wrongPubKeyBytes,
	})

	// Encrypt with wrong key
	secretData := []byte(`{"username":"admin","password":"secure123"}`)
	encryptedWithWrongKey, err := cryptoutils.EncryptWithPublicKey(wrongPubKeyPEM, secretData)
	require.NoError(t, err)

	// Store the incorrectly encrypted secret
	secretID, err := fileBackend.Store(ctx, encryptedWithWrongKey, interfaces.SecretType)
	require.NoError(t, err)

	// Create config template with reference to incorrectly encrypted secret
	configTemplate := []byte(fmt.Sprintf(`{
		"app": "test-app",
		"version": "1.0.0",
		"credentials": "__SECRET_REF_%x"
	}`, secretID))

	// Store the template
	configHash, err := fileBackend.Store(ctx, configTemplate, interfaces.ConfigType)
	require.NoError(t, err)

	// Setup mock expectations
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("IsWhitelisted", identity).Return(true, nil)
	mockRegistry.On("IdentityConfigMap", identity).Return([32]byte(configHash), nil)
	mockRegistry.On("AllStorageBackends").Return([]string{fileBackend.LocationURI()}, nil)
	mockRegistry.On("ComputeDCAPIdentity", mock.Anything).Return(identity, nil)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	// Create test request data
	attestationType := qemuTDX
	measurements := map[string]string{"0": "00", "1": "01"}
	csr, err := createTestCSR()
	require.NoError(t, err)

	// Call handleRegister - decryption should fail but not crash
	_, _, _, err = handler.handleRegister(ctx, attestationType, measurements, contractAddr, csr)
	require.Error(t, err)

	// Verify mock expectations were met
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

// TestNonJSONSecret tests handling of non-JSON secret data
func TestNonJSONSecret(t *testing.T) {
	// Create temporary storage directory
	tempDir, err := os.MkdirTemp("", "non-json-secret-test-")
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

	// Setup storage factory
	storageFactory := storage.NewStorageBackendFactory(logger)

	// Setup mock registry
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Setup test data
	contractAddr := interfaces.ContractAddress{}
	copy(contractAddr[:], []byte("0123456789abcdef0123"))
	identity := [32]byte{1, 2, 3, 4}

	// Get the application's public key for pre-encryption
	pki, err := kmsInstance.GetPKI(contractAddr)
	require.NoError(t, err)

	// Store test data
	ctx := context.Background()

	// Create and pre-encrypt a plaintext secret
	plainTextSecret := []byte("This is a plaintext secret with special chars: \n \t \" \\")
	encryptedSecret, err := cryptoutils.EncryptWithPublicKey(pki.Pubkey, plainTextSecret)
	require.NoError(t, err)

	// Store the pre-encrypted secret
	secretID, err := fileBackend.Store(ctx, encryptedSecret, interfaces.SecretType)
	require.NoError(t, err)

	// Create config template with secret reference
	configTemplate := []byte(fmt.Sprintf(`{
		"app": "test-app",
		"version": "1.0.0",
		"api_token": "__SECRET_REF_%x"
	}`, secretID))

	// Store the template
	configHash, err := fileBackend.Store(ctx, configTemplate, interfaces.ConfigType)
	require.NoError(t, err)

	// Setup mock expectations
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("IsWhitelisted", identity).Return(true, nil)
	mockRegistry.On("IdentityConfigMap", identity).Return([32]byte(configHash), nil)
	mockRegistry.On("AllStorageBackends").Return([]string{fileBackend.LocationURI()}, nil)
	mockRegistry.On("ComputeDCAPIdentity", mock.Anything).Return(identity, nil)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	// Create test request data
	attestationType := qemuTDX
	measurements := map[string]string{"0": "00", "1": "01"}
	csr, err := createTestCSR()
	require.NoError(t, err)

	// Call handleRegister
	_, _, processedConfig, err := handler.handleRegister(ctx, attestationType, measurements, contractAddr, csr)
	require.NoError(t, err)

	// Parse the processed config
	var config map[string]interface{}
	err = json.Unmarshal(processedConfig, &config)
	require.Error(t, err)

	// Verify mock expectations were met
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}
