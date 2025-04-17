package provisioner

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
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-chi/chi/v5"
	"github.com/ruteri/tee-service-provisioning-backend/api"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/ruteri/tee-service-provisioning-backend/kms"
	"github.com/ruteri/tee-service-provisioning-backend/registry"
	"github.com/ruteri/tee-service-provisioning-backend/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// setupTestEnvironment creates common test components
func setupTestEnvironment(t *testing.T) (string, *slog.Logger, interfaces.KMS, interfaces.StorageBackendFactory, *storage.FileBackend) {
	// Create temporary storage directory
	tempDir, err := os.MkdirTemp("", "tee-test-")
	require.NoError(t, err)

	// Create logger with no output for tests
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Set up real KMS
	masterKey := make([]byte, 32)
	_, err = rand.Read(masterKey)
	require.NoError(t, err)
	kmsInstance, err := kms.NewSimpleKMS(masterKey)
	require.NoError(t, err)

	// Set up real storage factory
	storageFactory := storage.NewStorageBackendFactory(logger, nil)

	// Initialize a file storage backend
	fileBackend, err := storage.NewFileBackend(tempDir, logger)
	require.NoError(t, err)

	return tempDir, logger, kmsInstance, storageFactory, fileBackend
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

// Test HandleRegister - Success Path
// TODO: test allowed identity but empty config
func TestHandleRegister_Success(t *testing.T) {
	tempDir, logger, kmsInstance, storageFactory, fileBackend := setupTestEnvironment(t)
	defer os.RemoveAll(tempDir)

	// Set up mock registry factory
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Set up test data
	contractAddr, _ := interfaces.NewContractAddressFromHex("0123456789abcdef0123")
	identity := [32]byte{1, 2, 3, 4}
	configTemplate := []byte(`{"app":"test","settings":{"timeout":30}}`)

	// Store the config in file storage
	configHash, err := fileBackend.Store(context.Background(), configTemplate, interfaces.ConfigType)
	require.NoError(t, err)

	// Setup mock expectations for registry
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("ComputeDCAPIdentity", mock.Anything).Return(identity, nil)
	mockRegistry.On("IdentityAllowed", identity, mock.Anything).Return(true, nil)
	mockRegistry.On("IdentityConfigMap", identity, mock.Anything).Return([32]byte(configHash), nil)
	mockRegistry.On("AllStorageBackends").Return([]string{fileBackend.LocationURI()}, nil)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	// Create test CSR
	_, csr, err := cryptoutils.CreateCSRWithRandomKey(interfaces.NewAppCommonName(contractAddr).String())
	require.NoError(t, err)

	// Create request with contract address in URL
	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/attested/register/%s", contractAddr.String()),
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
	tempDir, logger, kmsInstance, storageFactory, _ := setupTestEnvironment(t)
	defer os.RemoveAll(tempDir)

	// Set up mock registry factory
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Set up test data
	contractAddr, _ := interfaces.NewContractAddressFromHex("0123456789abcdef0123")
	identity := [32]byte{1, 2, 3, 4}

	// Setup mock expectations for failure case
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("ComputeDCAPIdentity", mock.Anything).Return(identity, nil)
	mockRegistry.On("IdentityAllowed", identity, mock.Anything).Return(false, nil)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	// Create test CSR
	_, csr, err := cryptoutils.CreateCSRWithRandomKey(interfaces.NewAppCommonName(contractAddr).String())
	require.NoError(t, err)

	// Create request with contract address in URL
	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/attested/register/%s", contractAddr.String()),
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

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "identity not allowed")

	// Verify expectations
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

// Test HandleRegister - Config Not Mapped
func TestHandleRegister_ConfigNotMapped(t *testing.T) {
	tempDir, logger, kmsInstance, storageFactory, _ := setupTestEnvironment(t)
	defer os.RemoveAll(tempDir)

	// Set up mock registry factory
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Set up test data
	contractAddr, _ := interfaces.NewContractAddressFromHex("0123456789abcdef0123")
	identity := [32]byte{1, 2, 3, 4}

	// Setup mock expectations for failure case
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("ComputeDCAPIdentity", mock.Anything).Return(identity, nil)
	mockRegistry.On("IdentityAllowed", identity, mock.Anything).Return(true, nil)
	mockRegistry.On("IdentityConfigMap", identity, mock.Anything).Return([32]byte{}, errors.New("No mapping"))

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	// Create test CSR
	_, csr, err := cryptoutils.CreateCSRWithRandomKey(interfaces.NewAppCommonName(contractAddr).String())
	require.NoError(t, err)

	// Create request with contract address in URL
	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/attested/register/%s", contractAddr.String()),
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

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "config lookup error")

	// Verify expectations
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

// Test HandleRegister - Empty Config
func TestHandleRegister_EmptyConfig(t *testing.T) {
	tempDir, logger, kmsInstance, storageFactory, _ := setupTestEnvironment(t)
	defer os.RemoveAll(tempDir)

	// Set up mock registry factory
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Set up test data
	contractAddr, _ := interfaces.NewContractAddressFromHex("0123456789abcdef0123")
	identity := [32]byte{1, 2, 3, 4}

	// Setup mock expectations for failure case
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("ComputeDCAPIdentity", mock.Anything).Return(identity, nil)
	mockRegistry.On("IdentityAllowed", identity, mock.Anything).Return(true, nil)
	mockRegistry.On("IdentityConfigMap", identity, mock.Anything).Return([32]byte{}, nil)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	// Create test CSR
	_, csr, err := cryptoutils.CreateCSRWithRandomKey(interfaces.NewAppCommonName(contractAddr).String())
	require.NoError(t, err)

	// Create request with contract address in URL
	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/attested/register/%s", contractAddr.String()),
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

	var result map[string]interface{}
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	err = json.Unmarshal(respBody, &result)
	require.NoError(t, err, string(respBody))

	// Verify response contains expected fields
	assert.Contains(t, result, "app_privkey")
	assert.Contains(t, result, "tls_cert")
	assert.Contains(t, result, "config")
	assert.Equal(t, result["config"], nil)

	// Verify registry mock expectations were met
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

// Test HandleAppMetadata - Success Path
func TestHandleAppMetadata_Success(t *testing.T) {
	_, logger, kmsInstance, storageFactory, _ := setupTestEnvironment(t)

	// Set up mock registry factory
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := registry.NewMockRegistryClient()
	mockRegistry.SetTransactOpts()

	// Set up test data
	contractAddr, _ := interfaces.NewContractAddressFromHex("0123456789abcdef0123")

	// Setup mock expectations for failure case
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	testPKI, err := kmsInstance.GetPKI(contractAddr)
	require.NoError(t, err)
	mockRegistry.RegisterPKI(&testPKI)
	_, err = mockRegistry.RegisterInstanceDomainName("test.app")
	require.NoError(t, err)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	// Create test request with contract address in URL
	req := httptest.NewRequest(
		http.MethodGet,
		fmt.Sprintf("/api/public/app_metadata/%s", contractAddr.String()),
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

	var result api.MetadataResponse
	respBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	err = json.Unmarshal(respBody, &result)
	require.NoError(t, err, string(respBody))

	// Verify response contains expected fields
	assert.NoError(t, cryptoutils.CACert(result.CACert).Validate())
	assert.Equal(t, []interfaces.AppDomainName{"test.app"}, result.DomainNames)
}

// TestConfigReferenceResolution tests that the handler correctly resolves
// config and secret references in a template.
func TestConfigReferenceResolution(t *testing.T) {
	tempDir, logger, kmsInstance, storageFactory, fileBackend := setupTestEnvironment(t)
	defer os.RemoveAll(tempDir)

	// Set up mock registry factory
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Set up contract address and identity
	contractAddr, _ := interfaces.NewContractAddressFromHex("0123456789abcdef0123")
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
		"database": "__CONFIG_REF_%s",
		"logging": "__CONFIG_REF_%s",
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
	mockRegistry.On("IdentityAllowed", identity, mock.Anything).Return(true, nil)
	mockRegistry.On("IdentityConfigMap", identity, mock.Anything).Return([32]byte(templateHash), nil)
	mockRegistry.On("AllStorageBackends").Return([]string{fileBackend.LocationURI()}, nil)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	// Create test CSR
	_, csr, err := cryptoutils.CreateCSRWithRandomKey(interfaces.NewAppCommonName(contractAddr).String())
	require.NoError(t, err)

	// Create test request
	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/attested/register/%s", contractAddr.String()),
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
	responseBody, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.Equal(t, http.StatusOK, resp.StatusCode, string(responseBody))

	// Parse the response
	var result api.RegistrationResponse
	err = json.Unmarshal(responseBody, &result)
	require.NoError(t, err)

	// Parse the resolved config
	var resolvedConfig map[string]interface{}
	err = json.Unmarshal(result.Config, &resolvedConfig)
	require.NoError(t, err, string(result.Config))

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

	// Verify original fields are preserved
	settings, ok := resolvedConfig["settings"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, float64(100), settings["max_connections"])
	assert.Equal(t, float64(30), settings["timeout"])
	assert.Equal(t, "test-application", resolvedConfig["app"])
	assert.Equal(t, "1.0.0", resolvedConfig["version"])

	// Verify mock expectations
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

// TestServerSideDecryption tests that pre-encrypted secrets are correctly
// decrypted by the handler and included as plaintext in the config
func TestServerSideDecryption(t *testing.T) {
	tempDir, logger, kmsInstance, storageFactory, fileBackend := setupTestEnvironment(t)
	defer os.RemoveAll(tempDir)

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
		"credentials": "__SECRET_REF_%s",
		"settings": {
			"timeout": 30
		}
	}`, secretID))

	// Store the template
	configHash, err := fileBackend.Store(ctx, configTemplate, interfaces.ConfigType)
	require.NoError(t, err)

	// Setup mock expectations
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("IdentityAllowed", identity, mock.Anything).Return(true, nil)
	mockRegistry.On("IdentityConfigMap", identity, mock.Anything).Return([32]byte(configHash), nil)
	mockRegistry.On("AllStorageBackends").Return([]string{fileBackend.LocationURI()}, nil)
	mockRegistry.On("ComputeDCAPIdentity", mock.Anything).Return(identity, nil)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	// Create test request data
	_, csr, err := cryptoutils.CreateCSRWithRandomKey(interfaces.NewAppCommonName(contractAddr).String())
	require.NoError(t, err)

	// Call handleRegister directly
	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/attested/register/%s", contractAddr.String()),
		bytes.NewReader(csr),
	)
	req.Header.Set(cryptoutils.AttestationTypeHeader, cryptoutils.DCAPAttestation.StringID)
	req.Header.Set(cryptoutils.MeasurementHeader, getTestMeasurements())
	resp, err := handler.handleRegister(req, contractAddr, csr)
	require.NoError(t, err)
	require.NotNil(t, resp.AppPrivkey)

	// Parse the processed config
	var config map[string]interface{}
	err = json.Unmarshal(resp.Config, &config)
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

	// Verify mock expectations
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

// TestComplexConfigWithServerDecryption tests a complex configuration with
// multiple pre-encrypted secrets at different levels
func TestComplexConfigWithServerDecryption(t *testing.T) {
	tempDir, logger, kmsInstance, storageFactory, fileBackend := setupTestEnvironment(t)
	defer os.RemoveAll(tempDir)

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
		"credentials": "__SECRET_REF_%s"
	}`, dbCredID))

	dbConfigID, err := fileBackend.Store(ctx, databaseConfig, interfaces.ConfigType)
	require.NoError(t, err)

	// Create main config template with references
	configTemplate := []byte(fmt.Sprintf(`{
		"app": "complex-app",
		"version": "2.0.0",
		"database": "__CONFIG_REF_%s",
		"api": {
			"url": "https://api.example.com",
			"version": "v2",
			"credentials": "__SECRET_REF_%s"
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
	mockRegistry.On("IdentityAllowed", identity, mock.Anything).Return(true, nil)
	mockRegistry.On("IdentityConfigMap", identity, mock.Anything).Return([32]byte(configHash), nil)
	mockRegistry.On("AllStorageBackends").Return([]string{fileBackend.LocationURI()}, nil)
	mockRegistry.On("ComputeDCAPIdentity", mock.Anything).Return(identity, nil)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	// Create test request data
	_, csr, err := cryptoutils.CreateCSRWithRandomKey(interfaces.NewAppCommonName(contractAddr).String())
	require.NoError(t, err)

	// Call handleRegister
	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/attested/register/%s", contractAddr.String()),
		bytes.NewReader(csr),
	)
	req.Header.Set(cryptoutils.AttestationTypeHeader, cryptoutils.DCAPAttestation.StringID)
	req.Header.Set(cryptoutils.MeasurementHeader, getTestMeasurements())
	resp, err := handler.handleRegister(req, contractAddr, csr)
	require.NoError(t, err)

	// Parse the processed config
	var config map[string]interface{}
	err = json.Unmarshal(resp.Config, &config)
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

	// Verify mock expectations
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

// TestDecryptionFailure tests handling of decryption failures
func TestDecryptionFailure(t *testing.T) {
	tempDir, logger, kmsInstance, storageFactory, fileBackend := setupTestEnvironment(t)
	defer os.RemoveAll(tempDir)

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
		"credentials": "__SECRET_REF_%s"
	}`, secretID))

	// Store the template
	configHash, err := fileBackend.Store(ctx, configTemplate, interfaces.ConfigType)
	require.NoError(t, err)

	// Setup mock expectations
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("IdentityAllowed", identity, mock.Anything).Return(true, nil)
	mockRegistry.On("IdentityConfigMap", identity, mock.Anything).Return([32]byte(configHash), nil)
	mockRegistry.On("AllStorageBackends").Return([]string{fileBackend.LocationURI()}, nil)
	mockRegistry.On("ComputeDCAPIdentity", mock.Anything).Return(identity, nil)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	// Create test request data
	_, csr, err := cryptoutils.CreateCSRWithRandomKey(interfaces.NewAppCommonName(contractAddr).String())
	require.NoError(t, err)

	// Call handleRegister
	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/attested/register/%s", contractAddr.String()),
		bytes.NewReader(csr),
	)
	req.Header.Set(cryptoutils.AttestationTypeHeader, cryptoutils.DCAPAttestation.StringID)
	req.Header.Set(cryptoutils.MeasurementHeader, getTestMeasurements())
	_, err = handler.handleRegister(req, contractAddr, csr)
	require.Error(t, err)

	// Verify mock expectations
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

// TestNonJSONSecret tests handling of non-JSON secret data
func TestNonJSONSecret(t *testing.T) {
	tempDir, logger, kmsInstance, storageFactory, fileBackend := setupTestEnvironment(t)
	defer os.RemoveAll(tempDir)

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
		"api_token": "__SECRET_REF_%s"
	}`, secretID))

	// Store the template
	configHash, err := fileBackend.Store(ctx, configTemplate, interfaces.ConfigType)
	require.NoError(t, err)

	// Setup mock expectations
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("IdentityAllowed", identity, mock.Anything).Return(true, nil)
	mockRegistry.On("IdentityConfigMap", identity, mock.Anything).Return([32]byte(configHash), nil)
	mockRegistry.On("AllStorageBackends").Return([]string{fileBackend.LocationURI()}, nil)
	mockRegistry.On("ComputeDCAPIdentity", mock.Anything).Return(identity, nil)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

	_, csr, err := cryptoutils.CreateCSRWithRandomKey(interfaces.NewAppCommonName(contractAddr).String())
	require.NoError(t, err)

	// Call handleRegister
	req := httptest.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/attested/register/%s", contractAddr.String()),
		bytes.NewReader(csr),
	)
	req.Header.Set(cryptoutils.AttestationTypeHeader, cryptoutils.DCAPAttestation.StringID)
	req.Header.Set(cryptoutils.MeasurementHeader, getTestMeasurements())
	resp, err := handler.handleRegister(req, contractAddr, csr)
	require.NoError(t, err)

	// Parse the processed config
	var config map[string]interface{}
	err = json.Unmarshal(resp.Config, &config)
	require.Error(t, err)

	// Verify mock expectations
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}

// TestHandleRegister_WithOperatorSignature tests the registration process
// when an operator signature is included in the CSR.
func TestHandleRegister_WithOperatorSignature(t *testing.T) {
	tempDir, logger, kmsInstance, storageFactory, fileBackend := setupTestEnvironment(t)
	defer os.RemoveAll(tempDir)

	// Set up mock registry factory
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Set up test data
	contractAddr, _ := interfaces.NewContractAddressFromHex("0123456789abcdef0123")
	identity := [32]byte{1, 2, 3, 4}
	configTemplate := []byte(`{"app":"test","settings":{"timeout":30}}`)

	// Store the config in file storage
	ctx := context.Background()
	configHash, err := fileBackend.Store(ctx, configTemplate, interfaces.ConfigType)
	require.NoError(t, err)

	// Setup mock expectations for registry - note the operatorAddress parameter
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("IdentityAllowed", identity, mock.Anything).Return(true, nil)
	mockRegistry.On("ComputeDCAPIdentity", mock.Anything).Return(identity, nil)
	mockRegistry.On("AllStorageBackends").Return([]string{fileBackend.LocationURI()}, nil)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

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

	mockRegistry.On("IdentityConfigMap", identity, operatorAddress).Return([32]byte(configHash), nil)

	// Create a new CSR template with the signature extension
	templateWithSig := template
	templateWithSig.ExtraExtensions = []pkix.Extension{
		{
			Id:    api.OIDOperatorSignature,
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
		fmt.Sprintf("/api/attested/register/%s", contractAddr.String()),
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

// TestHandleRegister_UnauthorizedOperator tests rejection when an operator
// without necessary permissions attempts to sign a CSR
func TestHandleRegister_UnauthorizedOperator(t *testing.T) {
	tempDir, logger, kmsInstance, storageFactory, _ := setupTestEnvironment(t)
	defer os.RemoveAll(tempDir)

	// Set up mock registry factory
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistry := new(registry.MockRegistry)

	// Set up test data
	contractAddr, _ := interfaces.NewContractAddressFromHex("0123456789abcdef0123")
	identity := [32]byte{1, 2, 3, 4}

	// Setup mock expectations - operator is not authorized for this identity
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.On("IdentityAllowed", identity, mock.Anything).Return(true, nil)
	mockRegistry.On("ComputeDCAPIdentity", mock.Anything).Return(identity, nil)

	// Create handler
	handler := NewHandler(kmsInstance, storageFactory, mockRegistryFactory, logger)

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
	mockRegistry.On("IdentityConfigMap", identity, operatorAddress).Return([32]byte{}, errors.New("Operator not authorized"))

	// Sign the CSR's public key info
	operatorSignature, err := crypto.Sign(cryptoutils.DERPubkeyHash(parsedCSR.RawSubjectPublicKeyInfo), operatorKey)
	require.NoError(t, err)

	// Create CSR with signature extension
	templateWithSig := template
	templateWithSig.ExtraExtensions = []pkix.Extension{
		{
			Id:    api.OIDOperatorSignature,
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
		fmt.Sprintf("/api/attested/register/%s", contractAddr.String()),
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

	assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Contains(t, string(body), "config lookup error")

	// Verify expectations
	mockRegistryFactory.AssertExpectations(t)
	mockRegistry.AssertExpectations(t)
}
