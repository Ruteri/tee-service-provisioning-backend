package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ruteri/tee-service-provisioning-backend/instanceutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/ruteri/tee-service-provisioning-backend/kms"
	"github.com/ruteri/tee-service-provisioning-backend/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// IntegrationTestSuite tests the complete flow of request routing
// through the TEE instance communication system using real KMS and MockRegistryClient
func TestIntegration_RequestRoutingWithRealKMS(t *testing.T) {
	// Skip this test in normal test runs unless explicitly enabled
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create logger that discards output
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create contract addresses for source and target apps
	var sourceAppAddr, targetAppAddr interfaces.ContractAddress
	sourceAppHex := "1111111111111111111111111111111111111111"
	targetAppHex := "2222222222222222222222222222222222222222"

	sourceAppBytes, _ := hex.DecodeString(sourceAppHex)
	targetAppBytes, _ := hex.DecodeString(targetAppHex)

	copy(sourceAppAddr[:], sourceAppBytes[:20])
	copy(targetAppAddr[:], targetAppBytes[:20])

	// Initialize SimpleKMS with a test master key
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	kmsInstance, err := kms.NewSimpleKMS(masterKey)
	require.NoError(t, err, "Failed to create SimpleKMS")

	// Create a real MockRegistryClient
	mockRegistry := registry.NewMockRegistryClient()
	mockRegistry.SetTransactOpts()
	testTargetPKI, err := kmsInstance.GetPKI(targetAppAddr)
	require.NoError(t, err)
	mockRegistry.RegisterPKI(&testTargetPKI)
	testSourcePKI, err := kmsInstance.GetPKI(sourceAppAddr)
	require.NoError(t, err)
	mockRegistry.RegisterPKI(&testSourcePKI)

	mockRegistryFactory := new(registry.MockRegistryFactory)
	_, err = mockRegistry.RegisterInstanceDomainName("127.0.0.1:11234")
	mockRegistryFactory.On("RegistryFor", sourceAppAddr).Return(mockRegistry, nil)
	mockRegistryFactory.On("RegistryFor", targetAppAddr).Return(mockRegistry, nil)

	// Setup a backend service to receive routed requests
	backendHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"success","message":"Request received by backend"}`))
	})
	backendServer := httptest.NewServer(backendHandler)
	defer backendServer.Close()

	appResolver := instanceutils.NewRegistryAppResolver(
		&instanceutils.LocalKMSRegistrationProvider{KMS: kmsInstance},
		mockRegistryFactory,
		0,
		logger,
	)

	ingressCertManager, err := NewAppCertificateManager(
		appResolver,
		targetAppAddr,
		logger,
	)

	// Create router config
	ingressConfig := RouterConfig{
		DefaultAppContractAddress: targetAppAddr,
		CertManager:               ingressCertManager,
		Resolver:                  nil,
		IngressListenAddr:         "127.0.0.1:11234",
		EgressListenAddr:          ":0", // Let the OS pick a port
		Routes: map[interfaces.ContractAddress]string{
			sourceAppAddr: backendServer.URL,
		},
		PublicEndpoint: backendServer.URL,
		RequestTimeout: 5 * time.Second,
		Log:            logger,
	}

	// Create router with real dependencies
	ingressRouter, err := NewHTTPRouter(ingressConfig)
	assert.NoError(t, err)

	go ingressRouter.RunInBackground()
	defer ingressRouter.Shutdown(context.TODO())

	mockResolver := instanceutils.NewRegistryAppResolver(
		&instanceutils.LocalKMSRegistrationProvider{KMS: kmsInstance},
		mockRegistryFactory,
		time.Hour,
		logger,
	)

	egressCertManager, err := NewAppCertificateManager(
		appResolver,
		sourceAppAddr,
		logger,
	)

	// Create router config
	egressConfig := RouterConfig{
		DefaultAppContractAddress: sourceAppAddr,
		CertManager:               egressCertManager,
		Resolver:                  mockResolver,
		IngressListenAddr:         ":0", // Let the OS pick a port
		EgressListenAddr:          ":0", // Let the OS pick a port
		Routes:                    nil,
		PublicEndpoint:            "",
		RequestTimeout:            5 * time.Second,
		Log:                       logger,
	}

	// Create router with real dependencies
	egressRouter, err := NewHTTPRouter(egressConfig)
	assert.NoError(t, err)

	// Test routing an egress request to the target app
	egressHandler := http.HandlerFunc(egressRouter.handleEgressRequest)
	egressServer := httptest.NewServer(egressHandler)
	defer egressServer.Close()

	// Create a client
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Create a request to the egress server
	req, err := http.NewRequest("GET", egressServer.URL+"/api/test", nil)
	assert.NoError(t, err)

	// Set routing headers
	req.Header.Set("X-Source-App", sourceAppHex)
	req.Header.Set("X-Target-App", targetAppHex)
	req.Header.Set("X-Request-Type", "any")

	// Send the request
	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	// Check response
	assert.Equal(t, http.StatusOK, resp.StatusCode, string(bodyBytes))

	// Parse the response to verify it's the expected format
	var responseBody map[string]interface{}
	err = json.Unmarshal(bodyBytes, &responseBody)
	assert.NoError(t, err, "Should be valid JSON response")

	assert.Equal(t, "success", responseBody["status"], "Should have status=success")
}

// TestIntegration_BroadcastRequestWithRealKMS tests the broadcast request functionality with real KMS
func TestIntegration_BroadcastRequestWithRealKMS(t *testing.T) {
	// Skip this test in normal test runs unless explicitly enabled
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create logger that discards output
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create contract addresses
	var appAddr interfaces.ContractAddress
	appHex := "1111111111111111111111111111111111111111"
	appBytes, _ := hex.DecodeString(appHex)
	copy(appAddr[:], appBytes[:20])

	// Initialize SimpleKMS
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	kmsInstance, err := kms.NewSimpleKMS(masterKey)
	require.NoError(t, err, "Failed to create SimpleKMS")

	// Create a real MockRegistryClient
	mockRegistry := registry.NewMockRegistryClient()
	mockRegistry.SetTransactOpts()
	testPKI, err := kmsInstance.GetPKI(appAddr)
	require.NoError(t, err)
	mockRegistry.RegisterPKI(&testPKI)

	// Set up multiple backend instance servers
	instance1Handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"instance":"instance1","status":"success"}`))
	})
	instance1Server := httptest.NewServer(instance1Handler)
	defer instance1Server.Close()

	instance2Handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"instance":"instance2","status":"success"}`))
	})
	instance2Server := httptest.NewServer(instance2Handler)
	defer instance2Server.Close()

	_, err = mockRegistry.RegisterInstanceDomainName(appHex + ".app")
	require.NoError(t, err, "Failed to register app domain")

	_, err = mockRegistry.RegisterInstanceDomainName(appHex + ".instance1")
	require.NoError(t, err, "Failed to register instance1 domain")

	_, err = mockRegistry.RegisterInstanceDomainName(appHex + ".instance2")
	require.NoError(t, err, "Failed to register instance2 domain")

	caPEMBlock, _ := pem.Decode(testPKI.Ca)
	require.NotNil(t, caPEMBlock, "Failed to decode CA PEM")

	caCert, err := x509.ParseCertificate(caPEMBlock.Bytes)
	require.NoError(t, err, "Failed to parse CA certificate")

	// Create a test certificate manager
	certManager := &testCertificateManager{
		caCert: caCert,
	}

	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistryFactory.On("RegistryFor", appAddr).Return(mockRegistry, nil)

	appResolver := instanceutils.NewRegistryAppResolver(
		&instanceutils.LocalKMSRegistrationProvider{KMS: kmsInstance},
		mockRegistryFactory,
		0,
		logger,
	)

	// Create router config
	config := RouterConfig{
		DefaultAppContractAddress: appAddr,
		CertManager:               certManager,
		Resolver:                  appResolver,
		IngressListenAddr:         ":0", // Let the OS pick a port
		EgressListenAddr:          ":0", // Let the OS pick a port
		RequestTimeout:            1 * time.Second,
		Log:                       logger,
	}

	// Create router
	router, err := NewHTTPRouter(config)
	assert.NoError(t, err)

	// Create test server with the egress handler
	egressHandler := http.HandlerFunc(router.handleEgressRequest)
	server := httptest.NewServer(egressHandler)
	defer server.Close()

	// Create a request with broadcast type
	req, err := http.NewRequest("GET", server.URL+"/api/test", nil)
	assert.NoError(t, err)
	req.Header.Set("X-Source-App", appHex)
	req.Header.Set("X-Target-App", appHex)
	req.Header.Set("X-Request-Type", "all")

	// Send the request
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	assert.NoError(t, err)
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	assert.NoError(t, err)

	// Check response
	assert.Equal(t, http.StatusOK, resp.StatusCode, string(bodyBytes))

	// Decode the response body
	type ResponseData struct {
		Responses []struct {
			Instance   string          `json:"instance"`
			StatusCode int             `json:"statusCode"`
			Error      string          `json:"error,omitempty"`
			Body       json.RawMessage `json:"body,omitempty"`
		} `json:"responses"`
		Count int `json:"count"`
		Total int `json:"total"`
	}

	var responseData ResponseData
	err = json.Unmarshal(bodyBytes, &responseData)
	assert.NoError(t, err)

	// Verify the response contains data from instances
	assert.Equal(t, 3, responseData.Count)
	assert.Equal(t, 3, responseData.Total)
	assert.Len(t, responseData.Responses, 3)
}

// Test helper certificate manager implementation
type testCertificateManager struct {
	caCert *x509.Certificate
}

func (m *testCertificateManager) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return &tls.Certificate{}, nil
}

func (m *testCertificateManager) GetConfigForClient(_ *tls.ClientHelloInfo) (*tls.Config, error) {
	return &tls.Config{
		ClientAuth: tls.RequireAndVerifyClientCert,
	}, nil
}

func (m *testCertificateManager) CACertFor(_ interfaces.ContractAddress) (*x509.Certificate, error) {
	return m.caCert, nil
}
