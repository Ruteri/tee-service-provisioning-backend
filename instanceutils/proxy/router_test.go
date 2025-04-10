package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ruteri/tee-service-provisioning-backend/api"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/instanceutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/ruteri/tee-service-provisioning-backend/kms"
	"github.com/ruteri/tee-service-provisioning-backend/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// MockCertificateManager implements the CertificateManager interface for testing
type MockCertificateManager struct {
	mock.Mock
}

func (m *MockCertificateManager) GetClientCertificate(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	args := m.Called(info)
	return args.Get(0).(*tls.Certificate), args.Error(1)
}

func (m *MockCertificateManager) GetConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	args := m.Called(hello)
	return args.Get(0).(*tls.Config), args.Error(1)
}

func (m *MockCertificateManager) CACertFor(contractAddr interfaces.ContractAddress) (*x509.Certificate, error) {
	args := m.Called(contractAddr)
	return args.Get(0).(*x509.Certificate), args.Error(1)
}

// MockInstanceResolver implements the InstanceResolver interface for testing
type MockInstanceResolver struct {
	mock.Mock
}

func (m *MockInstanceResolver) GetAppMetadata(contractAddr interfaces.ContractAddress) ([]string, error) {
	args := m.Called(contractAddr)
	return args.Get(0).([]string), args.Error(1)
}

// setupTestEnvironment creates a common test setup for HTTPRouter tests
func setupTestEnvironment(t *testing.T) (
	interfaces.ContractAddress,
	*MockCertificateManager,
	api.MetadataProvider,
	interfaces.KMS,
	*registry.MockRegistryClient,
	*slog.Logger,
) {
	// Create logger that discards output
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create contract address using type system helper
	contractAddr, err := interfaces.NewContractAddressFromHex("0123456789abcdef0123456789abcdef01234567")
	require.NoError(t, err, "Failed to create contract address")

	// Create mocks
	mockCertManager := new(MockCertificateManager)

	// Create KMS and registry
	kmsInstance, err := kms.NewSimpleKMS(make([]byte, 32))
	require.NoError(t, err, "Failed to create KMS")

	mockRegistry := registry.NewMockRegistryClient()
	mockRegistry.SetTransactOpts()

	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)

	// Create resolver
	mockResolver := instanceutils.NewRegistryAppResolver(
		mockRegistryFactory,
		time.Hour,
		logger,
	)

	return contractAddr, mockCertManager, mockResolver, kmsInstance, mockRegistry, logger
}

// TestNewHTTPRouter tests the NewHTTPRouter function
func TestNewHTTPRouter(t *testing.T) {
	// Setup test environment
	contractAddr, mockCertManager, mockResolver, _, _, logger := setupTestEnvironment(t)

	// Create router config
	config := RouterConfig{
		DefaultAppContractAddress: contractAddr,
		CertManager:               mockCertManager,
		Resolver:                  mockResolver,
		IngressListenAddr:         ":8443",
		EgressListenAddr:          ":8080",
		Routes: map[interfaces.ContractAddress]string{
			contractAddr: "http://localhost:9000",
		},
		PublicEndpoint: "http://localhost:8000",
		RequestTimeout: 30 * time.Second,
		Log:            logger,
	}

	// Create router
	router, err := NewHTTPRouter(config)

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, router)
	assert.Equal(t, config, router.config)
	assert.NotNil(t, router.egressServer)
	assert.NotNil(t, router.ingressServer)
	assert.NotNil(t, router.transportCache)
}

// setupTestServer creates a test HTTPS server with proper TLS configuration
func setupTestServer(t *testing.T, kmsInstance interfaces.KMS, contractAddr interfaces.ContractAddress) (*httptest.Server, string) {
	// Create certificate for test server
	commonName := contractAddr.String() + ".app"
	key, csr, err := cryptoutils.CreateCSRWithRandomKey(commonName)
	require.NoError(t, err, "Failed to create CSR")

	signedCert, err := kmsInstance.SignCSR(contractAddr, csr)
	require.NoError(t, err, "Failed to sign CSR")

	cert, err := tls.X509KeyPair(signedCert, key)
	require.NoError(t, err, "Failed to create X509 key pair")

	// Prepare test response
	expectedResponse, err := json.Marshal(map[string]string{"message": "test successful"})
	require.NoError(t, err, "Failed to marshal JSON response")

	// Create test server
	testServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(expectedResponse)
	}))

	testServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	testServer.StartTLS()

	// Extract host from the test server URL
	serverHost := strings.TrimPrefix(testServer.URL, "https://")

	return testServer, serverHost
}

// TestHTTPRouter_handleEgressRequest tests the handleEgressRequest method
func TestHTTPRouter_handleEgressRequest(t *testing.T) {
	// Setup test environment
	contractAddr, mockCertManager, mockResolver, kmsInstance, mockRegistry, logger := setupTestEnvironment(t)

	// Get PKI information for CA certificate
	testPKI, err := kmsInstance.GetPKI(contractAddr)
	require.NoError(t, err, "Failed to get PKI")
	mockRegistry.RegisterPKI(&testPKI)

	// Setup test server
	testServer, serverHost := setupTestServer(t, kmsInstance, contractAddr)
	defer testServer.Close()

	// Register domain name in registry
	_, err = mockRegistry.RegisterInstanceDomainName(serverHost)
	require.NoError(t, err, "Failed to register domain name")

	// Parse CA certificate for mock expectations
	caCert, err := cryptoutils.NewCACert(testPKI.Ca)
	require.NoError(t, err, "Failed to parse CA certificate")

	x509CACert, err := caCert.GetX509Cert()
	require.NoError(t, err)

	// Set up mock expectations
	mockCertManager.On("CACertFor", contractAddr).Return(x509CACert, nil).Maybe()

	// Create router config
	config := RouterConfig{
		DefaultAppContractAddress: contractAddr,
		CertManager:               mockCertManager,
		Resolver:                  mockResolver,
		IngressListenAddr:         ":8443",
		EgressListenAddr:          ":8080",
		Log:                       logger,
	}

	// Create router
	router, err := NewHTTPRouter(config)
	require.NoError(t, err, "Failed to create router")

	// Create test request
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("X-Target-App", contractAddr.String())
	req.Header.Set("X-Source-App", contractAddr.String())
	req.Header.Set("X-Request-Type", "")

	// Create response recorder
	rr := httptest.NewRecorder()

	// Call handler directly
	router.handleEgressRequest(rr, req)

	// Get and verify response
	resp := rr.Result()
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "Failed to read response body")

	// Verify status code and content
	assert.Equal(t, http.StatusOK, resp.StatusCode, "HTTP status code should be 200 OK")

	// Verify expected JSON response
	expectedResponse, err := json.Marshal(map[string]string{"message": "test successful"})
	require.NoError(t, err, "Failed to marshal expected response")
	assert.Equal(t, expectedResponse, respBytes, "Response body should match expected value")
}
