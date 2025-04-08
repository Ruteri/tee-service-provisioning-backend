package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

// TestNewHTTPRouter tests the NewHTTPRouter function
func TestNewHTTPRouter(t *testing.T) {
	// Create logger that discards output
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create mocks
	mockCertManager := new(MockCertificateManager)

	kmsInstance, err := kms.NewSimpleKMS(make([]byte, 32))
	require.NoError(t, err)

	// Create contract address
	var contractAddr interfaces.ContractAddress
	contractAddrHex := "0123456789abcdef0123456789abcdef01234567"
	contractAddrBytes, _ := hex.DecodeString(contractAddrHex)
	copy(contractAddr[:], contractAddrBytes[:20])

	mockRegistry := registry.NewMockRegistryClient()
	mockRegistry.SetTransactOpts()
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.SetTransactOpts()

	mockResolver := instanceutils.NewRegistryAppResolver(
		&instanceutils.LocalKMSRegistrationProvider{KMS: kmsInstance},
		mockRegistryFactory,
		time.Hour,
		logger,
	)

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
	assert.NoError(t, err)
	assert.NotNil(t, router)
	assert.Equal(t, config, router.config)
	assert.NotNil(t, router.egressServer)
	assert.NotNil(t, router.ingressServer)
	assert.NotNil(t, router.transportCache)
}

// TestHTTPRouter_handleEgressRequest tests the handleEgressRequest method
func TestHTTPRouter_handleEgressRequest(t *testing.T) {
	// Create logger that discards output
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create mocks
	mockCertManager := new(MockCertificateManager)

	kmsInstance, err := kms.NewSimpleKMS(make([]byte, 32))

	// Create contract address
	var contractAddr interfaces.ContractAddress
	contractAddrHex := "0123456789abcdef0123456789abcdef01234567"
	contractAddrBytes, _ := hex.DecodeString(contractAddrHex)
	copy(contractAddr[:], contractAddrBytes[:20])

	mockRegistry := registry.NewMockRegistryClient()
	mockRegistry.SetTransactOpts()
	testPKI, err := kmsInstance.GetPKI(contractAddr)
	require.NoError(t, err)
	mockRegistry.RegisterPKI(&testPKI)
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.SetTransactOpts()

	mockResolver := instanceutils.NewRegistryAppResolver(
		&instanceutils.LocalKMSRegistrationProvider{KMS: kmsInstance},
		mockRegistryFactory,
		time.Hour,
		logger,
	)

	// Create certificate and transport for mocking
	key, csr, err := cryptoutils.CreateCSRWithRandomKey(contractAddrHex + ".app")
	require.NoError(t, err)
	signedCert, err := kmsInstance.SignCSR(contractAddr, csr)
	require.NoError(t, err)
	cert, err := tls.X509KeyPair(signedCert, key)
	require.NoError(t, err)

	expectedResponse, err := json.Marshal(map[string]string{"message": "test successful"})
	require.NoError(t, err)

	// Set up a simple test server
	testServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write(expectedResponse)
	}))
	testServer.TLS = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}
	testServer.StartTLS()
	defer testServer.Close()

	// Extract host and port from the test server
	serverURL := testServer.URL
	serverHost := strings.TrimPrefix(serverURL, "https://")

	_, err = mockRegistry.RegisterInstanceDomainName(serverHost)
	require.NoError(t, err)

	// Create router config
	config := RouterConfig{
		DefaultAppContractAddress: contractAddr,
		CertManager:               mockCertManager,
		Resolver:                  mockResolver,
		IngressListenAddr:         ":8443",
		EgressListenAddr:          ":8080",
		Log:                       logger,
	}

	caPEMBlock, _ := pem.Decode(testPKI.Ca)
	require.NotNil(t, caPEMBlock, "Failed to decode CA PEM")

	caCert, err := x509.ParseCertificate(caPEMBlock.Bytes)
	require.NoError(t, err, "Failed to parse CA certificate")

	// Set up mock expectations
	mockCertManager.On("CACertFor", contractAddr).Return(caCert, nil).Maybe()

	// Create router
	router, err := NewHTTPRouter(config)
	assert.NoError(t, err)

	// Create test request with both target and source app set to our app
	req := httptest.NewRequest("GET", "/api/test", nil)
	req.Header.Set("X-Target-App", contractAddrHex)
	req.Header.Set("X-Source-App", contractAddrHex)
	req.Header.Set("X-Request-Type", "")

	// Create response recorder
	rr := httptest.NewRecorder()

	// Directly call the handler to avoid starting real servers
	router.handleEgressRequest(rr, req)

	resp := rr.Result()
	respBytes, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	require.Equal(t, resp.StatusCode, http.StatusOK, string(respBytes))
	require.Equal(t, respBytes, expectedResponse)
}
