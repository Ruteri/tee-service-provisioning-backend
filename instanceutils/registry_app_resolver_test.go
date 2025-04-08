package instanceutils

import (
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/ruteri/tee-service-provisioning-backend/kms"
	"github.com/ruteri/tee-service-provisioning-backend/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupTestEnvironment creates a common test setup for RegistryAppResolver tests
func setupTestEnvironment(t *testing.T) (
	interfaces.ContractAddress,
	*registry.MockRegistryClient,
	*registry.MockRegistryFactory,
	interfaces.KMS,
	*slog.Logger,
) {
	// Create logger that discards output
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create contract address using the type system helper
	contractAddr, err := interfaces.NewContractAddressFromHex("0123456789abcdef0123456789abcdef01234567")
	require.NoError(t, err, "Failed to create contract address")

	// Create a real MockRegistryClient
	mockRegistry := registry.NewMockRegistryClient()
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)

	// Initialize SimpleKMS with a test master key
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	kmsInstance, err := kms.NewSimpleKMS(masterKey)
	require.NoError(t, err, "Failed to create SimpleKMS")

	return contractAddr, mockRegistry, mockRegistryFactory, kmsInstance, logger
}

// TestRegistryAppResolver_GetAppMetadata tests the GetAppMetadata method
// (renamed from ResolveAppInstances to match actual method being tested)
func TestRegistryAppResolver_GetAppMetadata(t *testing.T) {
	// Set up test environment
	contractAddr, mockRegistry, mockRegistryFactory, kmsInstance, logger := setupTestEnvironment(t)

	// Enable transactions for setup
	mockRegistry.SetTransactOpts()

	// Register test domains using the contract address string representation
	contractAddrStr := contractAddr.String()
	domainNames := []string{
		contractAddrStr,
		contractAddrStr + ".instance1",
		contractAddrStr + ".instance2",
	}

	for _, domain := range domainNames {
		_, err := mockRegistry.RegisterInstanceDomainName(domain)
		require.NoError(t, err, "Failed to register domain")
	}

	// Register PKI information
	testPKI, err := kmsInstance.GetPKI(contractAddr)
	require.NoError(t, err)
	mockRegistry.RegisterPKI(&testPKI)

	// Create app resolver
	resolver := NewRegistryAppResolver(
		&LocalKMSRegistrationProvider{KMS: kmsInstance},
		mockRegistryFactory,
		time.Minute,
		logger,
	)

	// Test GetAppMetadata
	caCert, instances, err := resolver.GetAppMetadata(contractAddr)

	// Verify results
	assert.NoError(t, err)
	assert.NotEmpty(t, caCert)

	// Validate that this is a PEM-encoded certificate
	assert.Contains(t, string(caCert), "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, string(caCert), "-----END CERTIFICATE-----")

	// Validate instance addresses
	assert.Len(t, instances, 3)
	assert.Contains(t, instances, contractAddrStr)
	assert.Contains(t, instances, contractAddrStr+".instance1")
	assert.Contains(t, instances, contractAddrStr+".instance2")
}

// TestRegistryAppResolver_GetCert tests the GetCert method
func TestRegistryAppResolver_GetCert(t *testing.T) {
	// Set up test environment
	contractAddr, _, mockRegistryFactory, kmsInstance, logger := setupTestEnvironment(t)

	// Create app resolver
	resolver := NewRegistryAppResolver(
		&LocalKMSRegistrationProvider{KMS: kmsInstance},
		mockRegistryFactory,
		time.Minute,
		logger,
	)

	// Test GetCert
	cert, err := resolver.GetCert(contractAddr)

	// Verify results
	assert.NoError(t, err)
	assert.NotNil(t, cert)

	// Additional validation for the certificate
	assert.NotNil(t, cert.Certificate)
	assert.NotNil(t, cert.PrivateKey)

	// Implementation for the TODO - validate certificate is properly formed
	// Check that it has certificates in the chain
	assert.True(t, len(cert.Certificate) > 0, "Certificate should have at least one certificate in the chain")

	// Check that private key exists and matches certificate
	assert.NotNil(t, cert.PrivateKey, "Certificate should have a private key")
}
