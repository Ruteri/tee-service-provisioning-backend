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
	domainNames := []string{
		"instance1.domain",
		"instance2.someotherdomain",
		"instance3.yetanother",
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
		mockRegistryFactory,
		time.Minute,
		logger,
	)

	// Test GetAppMetadata
	resp, err := resolver.GetAppMetadata(contractAddr)

	// Verify results
	assert.NoError(t, err)
	assert.NotEmpty(t, resp.CACert)

	// Validate that this is a PEM-encoded certificate
	assert.Contains(t, string(resp.CACert), "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, string(resp.CACert), "-----END CERTIFICATE-----")

	// Validate instance addresses
	assert.Len(t, resp.DomainNames, 3)
	for _, dn := range domainNames {
		assert.Contains(t, resp.DomainNames, interfaces.AppDomainName(dn))
	}
}
