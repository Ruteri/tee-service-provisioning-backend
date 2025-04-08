package instanceutils

import (
	"encoding/hex"
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

// TestRegistryAppResolver_ResolveAppInstances tests the ResolveAppInstances method
func TestRegistryAppResolver_ResolveAppInstances(t *testing.T) {
	// Create logger that discards output
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create contract address
	var contractAddr interfaces.ContractAddress
	contractAddrHex := "0123456789abcdef0123456789abcdef01234567"
	contractAddrBytes, _ := hex.DecodeString(contractAddrHex)
	copy(contractAddr[:], contractAddrBytes[:20])

	// Create a real MockRegistryClient instead of a mock
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

	// Register test domains in the registry
	mockRegistry.SetTransactOpts() // Enable transactions for setup

	// Register test domains
	domainNames := []string{
		contractAddrHex,
		contractAddrHex + ".instance1",
		contractAddrHex + ".instance2",
	}

	for _, domain := range domainNames {
		_, err := mockRegistry.RegisterInstanceDomainName(domain)
		require.NoError(t, err, "Failed to register domain")
	}

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

	caCert, instances, err := resolver.GetAppMetadata(contractAddr)
	assert.NoError(t, err)
	assert.NotEmpty(t, caCert)

	// Validate that this is a PEM-encoded certificate
	assert.True(t, len(caCert) > 0)
	assert.Contains(t, string(caCert), "-----BEGIN CERTIFICATE-----")
	assert.Contains(t, string(caCert), "-----END CERTIFICATE-----")

	assert.Len(t, instances, 3)
	assert.Contains(t, instances, contractAddrHex)
	assert.Contains(t, instances, contractAddrHex+".instance1")
	assert.Contains(t, instances, contractAddrHex+".instance2")
}

// TestRegistryAppResolver_GetCert tests the GetCert method
func TestRegistryAppResolver_GetCert(t *testing.T) {
	// Create logger that discards output
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Create contract address
	var contractAddr interfaces.ContractAddress
	contractAddrHex := "0123456789abcdef0123456789abcdef01234567"
	contractAddrBytes, _ := hex.DecodeString(contractAddrHex)
	copy(contractAddr[:], contractAddrBytes[:20])

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

	// Create app resolver
	resolver := NewRegistryAppResolver(
		&LocalKMSRegistrationProvider{KMS: kmsInstance},
		mockRegistryFactory,
		time.Minute,
		logger,
	)

	// Test GetCert
	cert, err := resolver.GetCert(contractAddr)
	assert.NoError(t, err)
	assert.NotNil(t, cert)

	// TODO: make sure cert is valid and signed by the CA
}
