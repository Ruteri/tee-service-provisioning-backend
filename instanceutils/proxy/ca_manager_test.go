package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"io"
	"log/slog"
	"testing"

	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/instanceutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/ruteri/tee-service-provisioning-backend/kms"
	"github.com/ruteri/tee-service-provisioning-backend/registry"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAppCertificateManager_WithRealKMS test the CertificateManager with real KMS
func TestAppCertificateManager_WithRealKMS(t *testing.T) {
	// Create logger that discards output
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	// Initialize SimpleKMS with a test master key
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	kmsInstance, err := kms.NewSimpleKMS(masterKey)
	require.NoError(t, err, "Failed to create SimpleKMS")

	// Create contract address
	var contractAddr interfaces.ContractAddress
	contractAddrHex := "0123456789abcdef0123456789abcdef01234567"
	contractAddrBytes, _ := hex.DecodeString(contractAddrHex)
	copy(contractAddr[:], contractAddrBytes[:20])

	// Create a real MockRegistryClient
	mockRegistry := registry.NewMockRegistryClient()
	testPKI, err := kmsInstance.GetPKI(contractAddr)
	require.NoError(t, err)
	mockRegistry.RegisterPKI(&testPKI)
	mockRegistryFactory := new(registry.MockRegistryFactory)
	mockRegistryFactory.On("RegistryFor", contractAddr).Return(mockRegistry, nil)
	mockRegistry.SetTransactOpts()

	// Create a real AppResolver
	appResolver := instanceutils.NewRegistryAppResolver(
		&instanceutils.LocalKMSRegistrationProvider{KMS: kmsInstance},
		mockRegistryFactory,
		0, // Default cache time
		logger,
	)

	// Create certificate manager
	manager, err := NewAppCertificateManager(appResolver, contractAddr, logger)
	assert.NoError(t, err)
	assert.NotNil(t, manager)

	// Test GetClientCertificate
	clientCert, err := manager.GetClientCertificate(nil)
	assert.NoError(t, err)
	assert.NotNil(t, clientCert)

	// Test GetConfigForClient
	config, err := manager.GetConfigForClient(&tls.ClientHelloInfo{ServerName: contractAddrHex + ".app"})
	assert.NoError(t, err)
	assert.NotNil(t, config)
	assert.Equal(t, tls.RequireAndVerifyClientCert, config.ClientAuth)

	// Test CACertFor
	caCert, err := manager.CACertFor(contractAddr)
	assert.NoError(t, err)
	assert.NotNil(t, caCert)

	// Test caching by calling again
	caCert2, err := manager.CACertFor(contractAddr)
	assert.NoError(t, err)
	assert.NotNil(t, caCert2)
	assert.True(t, caCert.Equal(caCert2), "Certificates should be equal from cache")
}

// TestCertificateValidation validates that the certificates produced by SimpleKMS
// can be parsed and are valid X.509 certificates
func TestCertificateValidation(t *testing.T) {
	// Initialize SimpleKMS with a test master key
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	kmsInstance, err := kms.NewSimpleKMS(masterKey)
	require.NoError(t, err, "Failed to create SimpleKMS")

	// Create contract address
	var contractAddr interfaces.ContractAddress
	contractAddrHex := "0123456789abcdef0123456789abcdef01234567"
	contractAddrBytes, _ := hex.DecodeString(contractAddrHex)
	copy(contractAddr[:], contractAddrBytes[:20])

	// Get PKI from KMS
	pki, err := kmsInstance.GetPKI(contractAddr)
	require.NoError(t, err, "Failed to get PKI")

	// Parse CA certificate
	block, _ := pem.Decode(pki.Ca)
	require.NotNil(t, block, "Failed to decode CA certificate PEM")
	caCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Failed to parse CA certificate")

	// Verify CA certificate properties
	assert.True(t, caCert.IsCA, "CA certificate should have IsCA=true")
	assert.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature, caCert.KeyUsage,
		"CA certificate should have correct key usage")
	assert.Contains(t, caCert.Subject.CommonName, contractAddrHex, "CA CommonName should contain contract address")

	// Parse app public key
	block, _ = pem.Decode(pki.Pubkey)
	require.NotNil(t, block, "Failed to decode public key PEM")
	_, err = x509.ParsePKIXPublicKey(block.Bytes)
	require.NoError(t, err, "Failed to parse public key")

	// Get app private key
	privKey, err := kmsInstance.GetAppPrivkey(contractAddr)
	require.NoError(t, err, "Failed to get app private key")

	// Verify private key is valid PEM
	block, _ = pem.Decode(privKey)
	require.NotNil(t, block, "Failed to decode private key PEM")
	_, err = x509.ParseECPrivateKey(block.Bytes)
	require.NoError(t, err, "Failed to parse EC private key")
}

// TestCSRSigning tests that SimpleKMS can correctly sign a CSR
func TestCSRSigning(t *testing.T) {
	_, certRequest, err := cryptoutils.CreateCSRWithRandomKey("01000000000000000000000000000000000000.app")
	require.NoError(t, err, "Failed to create test CSR")

	// Initialize SimpleKMS
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	kmsInstance, err := kms.NewSimpleKMS(masterKey)
	require.NoError(t, err, "Failed to create SimpleKMS")

	// Create contract address
	var contractAddr interfaces.ContractAddress
	contractAddrHex := "0123456789abcdef0123456789abcdef01234567"
	contractAddrBytes, _ := hex.DecodeString(contractAddrHex)
	copy(contractAddr[:], contractAddrBytes[:20])

	// Sign the CSR
	cert, err := kmsInstance.SignCSR(contractAddr, certRequest)
	require.NoError(t, err, "Failed to sign CSR")

	// Parse the signed certificate
	block, _ := pem.Decode(cert)
	require.NotNil(t, block, "Failed to decode certificate PEM")
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err, "Failed to parse certificate")

	// Verify certificate properties
	assert.Equal(t, "01000000000000000000000000000000000000.app", parsedCert.Subject.CommonName, "Certificate should have correct subject")
	assert.Contains(t, parsedCert.ExtKeyUsage, x509.ExtKeyUsageServerAuth, "Certificate should have server auth usage")
	assert.Contains(t, parsedCert.ExtKeyUsage, x509.ExtKeyUsageClientAuth, "Certificate should have client auth usage")
}
