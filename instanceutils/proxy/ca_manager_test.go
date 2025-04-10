package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
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

	// Create contract address using the new type properly
	contractAddr, err := interfaces.NewContractAddressFromHex("0123456789abcdef0123456789abcdef01234567")
	require.NoError(t, err, "Failed to create contract address")

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
		mockRegistryFactory,
		0, // Default cache time
		logger,
	)

	// Create certificate manager
	manager, err := NewAppCertificateManager(&instanceutils.LocalKMSRegistrationProvider{KMS: kmsInstance}, appResolver, contractAddr, logger)
	assert.NoError(t, err)
	assert.NotNil(t, manager)

	// Test GetClientCertificate
	clientCert, err := manager.GetClientCertificate(nil)
	assert.NoError(t, err)
	assert.NotNil(t, clientCert)

	// Create a valid common name based on contract address
	commonName := interfaces.NewAppCommonName(contractAddr)

	// Test GetConfigForClient with the appropriate domain format
	config, err := manager.GetConfigForClient(&tls.ClientHelloInfo{ServerName: commonName.String()})
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

	// Create contract address using the proper type constructor
	contractAddr, err := interfaces.NewContractAddressFromHex("0123456789abcdef0123456789abcdef01234567")
	require.NoError(t, err, "Failed to create contract address")

	// Get PKI from KMS
	pki, err := kmsInstance.GetPKI(contractAddr)
	require.NoError(t, err, "Failed to get PKI")

	// Validate the CA certificate using cryptoutils type
	caCert, err := cryptoutils.NewCACert(pki.Ca)
	require.NoError(t, err, "Failed to create CA certificate object")

	// Validate the CA certificate
	err = caCert.Validate()
	require.NoError(t, err, "CA certificate validation failed")

	// Get the X.509 cert for additional testing
	x509Cert, err := caCert.GetX509Cert()
	require.NoError(t, err, "Failed to get X.509 certificate")

	// Verify CA certificate properties
	assert.True(t, x509Cert.IsCA, "CA certificate should have IsCA=true")
	assert.Equal(t, x509.KeyUsageCertSign|x509.KeyUsageCRLSign|x509.KeyUsageDigitalSignature, x509Cert.KeyUsage,
		"CA certificate should have correct key usage")

	// Check that CN contains some form of the contract address
	cn := interfaces.NewAppCommonName(contractAddr)
	assert.Equal(t, x509Cert.Subject.CommonName, "CA for "+cn.String())

	// Validate the public key using cryptoutils type
	appPubkey, err := cryptoutils.NewAppPubkey(pki.Pubkey)
	require.NoError(t, err, "Failed to create public key object")

	// Validate the public key
	err = appPubkey.Validate()
	require.NoError(t, err, "Public key validation failed")

	// Get app private key
	rawPrivkey, err := kmsInstance.GetAppPrivkey(contractAddr)
	require.NoError(t, err, "Failed to get app private key")

	// Validate the private key using cryptoutils type
	appPrivkey, err := cryptoutils.NewAppPrivkey(rawPrivkey)
	require.NoError(t, err, "Failed to create private key object")

	// Validate the private key
	err = appPrivkey.Validate()
	require.NoError(t, err, "Private key validation failed")
}

// TestCSRSigning tests that SimpleKMS can correctly sign a CSR
func TestCSRSigning(t *testing.T) {
	// Create a contract address for the CSR using the proper constructor
	csrContractAddr, err := interfaces.NewContractAddressFromHex("0100000000000000000000000000000000000000")
	require.NoError(t, err, "Failed to create CSR contract address")

	// Create a CSR with the proper CommonName format
	commonName := fmt.Sprintf("%s.app", csrContractAddr.String())
	_, csrBytes, err := cryptoutils.CreateCSRWithRandomKey(commonName)
	require.NoError(t, err, "Failed to create test CSR")

	// Convert csrBytes to TLSCSR type
	certRequest, err := cryptoutils.NewTLSCSR(csrBytes)
	require.NoError(t, err, "Failed to create TLSCSR object")

	// Validate the CSR
	err = certRequest.Validate()
	require.NoError(t, err, "CSR validation failed")

	// Initialize SimpleKMS
	masterKey := make([]byte, 32)
	for i := range masterKey {
		masterKey[i] = byte(i)
	}
	kmsInstance, err := kms.NewSimpleKMS(masterKey)
	require.NoError(t, err, "Failed to create SimpleKMS")

	// Create contract address for signing using the proper constructor
	signingContractAddr, err := interfaces.NewContractAddressFromHex("0123456789abcdef0123456789abcdef01234567")
	require.NoError(t, err, "Failed to create signing contract address")

	// Sign the CSR
	certBytes, err := kmsInstance.SignCSR(signingContractAddr, certRequest)
	require.NoError(t, err, "Failed to sign CSR")

	// Convert to TLSCert type
	tlsCert, err := cryptoutils.NewTLSCert(certBytes)
	require.NoError(t, err, "Failed to create TLSCert object")

	// Validate the certificate
	err = tlsCert.Validate()
	require.NoError(t, err, "Certificate validation failed")

	// Get the X.509 certificate for additional validation
	parsedCert, err := tlsCert.GetX509Cert()
	require.NoError(t, err, "Failed to get X.509 certificate")

	// Verify certificate properties
	assert.Equal(t, commonName, parsedCert.Subject.CommonName, "Certificate should have correct subject")
	assert.Contains(t, parsedCert.ExtKeyUsage, x509.ExtKeyUsageServerAuth, "Certificate should have server auth usage")
	assert.Contains(t, parsedCert.ExtKeyUsage, x509.ExtKeyUsageClientAuth, "Certificate should have client auth usage")

	// Make sure it's not expired
	isExpired, err := tlsCert.IsExpired()
	require.NoError(t, err, "Failed to check expiration")
	assert.False(t, isExpired, "Certificate should not be expired")

	// If we have the CA cert, verify the certificate against it
	pki, err := kmsInstance.GetPKI(signingContractAddr)
	if err == nil {
		caCert, err := cryptoutils.NewCACert(pki.Ca)
		if err == nil {
			err = caCert.VerifyCertificate(tlsCert)
			assert.NoError(t, err, "Certificate should be verifiable against CA")
		}
	}
}
