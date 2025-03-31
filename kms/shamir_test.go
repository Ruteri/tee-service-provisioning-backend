package kms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShamirKMS_NewShamirKMS(t *testing.T) {
	// Test successful creation
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err, "Failed to generate test master key")

	kms, shares, err := NewShamirKMS(masterKey, 3, 5)
	require.NoError(t, err, "NewShamirKMS should succeed with valid parameters")
	assert.NotNil(t, kms, "KMS should not be nil")
	assert.Equal(t, 5, len(shares), "Should generate 5 shares")
	assert.True(t, kms.IsUnlocked(), "KMS should start in unlocked state when initiated with master key")

	// Test with invalid parameters
	_, _, err = NewShamirKMS(masterKey, 6, 5)
	assert.Error(t, err, "Should fail when threshold > total shares")

	_, _, err = NewShamirKMS(masterKey, 1, 5)
	assert.Error(t, err, "Should fail when threshold < 2")

	// Test with too short master key
	shortKey := make([]byte, 16)
	_, _, err = NewShamirKMS(shortKey, 3, 5)
	assert.Error(t, err, "Should fail with master key < 32 bytes")
}

func TestShamirKMS_NewShamirKMSRecovery(t *testing.T) {
	kms := NewShamirKMSRecovery(3)
	assert.NotNil(t, kms, "KMS should not be nil")
	assert.Equal(t, 3, kms.threshold, "Threshold should be set correctly")
	assert.False(t, kms.IsUnlocked(), "KMS should start in locked state")
}

func TestShamirKMS_RegisterAdmin(t *testing.T) {
	kms := NewShamirKMSRecovery(3)
	require.NotNil(t, kms, "KMS should not be nil")

	// Generate valid ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generate test key")

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err, "Failed to marshal public key")

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	// Test valid registration
	err = kms.RegisterAdmin(pubKeyPEM)
	assert.NoError(t, err, "Should successfully register valid admin key")

	// Test invalid PEM
	err = kms.RegisterAdmin([]byte("not-a-valid-pem"))
	assert.Error(t, err, "Should fail with invalid PEM")

	// Test unsupported key type
	wrongKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte("not-a-valid-key"),
	})
	err = kms.RegisterAdmin(wrongKeyPEM)
	assert.Error(t, err, "Should fail with invalid key")
}

func TestShamirKMS_ShareSubmission(t *testing.T) {
	// Generate a master key
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err, "Failed to generate test master key")

	// Create ShamirKMS in generation mode
	genKms, shares, err := NewShamirKMS(masterKey, 3, 5)
	require.NoError(t, err, "Failed to create KMS")
	require.Equal(t, 5, len(shares), "Should generate 5 shares")

	// Create admin keys
	adminKeys := make([]*ecdsa.PrivateKey, 5)
	adminPubKeyPEMs := make([][]byte, 5)

	for i := 0; i < 5; i++ {
		// Generate key pair
		adminKeys[i], err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err, "Failed to generate admin key")

		// Export public key
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&adminKeys[i].PublicKey)
		require.NoError(t, err, "Failed to marshal public key")

		adminPubKeyPEMs[i] = pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		})

		// Register with generator KMS (just for completeness)
		err = genKms.RegisterAdmin(adminPubKeyPEMs[i])
		require.NoError(t, err, "Failed to register admin")
	}

	// Create a recovery KMS
	recoveryKms := NewShamirKMSRecovery(3)

	// Register the same admins
	for i := 0; i < 5; i++ {
		err = recoveryKms.RegisterAdmin(adminPubKeyPEMs[i])
		require.NoError(t, err, "Failed to register admin with recovery KMS")
	}

	// Sign and submit shares
	for i := 0; i < 3; i++ {
		hash := sha256.Sum256(shares[i])
		signature, err := ecdsa.SignASN1(rand.Reader, adminKeys[i], hash[:])
		require.NoError(t, err, "Failed to sign share")

		err = recoveryKms.SubmitShare(i, shares[i], signature, adminPubKeyPEMs[i])
		require.NoError(t, err, "Share submission should succeed")
	}

	// After 3 shares, KMS should be unlocked
	assert.True(t, recoveryKms.IsUnlocked(), "KMS should be unlocked after threshold shares")

	// Test invalid cases

	// Create a new recovery KMS
	recoveryKms2 := NewShamirKMSRecovery(3)
	for i := 0; i < 5; i++ {
		err = recoveryKms2.RegisterAdmin(adminPubKeyPEMs[i])
		require.NoError(t, err)
	}

	// Test with invalid signature
	invalidSig := []byte("invalid-signature")
	err = recoveryKms2.SubmitShare(0, shares[0], invalidSig, adminPubKeyPEMs[0])
	assert.Error(t, err, "Should fail with invalid signature")

	// Test with unregistered admin
	unregisteredKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	unregPubKeyBytes, err := x509.MarshalPKIXPublicKey(&unregisteredKey.PublicKey)
	require.NoError(t, err)

	unregPubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: unregPubKeyBytes,
	})

	hash := sha256.Sum256(shares[0])
	signature, err := ecdsa.SignASN1(rand.Reader, unregisteredKey, hash[:])
	require.NoError(t, err)

	err = recoveryKms2.SubmitShare(0, shares[0], signature, unregPubKeyPEM)
	assert.Error(t, err, "Should fail with unregistered admin")
}

func TestShamirKMS_UnlockedOperations(t *testing.T) {
	// Generate a master key
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err, "Failed to generate test master key")

	// Create ShamirKMS in generation mode
	kms, shares, err := NewShamirKMS(masterKey, 3, 5)
	require.NoError(t, err, "Failed to create KMS")

	// Create admin keys
	adminKeys := make([]*ecdsa.PrivateKey, 5)
	adminPubKeyPEMs := make([][]byte, 5)

	for i := 0; i < 5; i++ {
		// Generate key pair
		adminKeys[i], err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err, "Failed to generate admin key")

		// Export public key
		pubKeyBytes, err := x509.MarshalPKIXPublicKey(&adminKeys[i].PublicKey)
		require.NoError(t, err, "Failed to marshal public key")

		adminPubKeyPEMs[i] = pem.EncodeToMemory(&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: pubKeyBytes,
		})

		// Register with generator KMS (just for completeness)
		err = kms.RegisterAdmin(adminPubKeyPEMs[i])
		require.NoError(t, err, "Failed to register admin")
	}

	// Unlock the KMS with shares
	recoveryKms := NewShamirKMSRecovery(3)
	for i := 0; i < 5; i++ {
		err = recoveryKms.RegisterAdmin(adminPubKeyPEMs[i])
		require.NoError(t, err)
	}

	// Sign and submit shares
	for i := 0; i < 3; i++ {
		hash := sha256.Sum256(shares[i])
		signature, err := ecdsa.SignASN1(rand.Reader, adminKeys[i], hash[:])
		require.NoError(t, err)

		err = recoveryKms.SubmitShare(i, shares[i], signature, adminPubKeyPEMs[i])
		require.NoError(t, err)
	}

	// Now KMS should be unlocked
	assert.True(t, recoveryKms.IsUnlocked(), "KMS should be unlocked")

	// Create contract address
	contractAddr := interfaces.ContractAddress{}
	_, err = rand.Read(contractAddr[:])
	require.NoError(t, err, "Failed to generate contract address")

	// Try operations on unlocked KMS - should succeed
	pki, err := recoveryKms.GetPKI(contractAddr)
	assert.NoError(t, err, "GetPKI should succeed on unlocked KMS")
	assert.NotEmpty(t, pki.Ca, "CA should not be empty")
	assert.NotEmpty(t, pki.Pubkey, "Public key should not be empty")

	privkey, err := recoveryKms.GetAppPrivkey(contractAddr)
	assert.NoError(t, err, "GetAppPrivkey should succeed on unlocked KMS")
	assert.NotEmpty(t, privkey, "Private key should not be empty")

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: "test.example.com",
		},
	}

	// Create a CSR for testing
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privKey)
	require.NoError(t, err)

	csr := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	cert, err := recoveryKms.SignCSR(contractAddr, csr)
	assert.NoError(t, err, "SignCSR should succeed on unlocked KMS")
	assert.NotEmpty(t, cert, "Certificate should not be empty")
}

func TestShamirKMS_SplitMasterKey(t *testing.T) {
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err, "Failed to generate test master key")

	// Test valid parameters
	shares, err := SplitMasterKey(masterKey, 5, 3)
	assert.NoError(t, err, "Should split with valid parameters")
	assert.Equal(t, 5, len(shares), "Should generate 5 shares")

	// Test invalid parameters
	_, err = SplitMasterKey(masterKey, 3, 5)
	assert.Error(t, err, "Should fail when threshold > total shares")

	// Test with too short master key
	shortKey := make([]byte, 16)
	_, err = SplitMasterKey(shortKey, 5, 3)
	assert.Error(t, err, "Should fail with master key < 32 bytes")
}

func TestSignShare(t *testing.T) {
	// Generate a key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generate key")

	// Create a test share
	share := []byte("test-share-data")

	// Sign the share
	signature, err := SignShare(share, privateKey)
	assert.NoError(t, err, "Should sign share successfully")
	assert.NotEmpty(t, signature, "Signature should not be empty")

	// Verify the signature
	hash := sha256.Sum256(share)
	valid := ecdsa.VerifyASN1(&privateKey.PublicKey, hash[:], signature)
	assert.True(t, valid, "Signature should be valid")
}
