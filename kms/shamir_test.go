package kms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/hashicorp/vault/shamir"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShamirKMS_NewShamirKMS(t *testing.T) {
	// Test successful creation
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err, "Failed to generate test master key")

	_, adminCerts := randomAdmins(t, 5)
	kms, shares, err := NewShamirKMS(masterKey, ShamirConfig{3, adminCerts})
	require.NoError(t, err, "NewShamirKMS should succeed with valid parameters")
	assert.NotNil(t, kms, "KMS should not be nil")
	assert.Equal(t, 5, len(shares), "Should generate 5 shares")
	assert.True(t, kms.IsUnlocked(), "KMS should start in unlocked state when initiated with master key")

	// Test with invalid parameters
	_, _, err = NewShamirKMS(masterKey, ShamirConfig{6, adminCerts})
	assert.Error(t, err, "Should fail when threshold > total shares")

	_, _, err = NewShamirKMS(masterKey, ShamirConfig{1, adminCerts})
	assert.Error(t, err, "Should fail when threshold < 2")

	// Test with too short master key
	shortKey := make([]byte, 16)
	_, _, err = NewShamirKMS(shortKey, ShamirConfig{2, adminCerts})
	assert.Error(t, err, "Should fail with master key < 32 bytes")
}

func TestShamirKMS_NewShamirKMSRecovery(t *testing.T) {
	_, adminCerts := randomAdmins(t, 3)
	kms, err := NewShamirKMSRecovery(ShamirConfig{3, adminCerts})
	assert.NoError(t, err)
	assert.NotNil(t, kms, "KMS should not be nil")
	assert.Equal(t, 3, kms.threshold, "Threshold should be set correctly")
	assert.False(t, kms.IsUnlocked(), "KMS should start in locked state")
}

func TestShamirKMS_InvalidAdmin(t *testing.T) {
	_, adminCerts := randomAdmins(t, 3)
	adminCerts[2] = pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: []byte("not-a-valid-key"),
	})
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	_, _, err = NewShamirKMS(masterKey, ShamirConfig{2, adminCerts})
	assert.Error(t, err, "Should fail with invalid key")

	_, err = NewShamirKMSRecovery(ShamirConfig{2, adminCerts})
	assert.Error(t, err, "Should fail with invalid key")
}

func TestShamirKMS_ShareSubmission(t *testing.T) {
	// Generate a master key
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err, "Failed to generate test master key")

	adminKeys, adminCerts := randomAdmins(t, 5)

	// Create ShamirKMS in generation mode
	_, shares, err := NewShamirKMS(masterKey, ShamirConfig{3, adminCerts})
	require.NoError(t, err, "Failed to create KMS")
	require.Equal(t, 5, len(shares), "Should generate 5 shares")

	// Create a recovery KMS
	recoveryKms, err := NewShamirKMSRecovery(ShamirConfig{3, adminCerts})
	require.NoError(t, err)

	// Sign and submit shares
	for i := 0; i < 3; i++ {
		signature, err := SignShare(shares[i], adminKeys[i])
		require.NoError(t, err, "Failed to sign share")

		err = recoveryKms.SubmitShare(i, shares[i], signature, adminCerts[i])
		require.NoError(t, err, "Share submission should succeed")
	}

	// After 3 shares, KMS should be unlocked
	assert.True(t, recoveryKms.IsUnlocked(), "KMS should be unlocked after threshold shares")

	// Test invalid cases

	// Create a new recovery KMS
	recoveryKms2, err := NewShamirKMSRecovery(ShamirConfig{3, adminCerts})
	require.NoError(t, err)

	// Test with invalid signature
	invalidSig := []byte("invalid-signature")
	err = recoveryKms2.SubmitShare(0, shares[0], invalidSig, adminCerts[0])
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

	signature, err := SignShare(shares[0], unregisteredKey)
	require.NoError(t, err)

	err = recoveryKms2.SubmitShare(0, shares[0], signature, unregPubKeyPEM)
	assert.Error(t, err, "Should fail with unregistered admin")
}

func TestShamirKMS_UnlockedOperations(t *testing.T) {
	// Generate a master key
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	require.NoError(t, err, "Failed to generate test master key")

	adminKeys, adminCerts := randomAdmins(t, 5)

	// Create ShamirKMS in generation mode
	_, shares, err := NewShamirKMS(masterKey, ShamirConfig{3, adminCerts})
	require.NoError(t, err, "Failed to create KMS")

	// Unlock the KMS with shares
	recoveryKms, err := NewShamirKMSRecovery(ShamirConfig{3, adminCerts})
	require.NoError(t, err)

	// Sign and submit shares
	for i := 0; i < 3; i++ {
		signature, err := SignShare(shares[i], adminKeys[i])
		require.NoError(t, err)

		err = recoveryKms.SubmitShare(i, shares[i], signature, adminCerts[i])
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
	valid := ecdsa.VerifyASN1(&privateKey.PublicKey, share, signature)
	assert.True(t, valid, "Signature should be valid")
}

// SplitMasterKey splits a master key into shares using Shamir's Secret Sharing algorithm.
// This is a helper function that can be used separately from the ShamirKMS when
// custom share generation is needed.
//
// Parameters:
//   - masterKey: The master key to split (should be at least 32 bytes)
//   - totalShares: The total number of shares to generate
//   - threshold: The minimum number of shares needed to reconstruct the key
//
// Returns:
//   - The generated shares
//   - Error if the splitting operation fails
func SplitMasterKey(masterKey []byte, totalShares, threshold int) ([][]byte, error) {
	if len(masterKey) < 32 {
		return nil, errors.New("master key must be at least 32 bytes")
	}

	return shamir.Split(masterKey, totalShares, threshold)
}

func randomAdmin(t *testing.T) (*ecdsa.PrivateKey, []byte) {
	// Generate valid ECDSA key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err, "Failed to generate test key")

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err, "Failed to marshal public key")

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return privateKey, pubKeyPEM
}

func randomAdmins(t *testing.T, n int) ([]*ecdsa.PrivateKey, [][]byte) {
	pkeys := []*ecdsa.PrivateKey{}
	r := [][]byte{}
	for _ = range n {
		pk, cert := randomAdmin(t)
		pkeys = append(pkeys, pk)
		r = append(r, cert)
	}

	return pkeys, r
}
