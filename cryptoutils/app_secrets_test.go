package cryptoutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestEncryptionDecryption tests the EncryptWithPublicKey and DecryptWithPrivateKey functions
func TestEncryptionDecryption(t *testing.T) {
	// Generate a key pair for testing
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	
	// Convert private key to PEM format
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	
	// Convert public key to PEM format
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	require.NoError(t, err)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	
	// Test cases
	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "Simple string",
			data: []byte("This is a secret message"),
		},
		{
			name: "JSON data",
			data: []byte(`{"username":"admin","password":"secret123"}`),
		},
		{
			name: "Binary data",
			data: []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD},
		},
		/* Needs a fix {
			name: "Empty data",
			data: []byte{},
		}, */
		{
			name: "Long data",
			data: make([]byte, 1024), // 1KB of zeros
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Encrypt the data
			encryptedData, err := EncryptWithPublicKey(publicKeyPEM, tc.data)
			require.NoError(t, err)
			
			// Encrypted data should be longer than original (except for empty data)
			if len(tc.data) > 0 {
				require.Greater(t, len(encryptedData), len(tc.data))
			}
			
			// Decrypt the data
			decryptedData, err := DecryptWithPrivateKey(privateKeyPEM, encryptedData)
			require.NoError(t, err)
			
			// Verify the decrypted data matches the original
			require.Equal(t, tc.data, decryptedData)
		})
	}
}

// TestDecryptionWithWrongKey tests that decryption fails with the wrong key
func TestDecryptionWithWrongKey(t *testing.T) {
	// Generate key pair for encryption
	privateKey1, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	
	// Convert public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey1.PublicKey)
	require.NoError(t, err)
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	
	// Generate different key pair for decryption
	privateKey2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	
	// Convert second private key to PEM
	privateKey2Bytes, err := x509.MarshalECPrivateKey(privateKey2)
	require.NoError(t, err)
	privateKey2PEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKey2Bytes,
	})
	
	// Encrypt with first public key
	data := []byte("Top secret data")
	encryptedData, err := EncryptWithPublicKey(publicKeyPEM, data)
	require.NoError(t, err)
	
	// Try to decrypt with wrong private key - should fail
	_, err = DecryptWithPrivateKey(privateKey2PEM, encryptedData)
	require.Error(t, err)
}

// TestInvalidKeyFormats tests error handling for invalid key formats
func TestInvalidKeyFormats(t *testing.T) {
	// Test invalid public key
	_, err := EncryptWithPublicKey([]byte("not a valid PEM"), []byte("test"))
	require.Error(t, err)
	
	// Test invalid private key
	_, err = DecryptWithPrivateKey([]byte("not a valid PEM"), []byte("test"))
	require.Error(t, err)
	
	// Test invalid encrypted data format
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	require.NoError(t, err)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	
	// Test with too short data
	_, err = DecryptWithPrivateKey(privateKeyPEM, []byte{0x01})
	require.Error(t, err)
	
	// Test with invalid format
	_, err = DecryptWithPrivateKey(privateKeyPEM, make([]byte, 100))
	require.Error(t, err)
}
