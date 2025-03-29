package cryptoutils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
)

// EncryptWithPublicKey encrypts data using ECIES with the given public key PEM
func EncryptWithPublicKey(publicKeyPEM []byte, data []byte) ([]byte, error) {
	// Parse public key
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, errors.New("failed to decode public key PEM")
	}

	publicKeyInterface, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	publicKey, ok := publicKeyInterface.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}

	// Generate ephemeral key for ECIES encryption
	ephemeralKey, err := ecdsa.GenerateKey(publicKey.Curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	// Derive shared secret using ECDH
	x, _ := publicKey.Curve.ScalarMult(publicKey.X, publicKey.Y, ephemeralKey.D.Bytes())
	sharedSecret := sha256.Sum256(x.Bytes())

	// Generate random IV for AES-GCM
	iv := make([]byte, 12) // 12 bytes is standard for GCM
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, fmt.Errorf("failed to generate IV: %w", err)
	}

	// Create AES cipher with shared secret
	aesBlock, err := aes.NewCipher(sharedSecret[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	aesGCM, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Encrypt data
	ciphertext := aesGCM.Seal(nil, iv, data, nil)

	// Encode ephemeral public key
	ephemeralPublicKeyBytes := elliptic.Marshal(ephemeralKey.Curve, ephemeralKey.X, ephemeralKey.Y)

	// Format: [ephemeral key length (2 bytes)][ephemeral key][iv][ciphertext]
	result := make([]byte, 2+len(ephemeralPublicKeyBytes)+len(iv)+len(ciphertext))
	binary.BigEndian.PutUint16(result[0:2], uint16(len(ephemeralPublicKeyBytes)))
	copy(result[2:2+len(ephemeralPublicKeyBytes)], ephemeralPublicKeyBytes)
	copy(result[2+len(ephemeralPublicKeyBytes):2+len(ephemeralPublicKeyBytes)+len(iv)], iv)
	copy(result[2+len(ephemeralPublicKeyBytes)+len(iv):], ciphertext)

	return result, nil
}

// DecryptWithPrivateKey decrypts data using the private key
func DecryptWithPrivateKey(privateKeyPEM []byte, encryptedData []byte) ([]byte, error) {
	// Parse private key
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("failed to decode private key PEM")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	// Validate input
	if len(encryptedData) < 2 {
		return nil, errors.New("encrypted data too short")
	}

	// Parse the encrypted data format
	ephemeralKeyLen := binary.BigEndian.Uint16(encryptedData[0:2])
	if len(encryptedData) < int(2+ephemeralKeyLen+12) { // 12 is GCM nonce size
		return nil, errors.New("encrypted data has invalid format")
	}

	// Extract ephemeral public key
	ephemeralKeyBytes := encryptedData[2 : 2+ephemeralKeyLen]
	x, y := elliptic.Unmarshal(privateKey.Curve, ephemeralKeyBytes)
	if x == nil {
		return nil, errors.New("failed to unmarshal ephemeral public key")
	}

	// Derive shared secret using ECDH
	xShared, _ := privateKey.Curve.ScalarMult(x, y, privateKey.D.Bytes())
	sharedSecret := sha256.Sum256(xShared.Bytes())

	// Extract IV and ciphertext
	ivStart := 2 + ephemeralKeyLen
	iv := encryptedData[ivStart : ivStart+12] // 12-byte nonce for GCM
	ciphertext := encryptedData[ivStart+12:]

	// Create AES cipher with shared secret
	aesBlock, err := aes.NewCipher(sharedSecret[:])
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create GCM mode
	aesGCM, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %w", err)
	}

	// Decrypt data
	plaintext, err := aesGCM.Open(nil, iv, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}
