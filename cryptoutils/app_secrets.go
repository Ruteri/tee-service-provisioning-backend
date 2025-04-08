package cryptoutils

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

// EncryptWithPublicKey encrypts data using ECIES with the given public key PEM.
// It implements Elliptic Curve Integrated Encryption Scheme with ECDH key agreement,
// SHA-256 for key derivation, and AES-GCM for authenticated encryption.
// A fresh ephemeral key is generated for each encryption operation, providing forward secrecy.
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

// DecryptWithPrivateKey decrypts data encrypted with EncryptWithPublicKey using the corresponding private key.
// It processes the binary format containing the ephemeral public key, IV, and ciphertext,
// then performs ECDH key agreement to derive the shared secret for decryption.
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

// VerifyCertificate validates that a certificate matches a given private key and has the expected common name.
// It performs the following checks:
//   - The certificate can be parsed correctly
//   - The common name matches the expected value
//   - The public key in the certificate corresponds to the provided private key
//
// This function is useful for ensuring that a certificate was issued for the correct entity
// and matches the private key that will be used with it.
func VerifyCertificate(keyPEM, certPEM []byte, expectedCN string) error {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return errors.New("failed to decode private key PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS#1 format if PKCS#8 fails
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return errors.New("failed to decode certificate PEM block")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Compare CommonName
	if cert.Subject.CommonName != expectedCN {
		return fmt.Errorf("CommonName is %s, expected %s", cert.Subject.CommonName, expectedCN)
	}

	// Compare public keys
	certPublicKey := cert.PublicKey
	privatePublicKey := privateKey.(interface{ Public() crypto.PublicKey }).Public()

	// For ECDSA keys
	if ecdsaCertKey, ok := certPublicKey.(*ecdsa.PublicKey); ok {
		ecdsaPrivKey, ok := privatePublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("private key type doesn't match certificate")
		}

		if ecdsaCertKey.X.Cmp(ecdsaPrivKey.X) != 0 ||
			ecdsaCertKey.Y.Cmp(ecdsaPrivKey.Y) != 0 ||
			ecdsaCertKey.Curve != ecdsaPrivKey.Curve {
			return errors.New("private key doesn't match certificate")
		}
		return nil
	}
	// Add comparisons for other key types (RSA, etc.) as needed

	return errors.New("unsupported key type")
}

// CreateCSRWithRandomKey generates a new ECDSA key pair and creates a Certificate Signing Request (CSR)
// with the specified Common Name (CN). This is useful for generating new identities for TLS connections.
//
// Returns:
//   - Private key in PEM format
//   - CSR in PEM format
//   - Error if key generation or CSR creation fails
func CreateCSRWithRandomKey(cn string) ([]byte, []byte, error) {
	// Generate a new ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Create a CSR template
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	// Create a CSR using the private key and template
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode the CSR in PEM format
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})
	return keyPEM, csrPEM, nil
}

// DeriveDiskKey creates a deterministic encryption key from a CSR and secret using Argon2id KDF.
// This function can be used to derive encryption keys for TEE disk protection, ensuring
// that the same key can be regenerated given the same inputs.
//
// Parameters:
//   - csr: Certificate Signing Request bytes, used as part of the salt
//   - secret: Secret material for key derivation
//
// Returns:
//   - Derived encryption key as a string
func DeriveDiskKey(csr []byte, secret []byte) string {
	// Use Argon2id with recommended parameters
	salt := append([]byte("TEE-DISK-KEY-"), csr[:]...) // Use part of CSR as salt

	// Parameters: time=1, memory=64*1024, threads=4, keyLen=32
	key := argon2.IDKey(secret, salt, 1, 64*1024, 4, 32)

	// Convert to string format if needed or return as bytes
	return string(key)
}
