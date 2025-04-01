// Package cryptoutils provides cryptographic operations for secure secret management
// in the TEE registry system.
//
// This package implements asymmetric encryption and decryption operations using
// elliptic curve cryptography and AES-GCM. It is primarily used for protecting
// sensitive configuration secrets throughout their lifecycle, from initial storage
// to eventual use within TEE instances.
//
// The encryption scheme uses ECIES (Elliptic Curve Integrated Encryption Scheme)
// with the following components:
//
//   - Elliptic curve (NIST P-256) for key exchange
//   - ECDH for shared secret derivation
//   - SHA-256 for key derivation
//   - AES-GCM for symmetric encryption with authenticated encryption
//   - Unique ephemeral keys for each encryption operation
//
// # Key Functions
//
// # EncryptWithPublicKey - Encrypts data using a public key in PEM format
//
// # DecryptWithPrivateKey - Decrypts data using a private key in PEM format
//
// # Encryption Format
//
// The encrypted data follows this binary format:
//
//	[ephemeral key length (2 bytes)][ephemeral key][iv (12 bytes)][ciphertext]
//
// Where:
//   - Ephemeral key length: uint16 in big-endian format
//   - Ephemeral key: Elliptic curve point encoded using elliptic.Marshal()
//   - IV: 12-byte nonce for AES-GCM
//   - Ciphertext: The encrypted data with GCM authentication tag
//
// # Security Considerations
//
// This package implements several security best practices:
//
//   - Fresh ephemeral keys for each encryption operation (forward secrecy)
//   - Authenticated encryption using AES-GCM
//   - No static IVs or predictable values
//   - Proper key derivation from ECDH shared secret
//
// However, users should be aware of these considerations:
//
//   - The security depends on the secrecy of the private key
//   - Data encrypted with a public key can only be decrypted with the corresponding private key
//   - Error messages are intentionally vague to prevent leaking information
//
// # Usage Example
//
//	// Get public key from PKI (typically from KMS)
//	publicKeyPEM := pki.Pubkey
//
//	// Encrypt sensitive data
//	secretData := []byte(`{"username":"admin","password":"secure123"}`)
//	encryptedData, err := cryptoutils.EncryptWithPublicKey(publicKeyPEM, secretData)
//	if err != nil {
//	    log.Fatalf("Failed to encrypt: %v", err)
//	}
//
//	// Store the encrypted data...
//
//	// Later, decrypt with private key
//	decryptedData, err := cryptoutils.DecryptWithPrivateKey(privateKeyPEM, encryptedData)
//	if err != nil {
//	    log.Fatalf("Failed to decrypt: %v", err)
//	}
//
//	// Use the decrypted data
//	var credentials map[string]string
//	json.Unmarshal(decryptedData, &credentials)
package cryptoutils
