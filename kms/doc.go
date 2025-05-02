// Package kms provides key management services for TEE applications.
//
// The KMS package is responsible for managing cryptographic keys, certificates,
// and attestations for TEE instances. It also provides the cryptographic materials
// needed for secure secret management. It implements the interfaces.KMS interface:
//
//	// KMS defines the interface for key management operations
//	type KMS interface {
//		// GetPKI *derives* the CA certificate, app pubkey and attests them for a given contract
//		// CA and pubkey should match the ones in the certificate (must match unless rotated)
//		// Anyone should be able to fetch the PKI through an attested channel, therefore the attestation is only provided as trace/transparency
//		GetPKI(contractAddr ContractAddress) (AppPKI, error)
//
//		// GetAppPrivkey returns the application private key (interface assumes attestation and identity have been verified already)
//		// The instance must be connected to through attested communication channels, whether directly or indirectly!
//		// This private key is also used for decrypting pre-encrypted secrets in configuration templates.
//		GetAppPrivkey(contractAddr ContractAddress) (AppPrivkey, error)
//
//		// SignCSR signs a certificate signing request (interface assumes attestation and identity have been verified already)
//		// The instance must be connected to through attested communication channels, whether directly or indirectly!
//		SignCSR(contractAddr ContractAddress, csr TLSCSR) (TLSCert, error)
//	}
//
// The package includes these implementations:
//
// # SimpleKMS
//
// A basic implementation that derives keys deterministically from a master key.
// It's suitable for development and testing scenarios. Keys are derived based on
// the contract address and purpose, ensuring consistent key generation even after
// service restarts.
//
// # ShamirKMS
//
// An enhanced implementation that uses Shamir's Secret Sharing to securely manage
// the master key. The master key is split into shares, distributed to administrators,
// and never stored in persistent storage. When the KMS starts, it requires a threshold
// number of authorized administrators to submit their shares to reconstruct the master key.
//
// ## Master Key Protection and Recovery
//
// The ShamirKMS protects the master key through several mechanisms:
//
//   - The master key is initially split into N shares, requiring M (threshold) shares to reconstruct
//   - The original master key is securely erased after splitting
//   - Each share is distributed to a different administrator
//   - Shares must be cryptographically signed by the administrator's private key
//   - During recovery, each share is verified against the administrator's public key
//   - Once the threshold is met, shares are combined to reconstruct the master key
//   - After reconstruction, all shares are securely wiped from memory
//   - The reconstructed master key exists only in memory and is never written to persistent storage
//
// This approach ensures that:
//
//   - No single administrator can compromise the master key
//   - The master key is protected even if the KMS storage is compromised
//   - Recovery requires cooperation of multiple authorized administrators
//   - The master key is securely managed throughout its lifecycle
//
// # Key Derivation
//
// Keys are derived deterministically using:
//   - Master key (provided at initialization or reconstructed from shares)
//   - Contract address (identifies the application)
//   - Purpose ("ca" for certificate authorities, "app" for application keys)
//
// # Secret Management
//
// The KMS plays a critical role in the secure management of secrets:
//   - The app's public key (from GetPKI) is used to pre-encrypt secrets before storage
//   - The app's private key (from GetAppPrivkey) is used by the handler to decrypt secrets
//     when processing configuration templates
//   - This asymmetric encryption ensures that secrets can only be decrypted by the
//     authorized TEE instance with the correct private key
//
// # Security Considerations
//
// The KMS implementations assume that attestation and identity verification
// have already been performed before sensitive cryptographic operations.
// Connections to instances must be secured through attested channels.
//
// Private keys should never leave the server except when being sent to a properly
// attested TEE instance. The private key allows not only for TLS communication but
// also for decrypting sensitive configuration secrets.
//
// # Usage Example: SimpleKMS
//
//	// Create a new SimpleKMS with a secure master key
//	masterKey := make([]byte, 32)
//	rand.Read(masterKey)
//	simpleKMS, err := kms.NewSimpleKMS(masterKey)
//	if err != nil {
//	    log.Fatalf("Failed to create KMS: %v", err)
//	}
//
//	// Get PKI information for a contract
//	var contractAddr interfaces.ContractAddress
//	// ... set contract address
//
//	pki, err := simpleKMS.GetPKI(contractAddr)
//	if err != nil {
//	    log.Fatalf("Failed to get PKI: %v", err)
//	}
//
// # Usage Example: ShamirKMS (Setup)
//
//	// Generate a secure master key
//	masterKey := make([]byte, 32)
//	rand.Read(masterKey)
//
//	// Prepare admin public keys
//	adminPubKeys := [][]byte{
//	    adminPubKey1PEM,
//	    adminPubKey2PEM,
//	    adminPubKey3PEM,
//	    adminPubKey4PEM,
//	    adminPubKey5PEM,
//	}
//
//	// Create a ShamirKMS with a 3-of-5 threshold
//	config := kms.ShamirConfig{
//	    Threshold:    3,
//	    AdminPubKeys: adminPubKeys,
//	}
//
//	shamirKMS, shares, err := kms.NewShamirKMS(masterKey, config)
//	if err != nil {
//	    log.Fatalf("Failed to create ShamirKMS: %v", err)
//	}
//
//	// Securely distribute shares to admins
//	for i, share := range shares {
//	    // Sign share with admin's private key
//	    signature, _ := kms.SignShare(share, adminKeys[i])
//
//	    // Securely distribute to admin: share, signature, adminKey
//	    fmt.Printf("Admin %d: please securely store your share and private key\n", i+1)
//	}
//
// # Usage Example: ShamirKMS (Recovery)
//
//	// Prepare admin public keys (same as during setup)
//	adminPubKeys := [][]byte{
//	    adminPubKey1PEM,
//	    adminPubKey2PEM,
//	    adminPubKey3PEM,
//	    adminPubKey4PEM,
//	    adminPubKey5PEM,
//	}
//
//	// Create a ShamirKMS in recovery mode with a threshold of 3
//	config := kms.ShamirConfig{
//	    Threshold:    3,
//	    AdminPubKeys: adminPubKeys,
//	}
//
//	shamirKMS, err := kms.NewShamirKMSRecovery(config)
//	if err != nil {
//	    log.Fatalf("Failed to create recovery KMS: %v", err)
//	}
//
//	// Administrators submit their shares
//	// In a real system, this would happen through an API or interface
//	for i := 0; i < 3; i++ {
//	    // Admin loads their share and private key
//	    share := loadAdminShare(i)
//	    adminKey := loadAdminPrivateKey(i)
//
//	    // Admin signs their share
//	    signature, _ := kms.SignShare(share, adminKey)
//
//	    // Admin submits their share to the KMS
//	    err := shamirKMS.SubmitShare(i, share, signature, adminPubKeyPEM[i])
//	    if err != nil {
//	        log.Printf("Share submission failed: %v", err)
//	    }
//	}
//
//	// Check if KMS is unlocked
//	if shamirKMS.IsUnlocked() {
//	    fmt.Println("KMS successfully unlocked and operational!")
//
//	    // Now we can use the KMS normally
//	    pki, _ := shamirKMS.GetPKI(contractAddr)
//	    // ...
//	}
package kms
