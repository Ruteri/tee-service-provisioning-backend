// Package kms provides key management services for TEE applications.
//
// The KMS package manages cryptographic keys, certificates, and attestations
// for TEE instances, providing materials needed for secure secret management and
// communication. It implements the interfaces.KMS interface:
//
//	// KMS handles cryptographic operations for TEE applications.
//	type KMS interface {
//	    // GetPKI retrieves application CA certificate, public key, and attestation.
//	    GetPKI(contractAddr ContractAddress) (AppPKI, error)
//
//	    // AppSecrets provides all cryptographic materials for a TEE instance.
//	    AppSecrets(ContractAddress, TLSCSR) (*AppSecrets, error)
//	}
//
// The package includes these implementations:
//
// # SimpleKMS
//
// A basic implementation that derives keys deterministically from a master key.
// Suitable for development and testing, it ensures consistent key generation
// across service restarts.
//
// # ShamirKMS
//
// An enhanced implementation using Shamir's Secret Sharing for secure master key
// management. The master key is split into shares, distributed to administrators,
// and never stored in persistent storage. It requires a threshold number of
// authorized administrators to submit their shares to reconstruct the master key.
//
// ## Master Key Protection
//
// The ShamirKMS protects the master key through several mechanisms:
//
//   - Split into N shares, requiring M (threshold) shares to reconstruct
//   - Original master key securely erased after splitting
//   - Each share distributed to a different administrator
//   - Shares cryptographically signed by administrators' private keys
//   - Reconstructed key exists only in memory, never written to persistent storage
//
// This ensures that no single administrator can compromise the master key and
// recovery requires cooperation of multiple authorized administrators.
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
// The KMS enables secure secret management:
//   - App public key is used to pre-encrypt secrets before storage
//   - App private key allows decryption of secrets in configuration templates
//   - Asymmetric encryption ensures secrets can only be decrypted by authorized
//     TEE instances
//
// # Integration with Onchain Governance
//
// The KMS integrates with the TEE Registry System's onchain governance:
//
//   - PKI information (CA cert, app pubkey) is published to the onchain contract
//   - Attestation evidence is provided for verification
//   - Application-specific keys are derived for different contract addresses
//   - TEE instances obtain cryptographic materials through attestation verification
//
// # Usage Example: SimpleKMS
//
//	// Create a SimpleKMS with a secure master key
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
//	pki, err := simpleKMS.GetPKI(contractAddr)
//
//	// Get all cryptographic materials for a TEE instance
//	csr := // ... prepare certificate signing request
//	appSecrets, err := simpleKMS.AppSecrets(contractAddr, csr)
//	if err != nil {
//	    log.Fatalf("Failed to get app secrets: %v", err)
//	}
//	// Use the returned materials
//	privKey := appSecrets.AppPrivkey
//	tlsCert := appSecrets.TLSCert
package kms
