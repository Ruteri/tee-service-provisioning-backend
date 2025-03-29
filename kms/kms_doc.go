// Package kms provides key management services for TEE applications.
//
// The KMS package is responsible for managing cryptographic keys, certificates,
// and attestations for TEE instances. It implements the interfaces.KMS interface:
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
// # Key Derivation
//
// Keys are derived deterministically using:
//   - Master key (provided at initialization)
//   - Contract address (identifies the application)
//   - Purpose ("ca" for certificate authorities, "app" for application keys)
//
// # Security Considerations
//
// The KMS implementations assume that attestation and identity verification
// have already been performed before sensitive cryptographic operations.
// Connections to instances must be secured through attested channels.
//
// # Usage Example
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
//	// Sign a CSR for a verified TEE instance
//	tlsCert, err := simpleKMS.SignCSR(contractAddr, csrData)
//
package kms
