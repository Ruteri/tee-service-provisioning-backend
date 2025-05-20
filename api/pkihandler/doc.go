// Package pkihandler implements HTTP handlers and client functions for
// the TEE Registry's Public Key Infrastructure (PKI) service.
//
// This package provides functionality to retrieve and verify attestation-backed
// PKI information for TEE applications identified by their contract addresses.
// It serves as an interface to the onchain-governed PKI system and is a critical
// component for establishing trusted TLS connections between TEE instances.
//
// # Key Components
//
//   - Handler: Processes HTTP requests for PKI information, retrieving attested
//     certificate authorities and public keys from the onchain-governed KMS
//
//   - PKI Client: Makes HTTP requests to retrieve PKI information from a
//     remote PKI service, enabling cross-application trust
//
// # Architecture Integration
//
// This package functions as part of the larger TEE Registry System architecture:
//
//  1. It interfaces with the KMS package to retrieve application-specific PKI materials
//  2. It provides a consistent API for TEE instances to obtain verified CA certificates
//  3. It supports the instanceutils components by providing the root certificates
//     needed for secure inter-instance communication
//  4. It enables cross-application authentication with onchain-governed identities
//
// # PKI Verification Flow
//
// When a client needs to verify the identity of a TEE application:
//
// 1. The client calls the PKI function with the target application's contract address
// 2. The PKI service (Handler) retrieves the attested PKI information from the KMS
// 3. The client receives the CA certificate, application public key, and attestation
// 4. The client can verify the attestation against the onchain registry
// 5. Once verified, the client can use the CA certificate to validate TLS connections to instances
//
// # Usage Example
//
// Server-side usage with onchain-governed KMS:
//
//	// Create a PKI handler with the KMS that interfaces with onchain governance
//	handler := pkihandler.NewHandler(onchainKmsInstance, logger)
//
//	// Register routes with a Chi router
//	router := chi.NewRouter()
//	handler.RegisterRoutes(router)
//
//	// Start the HTTP server
//	http.ListenAndServe(":8080", router)
//
// Client-side usage:
//
//	// Retrieve PKI information for a contract address
//	contractAddr, _ := interfaces.NewContractAddressFromHex("0x1234567890abcdef1234567890abcdef12345678")
//	pkiInfo, err := pkihandler.PKI("https://registry.example.com", contractAddr)
//	if err != nil {
//	    log.Fatalf("Failed to retrieve PKI: %v", err)
//	}
//
//	// Verify attestation against onchain governance
//	// (Verification logic should check the attestation against the blockchain)
//
//	// Use the PKI information for certificate validation
//	caCert := pkiInfo.Ca
//	// Configure TLS client with CA certificate...
//
// # Security Considerations
//
// The attestation provided with the PKI information should be cryptographically verified
// against the onchain registry to ensure the authenticity of the certificate authority.
// This attestation binds the PKI to a specific TEE identity governed by the blockchain,
// providing a decentralized root of trust for the application.
//
// PKI information is considered public and does not require confidentiality protection,
// but integrity and authenticity are critical. The onchain governance and attestation
// verification provide these security properties.
package pkihandler
