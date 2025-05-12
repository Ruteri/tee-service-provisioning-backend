// Package pkihandler implements HTTP handlers and client functions for 
// the TEE Registry's Public Key Infrastructure (PKI).
//
// This package provides the necessary functionality to retrieve and verify 
// attestation-backed PKI information for TEE applications identified by their 
// contract addresses. It implements both a server-side handler for responding 
// to PKI requests and a client-side function for retrieving PKI information.
//
// # Key Components
//
// - Handler: Processes HTTP requests for PKI information, retrieving attested
//   certificate authorities and public keys from the KMS
//
// - PKI Client: Makes HTTP requests to retrieve PKI information from a
//   remote PKI service
//
// # PKI Verification Flow
//
// When a client needs to verify the identity of a TEE application:
//
// 1. The client calls the PKI function with the target application's contract address
// 2. The PKI service (Handler) retrieves the attested PKI information from the KMS
// 3. The client receives the CA certificate, application public key, and attestation
// 4. The client can verify the attestation to ensure the PKI information is genuine
// 5. Once verified, the client can use the CA certificate to validate TLS connections to instances
//
// # Usage Example
//
// Server-side usage:
//
//	// Create a PKI handler
//	handler := pkihandler.NewHandler(kmsInstance, logger)
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
//	// Use the PKI information for certificate validation
//	caCert := pkiInfo.CACert
//	// Configure TLS client with CA certificate...
//
// # Security Considerations
//
// The attestation provided with the PKI information should be cryptographically verified
// to ensure the authenticity of the certificate authority. This attestation binds the
// PKI to a specific TEE identity, providing a root of trust for the application.
//
// PKI information is considered public and does not require confidentiality protection,
// but integrity and authenticity are critical. The attestation provides these security properties.
package pkihandler
