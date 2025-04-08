/*
Package clients provides client libraries for interacting with the TEE registry API.

This package implements secure client interfaces for both the Registry API and
Admin API, handling authentication, request signing, and response processing.

# Client Types

The package provides three main client types:

1. AdminClient - General admin API operations client
2. AdminShareClient - Specialized client for secure share management
3. Various utility functions for admin key management

# AdminClient Features

AdminClient provides methods for general admin operations:

- GetStatus - Query current bootstrap status
- InitGenerate - Start master key generation
- InitRecover - Initiate recovery mode
- SubmitShare - Submit a share during recovery
- WaitForCompletion - Poll until bootstrap completes

# AdminShareClient Features

AdminShareClient specializes in secure share operations:

- GetShare - Securely retrieve and decrypt an assigned share
- GetStatus - Check current share distribution status
- InitGenerate - Generate and distribute shares securely
- InitRecover - Start recovery process with proper parameters
- SubmitShare - Submit a share with cryptographic verification

# Security Model

All admin clients implement a robust security model:

- Request signing with the admin's private key
- Signature verification on the server side
- Secure share encryption/decryption
- Zero-trust share distribution and collection
- Proper error handling for security-critical operations

# Utility Functions

The package provides utility functions for admin operations:

- GenerateAdminKeyPair - Create admin credential pairs
- LoadAdminKeys - Parse admin keys from configuration
- ParsePrivateKey - Convert PEM format to usable private key
- ComputeFingerprint - Generate a fingerprint for admin identity
- SignAdminRequest - Add authentication headers to requests

# Example Usage

	// Create a new admin client
	privateKey, _ := crypto.HexToECDSA("your-private-key-hex")
	adminClient := clients.NewAdminClient(
	    "https://registry.example.com:8081",
	    "admin-1",
	    privateKey,
	    30*time.Second,
	)

	// Get current status
	status, err := adminClient.GetStatus()

	// Create a share client for secure operations
	shareClient := clients.NewAdminShareClient(
	    "https://registry.example.com:8081",
	    "admin-1",
	    privateKey,
	)

	// Retrieve your encrypted share
	shareIndex, shareData, err := shareClient.GetShare()
*/
package clients
