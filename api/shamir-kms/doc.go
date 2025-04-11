// Package shamirkms implements a secure Key Management System bootstrapping service
// using Shamir's Secret Sharing.
//
// This package provides a zero-trust system for initializing and recovering
// cryptographic master keys using Shamir's Secret Sharing algorithm. Each share
// is individually encrypted for a specific administrator using their public key,
// ensuring that no unauthorized party (including the server) can access all shares
// or reconstruct the master key without proper authorization.
//
// # Key Components
//
//   - AdminHandler: Implements secure share management with admin authentication,
//     encryption of shares for specific admins, and state transitions during bootstrap
//   - Server: Provides HTTP endpoints for the admin API with health checks
//     and bootstrap coordination
//   - AdminClient: Client library for administrators to interact with the bootstrap
//     API, including request signing and share management
//
// # Security Model
//
// The package implements a robust security model with:
//
//   - Cryptographic verification of admin identity using ECDSA signatures
//   - Individual encryption of shares with admin-specific public keys
//   - Zero knowledge of master key once split into shares
//   - Secure share distribution with admin-specific retrieval
//   - Signature verification for share submission during recovery
//
// # Bootstrap Process
//
// Two operational modes are supported:
//
//  1. Generation Mode:
//     - Server generates a strong cryptographic master key
//     - Key is split into shares using Shamir's Secret Sharing
//     - Each share is encrypted with an admin's public key
//     - Admins securely retrieve their encrypted shares
//
//  2. Recovery Mode:
//     - Server starts in recovery mode awaiting admin shares
//     - Admins submit their shares with cryptographic proofs of identity
//     - Once threshold shares are validated, master key is reconstructed
//     - KMS becomes operational with the reconstructed key
//
// # Usage Example
//
//	// Setup the admin client
//	adminClient := shamirkms.NewAdminClient(
//	    "https://registry.example.com:8081",
//	    "admin-1",
//	    privateKey,
//	)
//
//	// Initialize KMS with a 3-of-5 threshold
//	err := adminClient.InitGenerate(3, 5)
//	if err != nil {
//	    log.Fatalf("Failed to initialize KMS: %v", err)
//	}
//
//	// Retrieve your encrypted share
//	shareResp, err := adminClient.FetchShare()
//
//	// During recovery, submit your share
//	err = adminClient.SubmitShare(shareIndex, shareBase64, nil)
package shamirkms
