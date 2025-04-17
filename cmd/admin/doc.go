// Package main (cmd/admin) implements the admin client for the TEE Registry System's KMS bootstrap process.
//
// The admin client provides command-line tools for managing the Shamir Secret Sharing
// based Key Management System (KMS). It enables initialization, key generation,
// share distribution, and recovery operations for the secure bootstrap process.
//
// Commands:
//
//	status              - Query the current status of the KMS bootstrap process
//	generate-admin      - Generate new administrator key pair for authentication
//	generate-config     - Create shamir-admins.json configuration with admin public keys
//	init-generate       - Initialize KMS in generation mode with specified threshold/shares
//	init-recovery       - Initialize KMS in recovery mode with specified threshold
//	fetch-share         - Retrieve encrypted share and save to file
//	submit-share        - Submit share during recovery mode for master key reconstruction
//
// Each administrator must be registered with the system by including their public key
// in the shamir-admins.json configuration. Administrators authenticate using ECDSA
// signatures created with their private keys, and each admin can only retrieve and
// submit their own assigned share.
//
// Example workflow:
//
//  1. Generate admin keypair for each administrator:
//     admin generate-admin --admin-privkey-file=admin1-private.pem --admin-pubkey-file=admin1-public.pem
//
//  2. Create admin configuration file:
//     admin generate-config --admin-pubkey-files=admin1-public.pem,admin2-public.pem
//
//  3. Initialize KMS with 2-of-3 threshold:
//     admin init-generate --shamir-threshold=2 --shamir-total-shares=3
//
//  4. Each admin fetches their share:
//     admin fetch-share
//
//  5. During recovery, admins submit their shares:
//     admin submit-share
//
// The security model ensures that:
//   - Each share is encrypted for a specific admin
//   - Only the designated admin can decrypt their share
//   - A threshold number of shares is required to reconstruct the master key
//   - The master key is never persistently stored, only reconstructed in memory when needed
package main
