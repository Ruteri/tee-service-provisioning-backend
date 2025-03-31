/*
Package httpserver provides secure share management for KMS bootstrapping.

# Share Distribution Security Model

The secure share distribution model ensures that shares are protected throughout
their lifecycle, without requiring admins to trust each other or the system.
This implementation follows security best practices for distributed key management.

## Key Security Properties

1. **Per-Admin Share Assignment**: Each share is assigned to a specific admin
2. **Public Key Encryption**: Each share is encrypted with its admin's public key
3. **Individual Retrieval**: Each admin can only retrieve their own share
4. **Cryptographic Verification**: All admin requests are authenticated with signatures
5. **Zero Trust Model**: No party (including the server) can access all shares
6. **Audit Trail**: All share operations are logged with admin identifiers

## Share Generation and Distribution Process

When an admin initiates master key generation:

1. The server generates a cryptographically random master key
2. This key is split into shares using Shamir's Secret Sharing algorithm
3. Each share is assigned to a specific admin
4. Each share is encrypted with its assigned admin's public key
5. The server stores the encrypted shares but cannot decrypt them
6. Only metadata about the share assignments is returned in the response
7. Each admin must make a separate authenticated request to retrieve their share

## Share Retrieval Process

When an admin retrieves their share:

1. The admin makes an authenticated request with their identity
2. The server verifies the admin's signature on the request
3. The server checks if the admin has an assigned share
4. If valid, the server returns the encrypted share to the admin
5. The admin decrypts the share using their private key
6. The admin securely stores their decrypted share

## Recovery Process

During recovery:

1. An admin initiates recovery mode with a specified threshold
2. Each admin submits their share along with a signature over the share
3. The server verifies each admin's identity and share signature
4. The server does not store the submitted shares, only passing them to the KMS
5. Once the threshold is reached, the KMS reconstructs the master key in memory
6. The master key exists only in memory and is never persisted

# Cryptographic Operations

All cryptographic operations use modern, secure algorithms:

1. **Share Encryption**: Asymmetric encryption using ECIES with AES-GCM
2. **Request Authentication**: ECDSA signatures with SHA-256
3. **Secret Sharing**: Shamir's Secret Sharing algorithm with GF(256)
4. **Master Key Generation**: Cryptographically secure random number generation

# Client Implementation

The AdminShareClient provides a secure client implementation that:

1. Automatically signs requests with the admin's private key
2. Handles share retrieval and decryption
3. Manages share submission with proper signatures
4. Provides a simple, secure API for administrators

# Security Considerations

1. Admin private keys must be securely generated and stored
2. Communication should always use TLS (HTTPS) to prevent eavesdropping
3. Shares should be securely stored when not in use
4. The threshold should be set appropriately (not too low, not too high)
5. In production, additional authentication factors should be considered
*/
package httpserver
