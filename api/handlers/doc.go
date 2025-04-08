/*
Package handlers implements request processing logic for a TEE registry system.

This package contains handlers for both the Registry API and Admin API endpoints,
processing requests and implementing the core business logic of the system.

# Handler Types

The package provides two main handler types:

1. Handler - Processes Registry API requests for TEE attestation and configuration
2. AdminHandler - Manages KMS bootstrapping operations with secure share distribution

# Registry Handler Features

The Registry Handler implements these key features:

- TEE instance registration with attestation validation
- Certificate signing for verified instances
- Application metadata retrieval
- Configuration template processing with secret resolution
- Health and readiness checking

# Admin Handler Features

The AdminHandler implements secure KMS bootstrapping:

- Master key generation and split into shares
- Secure share distribution to administrators
- Share collection with cryptographic verification
- KMS reconstruction from collected shares
- Bootstrap state management

# Secret Management

The Registry Handler manages pre-encrypted secrets securely:

- Fetches encrypted secrets from storage backends
- Decrypts them using the app's private key from KMS
- Embeds plaintext secrets in configurations for verified TEE instances
- Handles both JSON and non-JSON secrets appropriately
- Logs decryption failures without exposing sensitive data

# Main Methods

Registry Handler provides:
- HandleRegister - Processes TEE instance registration
- HandleAppMetadata - Retrieves application metadata
- SetKMS - Updates the KMS instance after bootstrap

Admin Handler provides:
- AdminRouter - Creates an HTTP router for admin endpoints
- WaitForBootstrap - Blocks until KMS bootstrap completes
- GetKMS - Returns the initialized ShamirKMS after bootstrap

# Security Considerations

- All handlers assume attestation validation before sensitive operations
- References to pre-encrypted secrets are properly processed
- Failed attestation attempts are logged and rejected
- Admin operations require cryptographic proof of identity
- Zero-trust share distribution model prevents unauthorized access
*/
package handlers
