/*
Package api provides components for a TEE (Trusted Execution Environment) registry system.

This package is organized into three main subpackages:

1. handlers - Request processing logic and business operations
2. servers - HTTP server configuration and lifecycle management
3. clients - Client libraries for API interaction

Together, these subpackages implement a secure system for TEE instance registration,
attestation verification, configuration management, and KMS bootstrapping.

# System Components

The TEE Registry API system works with the following components:

- KMS (Key Management System): Manages cryptographic operations and secrets
- StorageBackend: Content-addressed storage for configurations and secrets
- OnchainRegistry: Smart contract for identity verification and configuration
- TEE Instances: Confidential computing environments seeking registration

# Key Functionality

- TEE instance registration with attestation evidence verification
- Secure TLS certificate issuance to verified instances
- Configuration template processing with secret reference resolution
- Secure KMS bootstrapping with Shamir's Secret Sharing
- Application PKI (Public Key Infrastructure) management
- Health monitoring and graceful shutdown capabilities

# Security Model

The system implements a robust security model with:

- Attestation-based identity verification
- Cryptographic proof of admin identity for KMS operations
- Asymmetric encryption for secret protection
- Zero-trust share distribution for Shamir's Secret Sharing
- Server-side decryption only for verified TEE instances

# API Structure

The API structure is divided into two main components:

1. Registry API - For TEE instance registration and configuration
2. Admin API - For KMS bootstrapping and management

See the subpackages for detailed documentation on specific components.
*/
package api
