// Package api provides components for a TEE (Trusted Execution Environment) registry system.
//
// The api package and its subpackages implement a secure system for TEE instance
// registration, attestation verification, configuration management, and KMS bootstrapping.
// The system enables secure provisioning of confidential computing services while
// ensuring all sensitive data remains protected.
//
// # Subpackages
//
// The api package is organized into several subpackages:
//
//   - provisioner: Handles TEE instance registration and configuration provisioning
//   - shamir-kms: Implements secure key management with Shamir's Secret Sharing
//
// # System Components
//
// The TEE Registry API system works with the following components:
//
//   - KMS (Key Management System): Manages cryptographic operations and secrets
//   - StorageBackend: Content-addressed storage for configurations and secrets
//   - OnchainRegistry: Smart contract for identity verification and configuration
//   - TEE Instances: Confidential computing environments seeking registration
//
// # Key Functionality
//
//   - TEE instance registration with attestation evidence verification
//   - Secure TLS certificate issuance to verified instances
//   - Configuration template processing with secret reference resolution
//   - Secure KMS bootstrapping with Shamir's Secret Sharing
//   - Application PKI management
//
// # API Structure
//
// The API structure is divided into two main components:
//
//  1. Registry API - For TEE instance registration and configuration
//  2. Admin API - For KMS bootstrapping and management
//
// See the subpackages for detailed documentation on specific components.
package api
