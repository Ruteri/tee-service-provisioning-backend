// Package main (autoprovision) implements TEE instance bootstrapping with secure disk encryption
// and configuration management.
//
// This package provides a command-line tool that automates the process of:
//   - Registering a new TEE instance with the registry system
//   - Setting up encrypted persistent storage using LUKS
//   - Securely storing TLS certificates, keys, and application configuration
//   - Supporting both initial provisioning and re-provisioning scenarios
//
// # Security Model
//
// The auto-provisioning tool implements a robust security model:
//
//   - Disk Encryption: Uses LUKS with keys derived from application credentials
//   - Key Derivation: Combines CSR and app private key for deterministic encryption
//   - Attestation: Provides TEE attestation evidence for identity verification
//   - Configuration Persistence: Securely stores resolved configuration on encrypted media
//   - Optional operator signature support for additional verification
//
// # Provisioning Process
//
// The tool follows a secure provisioning workflow:
//
//  1. Initial Provisioning:
//  1. Generate TLS key pair and Certificate Signing Request (CSR)
//  2. Optionally wait for operator signature over CSR
//  3. Register with provisioning server using TEE attestation
//  4. Derive disk encryption key from app privkey and disk label
//     The disk label is generated randomly when attaching a new disk and written to LUKS header
//     The disk label is read from LUKS header metadata if disk is already provisioned
//  5. Write certificates, keys, and configuration to encrypted storage
//
// # Operator Signature Flow
//
// When operator signature is enabled, the tool:
//
//   - Calculates hash of the instance's public key
//   - Exposes HTTP endpoints for operator interaction
//   - Waits for a valid signature from an authorized operator
//   - Embeds the signature as an extension in the CSR
//   - Continues with registration once signature is received
//
// This approach provides additional security by ensuring that only
// instances approved by an operator can register with the system.
//
// # Usage
//
// The tool is typically run when a TEE instance first boots:
//
//	autoprovision --app-contract=0x1234... [options]
//
// Once successful, the instance will have:
//   - Mounted encrypted persistent storage
//   - TLS certificate and key for secure communication
//   - Application private key for secure secret management
//   - Resolved configuration from the registry
package main
