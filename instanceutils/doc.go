// Package instanceutils provides utilities for TEE (Trusted Execution Environment)
// instance management, secure communication, and provisioning in a registry-based
// confidential computing system.
//
// The package implements a set of interfaces and clients that enable TEE
// instances to discover each other, establish secure connections, register with a
// provisioning system, and manage their lifecycle across multiple applications.
//
// # Core Subpackages
//
// - configresolver: Resolves configuration from content-addressed storage backends
// - serviceresolver: Discovers peer instances using DNS and TLS-based authentication
// - diskutil: Manages encrypted persistent storage with LUKS for TEE instances
// - autoprovision: Manages TEE instance bootstrapping with disk encryption
//
// # Configuration Resolution
//
// The configresolver package provides functionality for retrieving and processing
// configurations:
//
// - Retrieves configuration hash from onchain governance contract
// - Fetches configuration content from registered storage backends
// - Resolves references to other configs and secrets
// - Decrypts secrets using application's private key
//
// # Service Discovery
//
// The serviceresolver package enables secure communication between instances:
//
// - Retrieves domain names from onchain discovery contract
// - Resolves domains to IP addresses using standard DNS
// - Fetches CA certificates for TLS validation
// - Provides metadata for establishing secure connections
//
// # Encrypted Storage Management
//
// The diskutil package provides secure disk management functionality:
//
// - Creates and mounts LUKS2 encrypted volumes
// - Derives encryption keys from application credentials
// - Stores disk metadata securely in LUKS tokens
// - Supports both new disk provisioning and remounting existing disks
// - Integrates with application private keys for secure key derivation
//
// # Instance Provisioning
//
// The autoprovision tool automates the process of:
//
// - Registering a new TEE instance with the registry system
// - Setting up encrypted persistent storage using LUKS
// - Securely storing TLS certificates, keys, and application configuration
// - Supporting both initial provisioning and re-provisioning scenarios
//
// # Security Model
//
// The package implements a comprehensive security model:
//
// - Attestation-based identity verification
// - TLS-based authentication with application-specific CAs
// - Encrypted persistent storage with keys derived from application credentials
// - Secure configuration with reference resolution and secret decryption
// - Optional operator signature verification for additional authorization
//
// # Usage
//
// To use the package for instance provisioning and communication:
//
//	// Create a storage factory
//	factory := storage.NewStorageBackendFactory(logger, registryFactory)
//
//	// Resolve configuration from governance contract
//	config, err := configresolver.ResolveConfiguration(
//		ctx,
//		logger,
//		provisioningContract,
//		factory,
//		configHash,
//		appPrivkey,
//	)
//
//	// Resolve service metadata for peer discovery
//	metadata, err := serviceresolver.ResolveServiceMetadata(discoveryContract)
//
//	// Provision or mount encrypted disk
//	diskConfig := diskutil.NewDiskConfig(devicePath, mountPoint, "cryptdisk")
//	diskLabel, isNew, err := diskutil.ProvisionOrMountDisk(diskConfig, appPrivkey)
//
//	// Use metadata.PKI for TLS verification
//	// Use metadata.IPs for connecting to instances
package instanceutils
