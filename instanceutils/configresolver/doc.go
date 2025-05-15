// Package configresolver provides functionality for resolving TEE instance
// configurations using onchain-governed storage backends and secure secret
// management.
//
// The configresolver package implements the standard application configuration
// and secrets framework for the TEE registry system. It works with onchain
// provisioning governance contracts to fetch and process configuration templates
// from content-addressed storage backends, resolving references and decrypting
// secrets.
//
// # Key Features
//
// - Content-addressed configuration resolution from multiple storage backends
// - Transparent reference resolution in configuration templates
// - Secure secret handling with asymmetric encryption
// - Support for multiple storage backend types (file, S3, IPFS, onchain, GitHub, Vault)
//
// # Configuration Processing
//
// The package resolves two types of references in configuration templates:
//
// - Config references (format: __CONFIG_REF_<hash>) - Replaced with content from storage
// - Secret references (format: __SECRET_REF_<hash>) - Replaced with decrypted secret content
//
// # Security Model
//
// Secrets are pre-encrypted with the application's public key and can only
// be decrypted by authorized TEE instances with access to the corresponding
// private key. This ensures that sensitive data remains protected throughout the
// configuration lifecycle.
//
// # Workflow
//
// 1. The instance obtains its identity through attestation verification
// 2. The identity is used to look up a configuration hash in the governance contract
// 3. Storage backend URIs are retrieved from the governance contract
// 4. The configuration template is fetched from available storage backends
// 5. References in the template are resolved recursively
// 6. Encrypted secrets are decrypted using the application's private key
// 7. The fully resolved configuration is returned to the instance
//
// # Usage Example
//
//	// Create storage factory
//	factory := storage.NewStorageBackendFactory(logger, registryFactory)
//
//	// Resolve configuration using provisioning governance contract
//	config, err := configresolver.ResolveConfiguration(
//		ctx,
//		logger,
//		provisioningContract,
//		factory,
//		configHash,
//		appPrivkey,
//	)
package configresolver
