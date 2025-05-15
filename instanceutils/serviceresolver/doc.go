// Package serviceresolver provides utilities for TEE (Trusted Execution
// Environment) service discovery and metadata resolution through onchain
// contracts and DNS.
//
// The serviceresolver package implements the DNS Service discovery and TLS-based
// authorization and authentication portion of the TEE registry system. It works
// with onchain discovery contracts to retrieve application PKI information and
// resolve domain names to IP addresses for peer discovery.
//
// # Key Features
//
// - Retrieval of application PKI from onchain governance contracts
// - Resolution of domain names registered in onchain contracts to IPs
// - Support for SRV record DNS resolution
// - Aggregation of service metadata for secure peer connections
//
// # Discovery Workflow
//
// The service discovery process follows these steps:
//
// 1. Query the onchain discovery contract for registered domain names
// 2. Resolve these domain names to IP addresses using DNS SRV records
// 3. Retrieve the application's PKI information from the contract
// 4. Return aggregated service metadata (PKI, IPs) for secure connections
//
// This approach enables decentralized service discovery with onchain governance
// while leveraging standard DNS for IP resolution, creating a flexible system that
// works with existing infrastructure.
//
// # TLS-Based Authentication
//
// The package enables secure TLS-based authentication between TEE instances:
//
// - Each application has a certificate authority managed by the TEE KMS
// - CA certificates are published through the onchain discovery contract
// - Instances use the CA to validate peer certificates
// - This creates a secure, application-specific authentication mechanism
//
// # Usage Example
//
//	// Create a contract client for the application
//	contract := registry.RegistryFor(contractAddress)
//
//	// Resolve service metadata
//	metadata, err := serviceresolver.ResolveServiceMetadata(contract)
//	if err != nil {
//		log.Fatalf("Failed to resolve service: %v", err)
//	}
//
//	// Use metadata.PKI for TLS verification
//	// Use metadata.IPs for connecting to instances
package serviceresolver
