// Package instanceutils provides utilities for TEE (Trusted Execution Environment) instance
// management, secure communication, and provisioning in a registry-based confidential
// computing system.
//
// The package implements a set of interfaces and clients that enable TEE instances to
// discover each other, establish secure connections, register with a provisioning system,
// and manage their lifecycle across multiple applications.
//
// # Core Interface
//
// AppResolver: Provides cryptographic materials (certificates, keys) for secure inter-instance
//
//	communication, including cross-application connections.
//
// # Provisioning and Registration
//
// The package provides client implementations for instance registration:
//
//   - ProvisioningClient: Communicates with the provisioning server for instance registration
//   - LocalKMSRegistrationProvider: Uses a local KMS for registration (useful for testing)
//   - MockRegistrationProvider: A mock implementation for testing
//
// This includes functionality for creating Certificate Signing Requests (CSRs) and handling
// registration responses containing cryptographic materials and configuration.
//
// # Certificate Management
//
// Certificate management components enable secure mTLS connections between instances:
//
//   - AppCertificateManager: Manages application certificates for verified connections
//   - CertificateManager: Interface defining certificate operations between TEE instances
//
// # Tools
//
// The package includes three command-line tools:
//
// ## 1. Operator Config API
//
// A lightweight HTTP server that accepts operator configuration before an instance
// fully starts. It functions as a configuration injection point during instance
// bootstrapping.
//
// Features:
//   - Listens for HTTP POST requests to /config
//   - Writes received configuration to a specified file
//   - Optionally uses TLS with a self-signed certificate
//   - Exits after successfully receiving configuration
//
// ## 2. Auto-provisioning Tool
//
// A provisioning utility that:
//   - Registers with the TEE registry system
//   - Sets up encrypted persistent storage
//   - Stores cryptographic materials and configuration
//   - Handles both new provisioning and re-provisioning scenarios
//
// Features:
//   - LUKS encrypted disk management
//   - Secure storage of TLS certificates and keys
//   - Configuration persistence across restarts
//   - Attestation-based identity verification
//
// ## 3. Proxy Router
//
// A secure proxy for TEE instance communication that:
//   - Routes requests between instances of the same or different applications
//   - Enforces mutual TLS authentication
//   - Supports targeted and broadcast request patterns
//   - Provides load balancing across multiple instances
//
// Features:
//   - Secure ingress and egress communication paths
//   - Certificate validation using application CAs
//   - Support for different routing patterns (any/single, all/broadcast)
//   - Response aggregation for broadcast requests
//
// # Usage
//
// To use the package for instance communication:
//
//	// Create an app resolver
//	resolver := instanceutils.NewRegistryAppResolver(
//		registrationProvider,
//		registryFactory,
//		5*time.Minute,
//		logger,
//	)
//
//	// Create certificate manager
//	certManager, err := proxy.NewAppCertificateManager(
//		resolver,
//		myAppContractAddr,
//		logger,
//	)
//
//	// Create and run router
//	router, err := proxy.NewHTTPRouter(proxy.RouterConfig{
//		DefaultAppContractAddress: myAppContractAddr,
//		CertManager:               certManager,
//		Resolver:                  resolver,
//		IngressListenAddr:         ":8443",
//		EgressListenAddr:          ":8080",
//		Routes:                    routes,
//		Log:                       logger,
//	})
//	router.RunInBackground()
//
// For example, to send a request to another application:
//
//	req, _ := http.NewRequest("GET", "http://localhost:8080/api/resource", nil)
//	req.Header.Set("X-Target-App", targetAppContractAddress)
//	req.Header.Set("X-Request-Type", "any")  // Single instance request
//	resp, err := http.DefaultClient.Do(req)
package instanceutils
