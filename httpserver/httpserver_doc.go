/*
Package httpserver implements an HTTP server for a TEE (Trusted Execution Environment) registry system.

It provides API endpoints that allow TEE instances to securely register themselves and retrieve
application-specific cryptographic materials and configuration. The server verifies attestation
evidence to ensure only legitimate and whitelisted TEE instances can obtain sensitive materials.

The package includes two main components:

1. Registry API - The primary API for TEE attestation and configuration
2. Admin API - A separate API for KMS bootstrapping when using ShamirKMS

# Registry API Features

  - TEE instance registration with attestation validation
  - Retrieval of cryptographic materials (private keys, certificates)
  - Retrieval of application metadata and configuration
  - Secret management with server-side decryption
  - Health and diagnostics endpoints

# Admin API Features (for ShamirKMS bootstrap)

  - Master key generation and share distribution to administrators
  - Recovery mode for reconstructing the master key from administrator shares
  - Admin authentication and authorization
  - KMS status monitoring

# Secret Management

The server handles pre-encrypted secrets securely:

  - Secrets are stored encrypted in storage backends (encrypted with the app's public key)
  - Referenced in config templates using __SECRET_REF_<hash> syntax
  - During template processing, the server:
  - Fetches the encrypted secret from storage
  - Decrypts it using the app's private key from KMS
  - Embeds the plaintext secret in the configuration sent to the TEE instance
  - JSON secrets are inserted as objects, non-JSON as properly escaped strings
  - Decryption failures are logged and the reference is omitted from the configuration

# Registry API Endpoints

  - POST /api/attested/register/{contract_address} - Register a TEE instance
  - GET /api/public/app_metadata/{contract_address} - Get application metadata
  - GET /livez - Liveness check
  - GET /readyz - Readiness check
  - GET /drain - Gracefully mark server as not ready
  - GET /undrain - Mark server as ready

# Admin API Endpoints

  - GET /status - Get current bootstrap status
  - POST /init/generate - Generate master key and distribute shares
  - POST /init/recover - Start recovery process
  - POST /share - Submit a share during recovery

# KMS Types

The server supports two types of Key Management Systems:

 1. SimpleKMS - A basic KMS that uses a fixed master key
 2. ShamirKMS - An enhanced KMS that uses Shamir's Secret Sharing for secure master key management,
    requiring multiple administrator shares to reconstruct the master key

When using ShamirKMS, the server follows this process:

 1. Start the admin API server on a separate port
 2. Wait for administrators to either:
    a) Generate a new master key and distribute shares, or
    b) Reconstruct the master key by submitting their shares
 3. Once the KMS is bootstrapped, start the registry API server

# Example Usage

	// Set up configuration
	cfg := &httpserver.HTTPServerConfig{
		ListenAddr:      ":8080",
		AdminListenAddr: ":8081",       // If using ShamirKMS
		MetricsAddr:     ":9090",
		Log:             logger,
		UseKMSBootstrap: true,          // If using ShamirKMS
		AdminKeys:       adminPubKeys,  // If using ShamirKMS
		BootstrapTimeout: 5 * time.Minute,
		DrainDuration:    30 * time.Second,
		GracefulShutdownDuration: 30 * time.Second,
		ReadTimeout:     5 * time.Second,
		WriteTimeout:    10 * time.Second,
	}

	// Create handler with initial KMS value (will be replaced during bootstrap if using ShamirKMS)
	handler := httpserver.NewHandler(initialKMS, storageFactory, registryFactory, logger)

	// Create server
	server, err := httpserver.New(cfg, handler)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// If using ShamirKMS, bootstrap first
	if cfg.UseKMSBootstrap {
		shamirKMS, err := server.Bootstrap()
		if err != nil {
			log.Fatalf("Failed to bootstrap KMS: %v", err)
		}

		// Update handler with bootstrapped KMS
		handler.SetKMS(shamirKMS)
	}

	// Run in background
	server.RunInBackground()

	// Shutdown gracefully on exit
	defer server.Shutdown()

This package integrates with the interfaces.KMS, interfaces.StorageBackendFactory, and
interfaces.RegistryFactory interfaces to provide a complete solution for TEE instance
registration and management.
*/
package httpserver
