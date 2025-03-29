/*
Package httpserver implements an HTTP server for a TEE (Trusted Execution Environment) registry system.

It provides API endpoints that allow TEE instances to securely register themselves and retrieve 
application-specific cryptographic materials and configuration. The server verifies attestation 
evidence to ensure only legitimate and whitelisted TEE instances can obtain sensitive materials.

Main features:

  • TEE instance registration with attestation validation
  • Retrieval of cryptographic materials (private keys, certificates)
  • Retrieval of application metadata and configuration
  • Secret management with server-side decryption
  • Health and diagnostics endpoints

# Secret Management

The server handles pre-encrypted secrets securely:

  • Secrets are stored encrypted in storage backends (encrypted with the app's public key)
  • Referenced in config templates using __SECRET_REF_<hash> syntax
  • During template processing, the server:
    - Fetches the encrypted secret from storage
    - Decrypts it using the app's private key from KMS
    - Embeds the plaintext secret in the configuration sent to the TEE instance
  • JSON secrets are inserted as objects, non-JSON as properly escaped strings
  • Decryption failures are logged and the reference is omitted from the configuration

API Endpoints:

  • POST /api/attested/register/{contract_address} - Register a TEE instance
  • GET /api/public/app_metadata/{contract_address} - Get application metadata
  • GET /livez - Liveness check
  • GET /readyz - Readiness check
  • GET /drain - Gracefully mark server as not ready
  • GET /undrain - Mark server as ready

The package integrates with the interfaces.KMS, interfaces.StorageBackendFactory, and 
interfaces.RegistryFactory interfaces to provide a complete solution for TEE instance 
registration and management.

Example usage:

	// Create the dependencies
	kmsInstance := // initialize KMS
	storageFactory := // initialize StorageFactory  
	registryFactory := // initialize RegistryFactory
	logger := // initialize logger

	// Create handler
	handler := httpserver.NewHandler(kmsInstance, storageFactory, registryFactory, logger)

	// Configure server
	config := &httpserver.HTTPServerConfig{
		ListenAddr:              ":8080",
		MetricsAddr:             ":9090",
		EnablePprof:             false,
		Log:                     logger,
		DrainDuration:           30 * time.Second,
		GracefulShutdownDuration: 30 * time.Second,
		ReadTimeout:             5 * time.Second, 
		WriteTimeout:            10 * time.Second,
	}

	// Create and start server
	server, err := httpserver.New(config, handler)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Run in background
	server.RunInBackground()

	// Shutdown gracefully on exit
	defer server.Shutdown()
*/
package httpserver
