// Package provisioner implements a secure provisioning system for Trusted Execution Environment (TEE) instances.
//
// This package enables TEE instances to register with the system by providing attestation evidence,
// which is cryptographically verified before granting access to sensitive materials and configurations.
// It implements both the server-side handling of registration requests and client-side libraries
// for TEE instances to interact with the provisioning API.
//
// # Key Components
//
//   - Handler: Processes registration requests, verifies attestation evidence,
//     signs certificates, and resolves configuration templates
//   - Server: Provides HTTP endpoints for registration and metadata retrieval
//     with health checks and graceful shutdown capabilities
//   - ProvisioningClient: Client implementation for TEE instances to register
//     and retrieve application metadata
//
// # Registration Process
//
// When a TEE instance requests registration:
//
//  1. The instance submits attestation evidence (measurements) and a CSR via HTTP headers and body
//  2. The Handler verifies the attestation to compute a unique identity for the instance
//  3. The system checks if this identity is whitelisted in the on-chain registry
//  4. If authorized, the Handler signs the CSR and prepares cryptographic materials
//  5. The Handler processes the configuration template, resolving references and decrypting secrets
//  6. The system returns the private key, signed certificate, and resolved configuration
//
// # Operator Signature Extension
//
// The system supports an optional additional authorization mechanism through operator signatures:
//
//  1. When enabled, the TEE instance generates a keypair and exposes its public key
//  2. An authorized operator signs the instance's public key using their Ethereum private key
//  3. The signature is embedded in the CSR as an X.509 extension with OID api.OIDOperatorSignature
//  4. During registration, the handler extracts the signature and recovers the operator's Ethereum address
//  5. The system checks if this operator is authorized to provision instances with the given identity
//  6. Registration proceeds only if both the TEE identity and operator signature are valid
//
// This two-factor authorization (attestation + operator signature) provides enhanced security
// for sensitive deployments and allows for explicit operator approval of each instance.
//
// # Configuration Template Processing
//
// The Handler resolves two types of references in configuration templates:
//
//   - Config references (format: __CONFIG_REF_<hash>) - Replaced with content from storage
//   - Secret references (format: __SECRET_REF_<hash>) - Replaced with decrypted secret content
//
// Secrets are pre-encrypted and only decrypted during the provisioning process
// for authorized TEE instances.
//
// # Usage Example
//
//	// Create a provisioning client
//	client := &provisioner.ProvisioningClient{
//		ServerAddr: "https://registry.example.com:8080",
//	}
//
//	// Register with attestation evidence (headers set automatically in production)
//	resp, err := client.Register(contractAddr, csrBytes)
//	if err != nil {
//		log.Fatalf("Registration failed: %v", err)
//	}
//
//	// Use the returned materials (private key, certificate, config)
//	tlsCert := resp.TLSCert
//	appConfig := resp.Config
package provisioner
