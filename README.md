# TEE Registry System

> **WARNING**: This project is mostly AI-generated and not yet reviewed!

A decentralized provisioning system for Trusted Execution Environment (TEE) services with robust identity verification, configuration management, and secure secret handling.

## Overview

The TEE Registry System enables secure provisioning of confidential computing services through cryptographic attestation, decentralized governance, and secure configuration management. It provides a complete solution for bootstrapping TEE instances with the required cryptographic materials, configurations, and secrets while ensuring all sensitive data remains protected.

## Key Features

### Attestation-Based Identity Verification
- Support for Intel TDX and Azure Confidential Computing
- Identity verification through cryptographic attestation reports
- Measurement-based whitelisting for authorized access

### Blockchain-Based Configuration Governance
- On-chain governance for configuration management
- Role-based access control for operators and administrators
- Smart contract verification of identity and permissions

### Secure Secret Management
- Pre-encrypted secrets with asymmetric encryption
- Server-side decryption only for verified TEE instances
- Transparent reference resolution in configuration templates

### Distributed Storage System
- Content-addressed storage for configurations and secrets
- Support for multiple backend types (S3, IPFS, File, GitHub, Vault)
- Encrypted data at rest using KMS-protected keys

### Multi-Tenant Service Architecture
- Per-application governance contracts
- Isolated configuration and secret namespaces
- Safe multi-tenant access through role-based permissions

### Flexible Key Management
- Support for simple and Shamir's Secret Sharing KMS implementations
- Secure bootstrapping with multi-administrator shares
- Deterministic key derivation for reproducible cryptographic materials

## Workflow Overview

### 1. System Initialization and KMS Bootstrap

The system uses a secure KMS bootstrap process with Shamir's Secret Sharing:

1. **Initial Setup**:
   - Administrators generate key pairs and register public keys with the system
   - System deploys governance contracts that define access control policies

2. **KMS Initialization** (choose one approach):
   - **Generation Mode**: A master key is generated, split into shares, and encrypted individually for each admin
   - **Recovery Mode**: System is initialized in recovery mode awaiting admin shares

3. **Share Distribution/Collection**:
   - During generation: Each admin securely retrieves their encrypted share via authenticated endpoints
   - During recovery: Admins submit their shares with cryptographic signatures
   - When sufficient shares are collected, the KMS is unlocked and bootstrap completes

### 2. TEE Instance Provisioning

Once the KMS is bootstrapped, the system can provision TEE instances:

1. **Instance Boot**:
   - TEE instance boots with measured parameters
   - Instance generates identity keypair and exposes public key
   - Instance awaits operator configuration

2. **Instance Registration**:
   - Instance submits attestation evidence to registry API
   - Registry verifies attestation against governance contract whitelist
   - If valid, registry provides cryptographic materials (private key, TLS cert)

3. **Configuration Resolution**:
   - Registry fetches configuration template for instance based on identity
   - Resolves any references to other configurations or secrets
   - Decrypts encrypted secrets using KMS
   - Returns complete, resolved configuration to instance

4. **Peer Discovery**:
   - Instance registers with peer discovery mechanism
   - Retrieves list of other running instances
   - Establishes secure connections using trusted certificates

## Architecture

The system consists of the following components:

- **OnchainRegistry**: Smart contract for identity verification and configuration management
- **KMS**: Key management system for cryptographic operations and secret decryption
- **StorageBackend**: Content-addressed storage for configurations and secrets
- **HTTP Server**: API endpoints for TEE registration and configuration retrieval

## API Endpoints

### Registry API (Attested Access)
- `POST /api/attested/register/{contract_address}` - Register a TEE instance
- `GET /api/public/app_metadata/{contract_address}` - Get application metadata

### Admin API (For KMS Bootstrap)
- `GET /status` - Get current bootstrap status and parameters
- `POST /init/generate` - Generate master key and distribute shares to admins
- `POST /init/recover` - Start recovery process with threshold parameters
- `GET /share` - Retrieve your assigned encrypted share (admin-specific)
- `POST /share` - Submit your share during recovery with signature

The share management endpoints provide a zero-trust model where:
- Each share is encrypted specifically for one admin using their public key
- Admins can only retrieve their own shares and cannot access others' shares
- Share submission requires cryptographic proof of admin identity
- The system never has access to the plaintext master key except during initial generation

## Getting Started

### Prerequisites
- Go 1.19 or higher
- Ethereum client with RPC access
- Access to a TEE environment (TDX or Azure Confidential Computing)

### Installation
```bash
go get github.com/ruteri/poc-tee-registry
```

### Basic Usage
```go
// Initialize KMS
masterKey := make([]byte, 32)
rand.Read(masterKey)
kmsInstance, _ := kms.NewSimpleKMS(masterKey)

// Create storage factory
storageFactory := storage.NewStorageBackendFactory(logger, registryFactory)

// Initialize handler
handler := httpserver.NewHandler(kmsInstance, storageFactory, registryFactory, logger)

// Create and run server
server, _ := httpserver.New(cfg, handler)
server.RunInBackground()
```

### Admin Bootstrap Example
```go
// Load admin public keys from configuration
adminKeys, _ := httpserver.LoadAdminKeys(configFile)

// Create admin handler
adminHandler := httpserver.NewAdminHandler(logger, adminKeys)

// Set up admin API server
adminRouter := adminHandler.AdminRouter()
adminServer := &http.Server{
    Addr:    ":8081",
    Handler: adminRouter,
}

// Wait for bootstrap to complete
ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
defer cancel()
shamirKMS, err := adminServer.WaitForBootstrap(ctx)

// Update handler with bootstrapped KMS
handler.SetKMS(shamirKMS)
```

## Security Considerations

- All sensitive data must be encrypted at rest
- TLS certificates should be validated through attestation
- KMS bootstrap should use multiple administrators for Shamir's Secret Sharing
- Governance contracts should be controlled by multi-signature wallets
- Regular key rotation is recommended for long-term deployments

## License
[MIT License](LICENSE)
