# TEE Registry System

A decentralized provisioning system for Trusted Execution Environment (TEE) services with robust identity verification, configuration management, and secure secret handling.

## Overview

The TEE Registry System enables secure provisioning of confidential computing services through cryptographic attestation, decentralized governance, and secure configuration management. It provides a complete solution for bootstrapping TEE instances with the required cryptographic materials, configurations, and secrets while ensuring all sensitive data remains protected.

## Key Features

### Attestation-Based Identity Verification
- Support for Intel TDX and Azure Confidential Computing
- Identity verification through cryptographic attestation reports (DCAP and MAA)
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
- Multiple storage backends:
  - File system (local development)
  - S3-compatible storage (cloud deployments)
  - IPFS storage (decentralized content)
  - On-chain storage (using smart contracts)
  - GitHub storage (read-only from repositories)
  - Vault storage (with TLS client authentication)
- Encrypted data at rest using KMS-protected keys

### Multi-Tenant Service Architecture
- Per-application governance contracts
- Isolated configuration and secret namespaces
- Safe multi-tenant access through role-based permissions

### Flexible Key Management
- Support for simple and Shamir's Secret Sharing KMS implementations
- Secure bootstrapping with multi-administrator shares
- Deterministic key derivation for reproducible cryptographic materials

## System Architecture

The system consists of the following main components:

### Core Components

1. **API Package**
   - **Provisioner**: Handles TEE instance registration with attestation verification
   - **Server**: Provides HTTP endpoints with health checks and graceful shutdown
   - **Shamir-KMS**: Implements secure key management with Shamir's Secret Sharing

2. **CryptoUtils Package**
   - Provides cryptographic operations for secure secret management
   - Implements ECIES with AES-GCM for protecting sensitive data

3. **InstanceUtils Package**
   - **AppResolver**: Resolves application instances for secure communication
   - **AutoProvision**: Tools for TEE instance bootstrapping with disk encryption
   - **Proxy**: Secure routing between TEE instances

4. **Interfaces Package**
   - Defines core interfaces and types for the system
   - Separates interface definitions from implementations

5. **KMS Package**
   - **SimpleKMS**: Basic implementation for development and testing
   - **ShamirKMS**: Enhanced implementation with secure master key management

6. **Registry Package**
   - Interfaces with on-chain registry contracts
   - Manages TEE identities and configurations

7. **Storage Package**
   - Content-addressed storage with multiple backend implementations
   - URI-based backend configuration

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

## API Endpoints

### Registry API (Attested Access)
- `POST /api/attested/register/{contract_address}` - Register a TEE instance with attestation evidence
- `GET /api/public/app_metadata/{contract_address}` - Get application metadata (CA cert, public key)

See cmd/registry_client for more.

### Admin API (For KMS Bootstrap)
- `GET /admin/status` - Get current bootstrap status and parameters
- `POST /admin/init/generate` - Generate master key and distribute shares
- `POST /admin/init/recover` - Start recovery process with threshold parameters
- `GET /admin/share` - Retrieve your assigned encrypted share (admin-specific)
- `POST /admin/share` - Submit your share during recovery with signature

See cmd/admin for more.

## Storage Backend URIs

Storage backends are specified using URI format:

```
[scheme]://[auth@]host[:port][/path][?params]
```

Supported URIs:

- **File System**: `file:///var/lib/registry/configs/` or `file://./relative/path/`
- **S3**: `s3://bucket-name/prefix/?region=us-west-2` or `s3://ACCESS_KEY:SECRET_KEY@bucket-name/path/`
- **IPFS**: `ipfs://ipfs.example.com:5001/` or `ipfs://localhost:8080/?gateway=true&timeout=30s`
- **On-Chain**: `onchain://0x1234567890abcdef1234567890abcdef12345678`
- **GitHub**: `github://owner/repo`
- **Vault**: `vault://vault.example.com:8200/secret/data`

## License
[MIT License](LICENSE)
