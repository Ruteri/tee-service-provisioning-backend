# TEE Registry System

A decentralized provisioning system for Trusted Execution Environment (TEE) services with onchain governance, flexible storage backends, and secure service discovery.

## Overview

The TEE Registry System enables secure provisioning of confidential computing services through cryptographic attestation, onchain governance, and flexible configuration management. It provides a complete solution for bootstrapping TEE instances with the required cryptographic materials, configurations, and secrets while ensuring all sensitive data remains protected.

## Key Features

### Attestation-Based Identity Verification
- Support for Intel TDX and Azure Confidential Computing (MAA)
- Mapping from TEE report data to workload identities
- Onchain verification of attestation reports (DCAP and MAA)
- Whitelisting mechanism for authorized identity access

### Onchain Governance
- Standard onchain TEE service governance interface
- Role-based access control for operators and administrators
- Transparent and configurable governance model
- Mapping of workload identities to content-addressed configurations

### Secure Secret Management
- Application-wide secrets derived from TEE KMS
- Pre-encrypted secrets with the application's public key
- Secure key management with optional Shamir's Secret Sharing recovery
- Transparent reference resolution in configuration templates

### Content-Addressed Storage System
- Multiple, flexible storage backends for different needs
- Content addressing to decouple data from specific storage providers
- Support for various backend types:
  - File system (local development)
  - S3-compatible storage (cloud deployments)
  - IPFS storage (decentralized content)
  - On-chain storage (using smart contracts)
  - GitHub storage (read-only from repositories)
  - Vault storage (with TLS client authentication)

### DNS-Based Service Discovery
- Domain names registered in onchain contracts
- Standard DNS for IP resolution and bootstrapping
- TLS-based authentication and authorization
- Application-wide certificate authority managed by TEE KMS

### Flexible Key Management
- Support for simple and Shamir's Secret Sharing KMS implementations
- Secure bootstrapping with multi-administrator shares
- Optional onchain-driven onboarding using already bootstrapped instances

## System Architecture

The system consists of the following main components:

### Core Components

1. **Governance Interfaces**
   - **WorkloadGovernance**: Handles identity verification and whitelisting
   - **ConfigGovernance**: Manages configuration mapping and storage backends
   - **OnchainDiscovery**: Provides service metadata and domain name management

2. **Storage System**
   - Content-addressed storage with multiple backend implementations
   - Configuration and secret namespaces
   - Reference resolution for configuration templates

3. **Key Management Service**
   - Application CA and secrets key management
   - Optional Shamir's Secret Sharing recovery
   - Onchain-driven onboarding mechanism

4. **Instance Tooling**
   - Configuration resolver for retrieving and processing configurations
   - Service resolver for discovering and authenticating peers
   - Disk encryption management using application credentials

## Workflow Overview

### 1. System Initialization and KMS Bootstrap

The system uses a secure KMS bootstrap process:

1. **Initial Setup**:
   - Onchain governance contracts are deployed
   - KMS is initialized with either generation or recovery mode
   - Administrators manage shares through secure channels

2. **Configuration Preparation**:
   - Configurations and secrets are stored in content-addressed storage backends
   - References to storage backends are registered in the governance contract
   - Workload identities are whitelisted for authorized access

### 2. TEE Instance Provisioning

Once the system is bootstrapped:

1. **Instance Boot**:
   - TEE instance boots with measured parameters
   - Instance generates TLS key pair and CSR
   - Optionally waits for operator signature

2. **Identity Verification**:
   - Instance submits attestation evidence to the registry
   - Registry verifies attestation against onchain governance contract
   - If valid, registry provides cryptographic materials

3. **Configuration Resolution**:
   - Instance resolves configuration using onchain governance contract
   - Retrieves content from registered storage backends
   - Decrypts secrets using application private key

4. **Service Discovery**:
   - Instance registers domain name in onchain contract
   - Other instances discover peers through DNS resolution
   - Secure connections established using TLS with CA verification

## API Interfaces

### Governance Interfaces

```go
// WorkloadGovernance handles TEE identity verification
interface WorkloadGovernance {
    // Identity verification and whitelisting
    IdentityAllowed(identity [32]byte, operator [20]byte) (bool, error)
    DCAPIdentity(report DCAPReport, events []DCAPEvent) ([32]byte, error)
    MAAIdentity(report MAAReport) ([32]byte, error)
}

// ConfigGovernance manages configuration mapping
interface ConfigGovernance {
    // Configuration and storage management
    ConfigForIdentity(identity [32]byte, operator [20]byte) ([32]byte, error)
    StorageBackends() ([]string, error)
}

// OnchainDiscovery provides service information
interface OnchainDiscovery {
    // Service discovery
    PKI() (AppPKI, error)
    InstanceDomainNames() ([]string, error)
}
```

### Utility Functions

```go
// Resolve configuration from onchain governance
func ResolveConfiguration(
    configGovernance ConfigGovernance,
    storageFactory StorageBackendFactory,
    configHash [32]byte,
    appPrivkey AppPrivkey
) (InstanceConfig, error)

// Resolve service metadata for peer discovery
func ResolveServiceMetadata(
    discoveryContract OnchainDiscovery
) (ServiceMetadata, error)

// Map attestation to workload identity
func AttestationToIdentity(
    attestationType AttestationType,
    measurements map[int]string,
    governance WorkloadGovernance
) ([32]byte, error)
```

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
