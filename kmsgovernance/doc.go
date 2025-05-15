// Package kmsgovernance provides a client for interacting with the KMS governance
// smart contract in the TEE Registry System.
//
// The KMS governance contract controls which TEE instances can interact with the
// Key Management System by maintaining a whitelist of approved identities based on
// attestation evidence. This allows for decentralized, transparent governance of
// cryptographic material access.
//
// This package implements a client that enables:
//   - Retrieval of PKI information (CA certificates, public keys, attestations)
//   - Identity computation from attestation reports (DCAP and MAA)
//   - Identity verification and whitelisting
//   - Onboarding request management for new instances
//   - Domain name registration for service discovery
//
// The governance client implements the WorkloadGovernance interface, providing
// methods to compute identity hashes from attestation reports and check whether
// identities are allowed:
//
//	// WorkloadGovernance interface methods
//	func (c *KmsGovernanceClient) DCAPIdentity(report interfaces.DCAPReport, events []interfaces.DCAPEvent) ([32]byte, error)
//	func (c *KmsGovernanceClient) MAAIdentity(report interfaces.MAAReport) ([32]byte, error)
//	func (c *KmsGovernanceClient) IdentityAllowed(identity [32]byte, operator [20]byte) (bool, error)
//
// It also implements the OnchainDiscovery interface for service information retrieval:
//
//	// OnchainDiscovery interface methods
//	func (c *KmsGovernanceClient) PKI() (interfaces.AppPKI, error)
//	func (c *KmsGovernanceClient) InstanceDomainNames() ([]string, error)
//
// Additional governance methods enable TEE identity management:
//
//	// Identity management methods
//	func (c *KmsGovernanceClient) WhitelistDCAP(report interfaces.DCAPReport) (*types.Transaction, error)
//	func (c *KmsGovernanceClient) WhitelistMAA(report interfaces.MAAReport) (*types.Transaction, error)
//	func (c *KmsGovernanceClient) WhitelistIdentity(identity [32]byte) (*types.Transaction, error)
//	func (c *KmsGovernanceClient) RemoveWhitelistedIdentity(identity [32]byte) (*types.Transaction, error)
//
// Example usage:
//
//	client, err := kmsgovernance.NewKmsGovernanceClient(ethClient, backend, contractAddr)
//	if err != nil {
//	    log.Fatalf("Failed to create KMS governance client: %v", err)
//	}
//
//	// Set transaction options for state-modifying operations
//	client.SetTransactOpts(auth)
//
//	// Get PKI information
//	pki, err := client.PKI()
//
//	// Check if a TEE identity is allowed
//	allowed, err := client.IdentityAllowed(identity, operator)
package kmsgovernance
