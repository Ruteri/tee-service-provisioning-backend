// Package registry provides an interface to interact with on-chain registry contracts
// for TEE (Trusted Execution Environment) identity verification and configuration management.
package registry

import (
	"context"
	"errors"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ruteri/tee-service-provisioning-backend/bindings/registry"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// ErrNoTransactOpts is returned when a transaction is attempted without first setting transaction options.
var ErrNoTransactOpts = errors.New("no authorized transactor available")

// OnchainRegistryClient implements the interfaces.OnchainRegistry interface for
// interacting with a Registry smart contract deployed on a blockchain.
type OnchainRegistryClient struct {
	contract *registry.Registry
	client   bind.ContractBackend
	backend  bind.DeployBackend
	address  common.Address
	auth     *bind.TransactOpts
}

// NewOnchainRegistryClient creates a new client for interacting with the Registry contract
// at the specified address. It requires a ContractBackend for reading from the blockchain
// and a DeployBackend for transaction operations.
func NewOnchainRegistryClient(client bind.ContractBackend, backend bind.DeployBackend, address common.Address) (*OnchainRegistryClient, error) {
	contract, err := registry.NewRegistry(address, client)
	if err != nil {
		return nil, err
	}

	return &OnchainRegistryClient{
		contract: contract,
		client:   client,
		backend:  backend,
		address:  address,
	}, nil
}

// SetTransactOpts sets the transaction options required for functions that modify state.
// This must be called before using any methods that send transactions to the blockchain.
func (c *OnchainRegistryClient) SetTransactOpts(auth *bind.TransactOpts) {
	c.auth = auth
}

// GetPKI retrieves the Certificate Authority and application public key information
// from the registry contract.
func (c *OnchainRegistryClient) GetPKI() (*interfaces.AppPKI, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	pki, err := c.contract.GetPKI(opts)
	if err != nil {
		return nil, err
	}

	return &interfaces.AppPKI{
		Ca:          pki.Ca,
		Pubkey:      pki.Pubkey,
		Attestation: pki.Attestation,
	}, nil
}

// ComputeDCAPIdentity calculates the identity hash for a DCAP report
// using the same algorithm as the on-chain registry.
func (c *OnchainRegistryClient) ComputeDCAPIdentity(report *interfaces.DCAPReport) ([32]byte, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	// Convert interfaces.DCAPReport to registry.DCAPReport
	contractReport := registry.DCAPReport{
		MrTd:          report.MrTd,
		RTMRs:         report.RTMRs,
		MrOwner:       report.MrOwner,
		MrConfigId:    report.MrConfigId,
		MrConfigOwner: report.MrConfigOwner,
	}

	// The contract expects an empty array of DCAPEvents as a second parameter
	emptyEventLog := []registry.DCAPEvent{}

	return c.contract.DCAPIdentity(opts, contractReport, emptyEventLog)
}

// ComputeMAAIdentity calculates the identity hash for an MAA report
// using the same algorithm as the on-chain registry.
func (c *OnchainRegistryClient) ComputeMAAIdentity(report *interfaces.MAAReport) ([32]byte, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	// Convert interfaces.MAAReport to registry.MAAReport
	contractReport := registry.MAAReport{
		PCRs: report.PCRs,
	}

	return c.contract.MAAIdentity(opts, contractReport)
}

// IdentityConfigMap gets the config hash assigned to an identity in the registry.
func (c *OnchainRegistryClient) IdentityConfigMap(identity [32]byte) ([32]byte, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	return c.contract.GetConfigForIdentity(opts, identity)
}

// AllStorageBackends retrieves all storage backend URIs registered in the contract.
func (c *OnchainRegistryClient) AllStorageBackends() ([]string, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	return c.contract.AllStorageBackends(opts)
}

// AddStorageBackend adds a new storage backend URI to the registry.
// Returns the transaction and an error if the transaction could not be sent.
func (c *OnchainRegistryClient) AddStorageBackend(locationURI string) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	tx, err := c.contract.SetStorageBackend(c.auth, locationURI)
	return tx, err
}

// RemoveStorageBackend removes a storage backend URI from the registry.
// Returns the transaction and an error if the transaction could not be sent.
func (c *OnchainRegistryClient) RemoveStorageBackend(locationURI string) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	tx, err := c.contract.RemoveStorageBackend(c.auth, locationURI)
	return tx, err
}

// RegisterInstanceDomainName registers a new instance domain name in the registry.
// Returns the transaction and an error if the transaction could not be sent.
func (c *OnchainRegistryClient) RegisterInstanceDomainName(domain string) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	tx, err := c.contract.RegisterInstanceDomainName(c.auth, domain)
	return tx, err
}

// AllInstanceDomainNames retrieves all registered instance domain names from the registry.
func (c *OnchainRegistryClient) AllInstanceDomainNames() ([]string, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	return c.contract.AllInstanceDomainNames(opts)
}

// AddArtifact adds a new artifact to the registry and returns its hash.
// This can be configuration data, encrypted secrets, or any other content.
// Returns the content hash, transaction, and an error if the transaction could not be sent.
func (c *OnchainRegistryClient) AddArtifact(data []byte) ([32]byte, *types.Transaction, error) {
	if c.auth == nil {
		return [32]byte{}, nil, ErrNoTransactOpts
	}

	tx, err := c.contract.AddArtifact(c.auth, data)
	if err != nil {
		return [32]byte{}, nil, err
	}

	var hash [32]byte = crypto.Keccak256Hash(data)
	return hash, tx, nil
}

// GetArtifact retrieves an artifact by its hash from the registry.
// This can be a configuration, secret, or any other data.
func (c *OnchainRegistryClient) GetArtifact(artifactHash [32]byte) ([]byte, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	return c.contract.GetArtifact(opts, artifactHash)
}

// SetConfigForDCAP associates an artifact with a DCAP-attested identity.
// Returns the transaction and an error if the transaction could not be sent.
func (c *OnchainRegistryClient) SetConfigForDCAP(report *interfaces.DCAPReport, artifactHash [32]byte) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	// Convert interfaces.DCAPReport to registry.DCAPReport
	contractReport := registry.DCAPReport{
		MrTd:          report.MrTd,
		RTMRs:         report.RTMRs,
		MrOwner:       report.MrOwner,
		MrConfigId:    report.MrConfigId,
		MrConfigOwner: report.MrConfigOwner,
	}

	// The contract expects an empty array of DCAPEvents as a second parameter
	emptyEventLog := []registry.DCAPEvent{}

	tx, err := c.contract.SetConfigForDCAP(c.auth, contractReport, emptyEventLog, artifactHash)
	return tx, err
}

// SetConfigForMAA associates an artifact with an MAA-attested identity.
// Returns the transaction and an error if the transaction could not be sent.
func (c *OnchainRegistryClient) SetConfigForMAA(report *interfaces.MAAReport, artifactHash [32]byte) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	// Convert interfaces.MAAReport to registry.MAAReport
	contractReport := registry.MAAReport{
		PCRs: report.PCRs,
	}

	tx, err := c.contract.SetConfigForMAA(c.auth, contractReport, artifactHash)
	return tx, err
}

// RemoveConfigMapForIdentity removes an identity's mapping to an artifact.
// Returns the transaction and an error if the transaction could not be sent.
func (c *OnchainRegistryClient) RemoveConfigMapForIdentity(identity [32]byte) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	tx, err := c.contract.RemoveConfigMapForIdentity(c.auth, identity)
	return tx, err
}

// RegistryFactory creates OnchainRegistry instances for different contract addresses.
type RegistryFactory struct {
	client  bind.ContractBackend
	backend bind.DeployBackend
}

// NewRegistryFactory creates a new factory for registry clients.
// It requires a ContractBackend for reading from the blockchain and a DeployBackend for transactions.
func NewRegistryFactory(client bind.ContractBackend, backend bind.DeployBackend) *RegistryFactory {
	return &RegistryFactory{client: client, backend: backend}
}

// RegistryFor returns an OnchainRegistry instance for the specified contract address.
func (f *RegistryFactory) RegistryFor(address interfaces.ContractAddress) (interfaces.OnchainRegistry, error) {
	// Convert interfaces.ContractAddress to common.Address
	commonAddr := common.Address(address)
	return NewOnchainRegistryClient(f.client, f.backend, commonAddr)
}
