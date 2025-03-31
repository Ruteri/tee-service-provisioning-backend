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

	pki, err := c.contract.AppPki(opts)
	if err != nil {
		return nil, err
	}

	return &interfaces.AppPKI{
		Ca:          pki.Ca,
		Pubkey:      pki.Pubkey,
		Attestation: pki.Attestation,
	}, nil
}

// IsWhitelisted checks if an identity hash is whitelisted in the registry.
func (c *OnchainRegistryClient) IsWhitelisted(identity [32]byte) (bool, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	return c.contract.WhitelistedIdentities(opts, identity)
}

// GetConfig retrieves a configuration by its hash from the registry.
func (c *OnchainRegistryClient) GetConfig(configHash [32]byte) ([]byte, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	return c.contract.Configs(opts, configHash)
}

// GetSecret retrieves an encrypted secret by its hash from the registry.
func (c *OnchainRegistryClient) GetSecret(secretHash [32]byte) ([]byte, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	return c.contract.EncryptedSecrets(opts, secretHash)
}

// ComputeDCAPIdentity calculates the identity hash for a DCAP report
// using the same algorithm as the on-chain registry.
func (c *OnchainRegistryClient) ComputeDCAPIdentity(report *interfaces.DCAPReport) ([32]byte, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	// The contract expects an empty array of DCAPEvents as a second parameter
	emptyEventLog := []registry.RegistryDCAPEvent{}

	return c.contract.DCAPIdentity(opts, *report, emptyEventLog)
}

// ComputeMAAIdentity calculates the identity hash for a MAA report
// using the same algorithm as the on-chain registry.
func (c *OnchainRegistryClient) ComputeMAAIdentity(report *interfaces.MAAReport) ([32]byte, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	return c.contract.MAAIdentity(opts, *report)
}

// IdentityConfigMap gets the config hash assigned to an identity in the registry.
func (c *OnchainRegistryClient) IdentityConfigMap(identity [32]byte) ([32]byte, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	return c.contract.IdentityConfigMap(opts, identity)
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

// AddConfig adds a new configuration to the registry and returns its hash.
// Returns the content hash, transaction, and an error if the transaction could not be sent.
func (c *OnchainRegistryClient) AddConfig(data []byte) ([32]byte, *types.Transaction, error) {
	if c.auth == nil {
		return [32]byte{}, nil, ErrNoTransactOpts
	}

	tx, err := c.contract.AddConfig(c.auth, data)
	if err != nil {
		return [32]byte{}, nil, err
	}

	return crypto.Keccak256Hash(data), tx, nil
}

// AddSecret adds a new encrypted secret to the registry and returns its hash.
// Returns the content hash, transaction, and an error if the transaction could not be sent.
func (c *OnchainRegistryClient) AddSecret(data []byte) ([32]byte, *types.Transaction, error) {
	if c.auth == nil {
		return [32]byte{}, nil, ErrNoTransactOpts
	}

	tx, err := c.contract.AddSecret(c.auth, data)
	if err != nil {
		return [32]byte{}, nil, err
	}

	return crypto.Keccak256Hash(data), tx, nil
}

// SetConfigForDCAP sets the configuration for a DCAP report in the registry.
// Returns the transaction and an error if the transaction could not be sent.
func (c *OnchainRegistryClient) SetConfigForDCAP(report *interfaces.DCAPReport, configHash [32]byte) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	// The contract expects an empty array of DCAPEvents as a second parameter
	emptyEventLog := []registry.RegistryDCAPEvent{}

	tx, err := c.contract.SetConfigForDCAP(c.auth, *report, emptyEventLog, configHash)
	return tx, err
}

// SetConfigForMAA sets the configuration for a MAA report in the registry.
// Returns the transaction and an error if the transaction could not be sent.
func (c *OnchainRegistryClient) SetConfigForMAA(report *interfaces.MAAReport, configHash [32]byte) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	tx, err := c.contract.SetConfigForMAA(c.auth, *report, configHash)
	return tx, err
}

// RemoveWhitelistedIdentity removes a whitelisted identity from the registry.
// Returns the transaction and an error if the transaction could not be sent.
func (c *OnchainRegistryClient) RemoveWhitelistedIdentity(identity [32]byte) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	tx, err := c.contract.RemoveWhitelistedIdentity(c.auth, identity)
	return tx, err
}

// ErrNoTransactOpts is returned when a transaction is attempted without first setting transaction options.
var ErrNoTransactOpts = errors.New("no authorized transactor available")

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
	return NewOnchainRegistryClient(f.client, f.backend, common.Address(address))
}
