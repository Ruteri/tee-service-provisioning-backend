package registry

import (
	"context"
	"errors"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"

	"github.com/ruteri/poc-tee-registry/bindings/registry"
	"github.com/ruteri/poc-tee-registry/interfaces"
)

type OnchainRegistryClient struct {
    contract *registry.Registry
    client   bind.ContractBackend
	backend  bind.DeployBackend
    address  common.Address
    auth     *bind.TransactOpts
}

// NewOnchainRegistryClient creates a new client for interacting with the Registry contract
func NewOnchainRegistryClient(client bind.ContractBackend, backend bind.DeployBackend, address common.Address) (*OnchainRegistryClient, error) {
    contract, err := registry.NewRegistry(address, client)
    if err != nil {
        return nil, err
    }

    return &OnchainRegistryClient{
        contract: contract,
        client:   client,
		backend: backend,
        address:  address,
    }, nil
}

// SetTransactOpts sets the transaction options for functions that modify state
func (c *OnchainRegistryClient) SetTransactOpts(auth *bind.TransactOpts) {
    c.auth = auth
}

// GetPKI retrieves the Certificate Authority and application public key information
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

// IsWhitelisted checks if an identity hash is whitelisted
func (c *OnchainRegistryClient) IsWhitelisted(identity [32]byte) (bool, error) {
    opts := &bind.CallOpts{Context: context.Background()}
    
    return c.contract.WhitelistedIdentities(opts, identity)
}

// GetConfig retrieves a configuration by its hash
func (c *OnchainRegistryClient) GetConfig(configHash [32]byte) ([]byte, error) {
    opts := &bind.CallOpts{Context: context.Background()}

    return c.contract.Configs(opts, configHash)
}

// GetSecret retrieves a secret by its hash
func (c *OnchainRegistryClient) GetSecret(secretHash [32]byte) ([]byte, error) {
    opts := &bind.CallOpts{Context: context.Background()}

    return c.contract.EncryptedSecrets(opts, secretHash)
}

// ComputeDCAPIdentity calculates the identity hash for a DCAP report
func (c *OnchainRegistryClient) ComputeDCAPIdentity(report *interfaces.DCAPReport) ([32]byte, error) {
    opts := &bind.CallOpts{Context: context.Background()}

    // The contract now expects an empty array of DCAPEvents as a second parameter
    emptyEventLog := []registry.RegistryDCAPEvent{}
    
    return c.contract.DCAPIdentity(opts, *report, emptyEventLog)
}

// ComputeMAAIdentity calculates the identity hash for a MAA report
func (c *OnchainRegistryClient) ComputeMAAIdentity(report *interfaces.MAAReport) ([32]byte, error) {
    opts := &bind.CallOpts{Context: context.Background()}
    
    return c.contract.MAAIdentity(opts, *report)
}

// IdentityConfigMap gets the config hash assigned to an identity
func (c *OnchainRegistryClient) IdentityConfigMap(identity [32]byte) ([32]byte, error) {
    opts := &bind.CallOpts{Context: context.Background()}
    
    return c.contract.IdentityConfigMap(opts, identity)
}

// AllStorageBackends retrieves all storage backends
func (c *OnchainRegistryClient) AllStorageBackends() ([]string, error) {
    opts := &bind.CallOpts{Context: context.Background()}

    return c.contract.AllStorageBackends(opts)
}

// AddStorageBackend adds a new storage backend
func (c *OnchainRegistryClient) AddStorageBackend(locationURI string) (*types.Transaction, error) {
    if c.auth == nil {
        return nil, ErrNoTransactOpts
    }

    tx, err := c.contract.SetStorageBackend(c.auth, locationURI)
    return tx, err
}

// RemoveStorageBackend removes a storage backend
func (c *OnchainRegistryClient) RemoveStorageBackend(locationURI string) (*types.Transaction, error) {
    if c.auth == nil {
        return nil, ErrNoTransactOpts
    }

    tx, err := c.contract.RemoveStorageBackend(c.auth, locationURI)
    return tx, err
}

// RegisterInstanceDomainName registers a new instance domain name
func (c *OnchainRegistryClient) RegisterInstanceDomainName(domain string) (*types.Transaction, error) {
    if c.auth == nil {
        return nil, ErrNoTransactOpts
    }

    tx, err := c.contract.RegisterInstanceDomainName(c.auth, domain)
    return tx, err
}

// AllInstanceDomainNames retrieves all registered instance domain names
func (c *OnchainRegistryClient) AllInstanceDomainNames() ([]string, error) {
    opts := &bind.CallOpts{Context: context.Background()}
    
    return c.contract.AllInstanceDomainNames(opts)
}

// AddConfig adds a new configuration and returns its hash
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

// AddSecret adds a new encrypted secret and returns its hash
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

// SetConfigForDCAP sets the configuration for a DCAP report
func (c *OnchainRegistryClient) SetConfigForDCAP(report *interfaces.DCAPReport, configHash [32]byte) (*types.Transaction, error) {
    if c.auth == nil {
        return nil, ErrNoTransactOpts
    }

    // The contract now expects an empty array of DCAPEvents as a second parameter
    emptyEventLog := []registry.RegistryDCAPEvent{}
    
    tx, err := c.contract.SetConfigForDCAP(c.auth, *report, emptyEventLog, configHash)
    return tx, err
}

// SetConfigForMAA sets the configuration for a MAA report
func (c *OnchainRegistryClient) SetConfigForMAA(report *interfaces.MAAReport, configHash [32]byte) (*types.Transaction, error) {
    if c.auth == nil {
        return nil, ErrNoTransactOpts
    }

    tx, err := c.contract.SetConfigForMAA(c.auth, *report, configHash)
    return tx, err
}

// RemoveWhitelistedIdentity removes a whitelisted identity
func (c *OnchainRegistryClient) RemoveWhitelistedIdentity(identity [32]byte) (*types.Transaction, error) {
    if c.auth == nil {
        return nil, ErrNoTransactOpts
    }

    tx, err := c.contract.RemoveWhitelistedIdentity(c.auth, identity)
    return tx, err
}

// Error definitions
var (
    ErrNoTransactOpts = errors.New("no authorized transactor available")
)

type RegistryFactory struct {
	client bind.ContractBackend
	backend bind.DeployBackend
}

func NewRegistryFactory(client bind.ContractBackend, backend bind.DeployBackend) *RegistryFactory {
	return &RegistryFactory{client: client, backend: backend}
}

func (f *RegistryFactory) RegistryFor(address interfaces.ContractAddress) (interfaces.OnchainRegistry, error) {
	return NewOnchainRegistryClient(f.client, f.backend, common.Address(address))
}
