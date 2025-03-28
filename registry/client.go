package registry

import (
    "context"
    "errors"

    "github.com/ethereum/go-ethereum/accounts/abi/bind"
    "github.com/ethereum/go-ethereum/common"
    "github.com/ethereum/go-ethereum/ethclient"

    "github.com/ruteri/poc-tee-registry/bindings/registry"
    "github.com/ruteri/poc-tee-registry/interfaces"
)

type OnchainRegistryClient struct {
    contract *registry.Registry
    client   *ethclient.Client
    address  common.Address
    auth     *bind.TransactOpts
}

// NewOnchainRegistryClient creates a new client for interacting with the Registry contract
func NewOnchainRegistryClient(client *ethclient.Client, address common.Address) (*OnchainRegistryClient, error) {
    contract, err := registry.NewRegistry(address, client)
    if err != nil {
        return nil, err
    }

    return &OnchainRegistryClient{
        contract: contract,
        client:   client,
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
func (c *OnchainRegistryClient) AddStorageBackend(locationURI string) error {
    if c.auth == nil {
        return ErrNoTransactOpts
    }

    _, err := c.contract.SetStorageBackend(c.auth, locationURI)
    return err
}

// RemoveStorageBackend removes a storage backend
func (c *OnchainRegistryClient) RemoveStorageBackend(locationURI string) error {
    if c.auth == nil {
        return ErrNoTransactOpts
    }

    _, err := c.contract.RemoveStorageBackend(c.auth, locationURI)
    return err
}

// RegisterInstanceDomainName registers a new instance domain name
func (c *OnchainRegistryClient) RegisterInstanceDomainName(domain string) error {
    if c.auth == nil {
        return ErrNoTransactOpts
    }

    _, err := c.contract.RegisterInstanceDomainName(c.auth, domain)
    return err
}

// AllInstanceDomainNames retrieves all registered instance domain names
func (c *OnchainRegistryClient) AllInstanceDomainNames() ([]string, error) {
    opts := &bind.CallOpts{Context: context.Background()}
    
    return c.contract.AllInstanceDomainNames(opts)
}

// AddConfig adds a new configuration and returns its hash
func (c *OnchainRegistryClient) AddConfig(data []byte) ([32]byte, error) {
    if c.auth == nil {
        return [32]byte{}, ErrNoTransactOpts
    }

    tx, err := c.contract.AddConfig(c.auth, data)
    if err != nil {
        return [32]byte{}, err
    }

    // Wait for transaction to be mined
    receipt, err := bind.WaitMined(context.Background(), c.client, tx)
    if err != nil {
        return [32]byte{}, err
    }

    // Parse the events from the receipt logs
    for _, log := range receipt.Logs {
        event, err := c.contract.ParseConfigAdded(*log)
        if err == nil && event != nil {
            return event.ConfigHash, nil
        }
    }

    return [32]byte{}, errors.New("config hash not found in transaction logs")
}

// AddSecret adds a new encrypted secret and returns its hash
func (c *OnchainRegistryClient) AddSecret(data []byte) ([32]byte, error) {
    if c.auth == nil {
        return [32]byte{}, ErrNoTransactOpts
    }

    tx, err := c.contract.AddSecret(c.auth, data)
    if err != nil {
        return [32]byte{}, err
    }

    // Wait for transaction to be mined
    receipt, err := bind.WaitMined(context.Background(), c.client, tx)
    if err != nil {
        return [32]byte{}, err
    }

    // Parse the events from the receipt logs
    for _, log := range receipt.Logs {
        event, err := c.contract.ParseSecretAdded(*log)
        if err == nil && event != nil {
            return event.SecretHash, nil
        }
    }

    return [32]byte{}, errors.New("secret hash not found in transaction logs")
}

// SetConfigForDCAP sets the configuration for a DCAP report
func (c *OnchainRegistryClient) SetConfigForDCAP(report *interfaces.DCAPReport, configHash [32]byte) error {
    if c.auth == nil {
        return ErrNoTransactOpts
    }

    // The contract now expects an empty array of DCAPEvents as a second parameter
    emptyEventLog := []registry.RegistryDCAPEvent{}
    
    _, err := c.contract.SetConfigForDCAP(c.auth, *report, emptyEventLog, configHash)
    return err
}

// SetConfigForMAA sets the configuration for a MAA report
func (c *OnchainRegistryClient) SetConfigForMAA(report *interfaces.MAAReport, configHash [32]byte) error {
    if c.auth == nil {
        return ErrNoTransactOpts
    }

    _, err := c.contract.SetConfigForMAA(c.auth, *report, configHash)
    return err
}

// RemoveWhitelistedIdentity removes a whitelisted identity
func (c *OnchainRegistryClient) RemoveWhitelistedIdentity(identity [32]byte) error {
    if c.auth == nil {
        return ErrNoTransactOpts
    }

    _, err := c.contract.RemoveWhitelistedIdentity(c.auth, identity)
    return err
}

// Error definitions
var (
    ErrNoTransactOpts = errors.New("no authorized transactor available")
)

type RegistryFactory struct {
	client *ethclient.Client
}

func NewRegistryFactory(client *ethclient.Client) *RegistryFactory {
	return &RegistryFactory{client: client}
}

func (f *RegistryFactory) RegistryFor(address interfaces.ContractAddress) (interfaces.OnchainRegistry, error) {
	return NewOnchainRegistryClient(f.client, common.Address(address))
}
