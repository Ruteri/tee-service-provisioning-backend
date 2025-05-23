// Package registry provides an interface to interact with on-chain registry contracts
// for TEE (Trusted Execution Environment) identity verification and configuration management.
package registry

import (
	"context"
	"crypto/sha256"
	"errors"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

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

// PKI retrieves the Certificate Authority and application public key information
// from the registry contract.
func (c *OnchainRegistryClient) PKI() (interfaces.AppPKI, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	pki, err := c.contract.PKI(opts)
	if err != nil {
		return interfaces.AppPKI{}, err
	}

	return interfaces.AppPKI{
		Ca:          pki.Ca,
		Pubkey:      pki.Pubkey,
		Attestation: pki.Attestation,
	}, nil
}

func DCAPReportToContractDCAPReport(report interfaces.DCAPReport) registry.DCAPReport {
	// Convert interfaces.DCAPReport to registry.DCAPReport
	contractReport := registry.DCAPReport{}

	contractReport.MrTd = make([]byte, 48)
	copy(contractReport.MrTd, report.MrTd[:])

	for rtmr := range report.RTMRs {
		contractReport.RTMRs[rtmr] = make([]byte, 48)
		copy(contractReport.RTMRs[rtmr], report.RTMRs[rtmr][:])
	}

	contractReport.MrConfigId = make([]byte, 48)
	contractReport.MrConfigOwner = make([]byte, 48)
	contractReport.MrOwner = make([]byte, 48)

	return contractReport
}

// DCAPIdentity calculates the identity hash for a DCAP report
// using the same algorithm as the on-chain registry.
func (c *OnchainRegistryClient) DCAPIdentity(report interfaces.DCAPReport, events []interfaces.DCAPEvent) ([32]byte, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	// Convert interfaces.DCAPReport to registry.DCAPReport
	contractReport := DCAPReportToContractDCAPReport(report)

	// The contract expects an empty array of DCAPEvents as a second parameter
	emptyEventLog := []registry.DCAPEvent{}

	return c.contract.DCAPIdentity(opts, contractReport, emptyEventLog)
}

// MAAIdentity calculates the identity hash for an MAA report
// using the same algorithm as the on-chain registry.
func (c *OnchainRegistryClient) MAAIdentity(report interfaces.MAAReport) ([32]byte, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	// Convert interfaces.MAAReport to registry.MAAReport
	contractReport := registry.MAAReport{
		PCRs: report.PCRs,
	}

	return c.contract.MAAIdentity(opts, contractReport)
}

func (c *OnchainRegistryClient) IdentityAllowed(identity [32]byte, operator [20]byte) (bool, error) {
	opts := &bind.CallOpts{Context: context.Background()}
	return c.contract.IdentityAllowed(opts, identity, operator)
}

// ConfigForIdentity gets the config hash assigned to an identity in the registry.
func (c *OnchainRegistryClient) ConfigForIdentity(identity [32]byte, address [20]byte) ([32]byte, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	return c.contract.ConfigForIdentity(opts, identity, address)
}

// StorageBackends retrieves all storage backend URIs registered in the contract.
func (c *OnchainRegistryClient) StorageBackends() ([]string, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	return c.contract.StorageBackends(opts)
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

// InstanceDomainNames retrieves all registered instance domain names from the registry.
func (c *OnchainRegistryClient) InstanceDomainNames() ([]string, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	return c.contract.InstanceDomainNames(opts)
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

	var hash [32]byte = sha256.Sum256(data)
	return hash, tx, nil
}

// GetArtifact retrieves an artifact by its hash from the registry.
// This can be a configuration, secret, or any other data.
func (c *OnchainRegistryClient) GetArtifact(artifactHash [32]byte) ([]byte, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	return c.contract.GetArtifact(opts, artifactHash)
}

// SetConfigForIdentity associates an artifact with an identity.
// Returns the transaction and any error that occurred.
func (c *OnchainRegistryClient) SetConfigForIdentity(identity [32]byte, artifactHash [32]byte) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	tx, err := c.contract.SetConfigForIdentity(c.auth, identity, artifactHash)
	return tx, err
}

// SetConfigForDCAP associates an artifact with a DCAP-attested identity.
// Returns the transaction and an error if the transaction could not be sent.
func (c *OnchainRegistryClient) SetConfigForDCAP(report interfaces.DCAPReport, artifactHash [32]byte) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	contractReport := DCAPReportToContractDCAPReport(report)

	// The contract expects an empty array of DCAPEvents as a second parameter
	emptyEventLog := []registry.DCAPEvent{}

	tx, err := c.contract.SetConfigForDCAP(c.auth, contractReport, emptyEventLog, artifactHash)
	return tx, err
}

// SetConfigForMAA associates an artifact with an MAA-attested identity.
// Returns the transaction and an error if the transaction could not be sent.
func (c *OnchainRegistryClient) SetConfigForMAA(report interfaces.MAAReport, artifactHash [32]byte) (*types.Transaction, error) {
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
