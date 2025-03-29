package registry

import (
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ruteri/poc-tee-registry/interfaces"
)

// MockRegistryClient provides a simple in-memory implementation of the OnchainRegistry
// interface for testing purposes without requiring a blockchain connection.
type MockRegistryClient struct {
	mutex            sync.RWMutex
	configs          map[[32]byte][]byte
	secrets          map[[32]byte][]byte
	idToConfig       map[[32]byte][32]byte
	whitelisted      map[[32]byte]bool
	storageBackends  []string
	domainNames      []string
	pki              *interfaces.AppPKI
	allowTransacting bool
}

// NewMockRegistryClient creates a new mock registry client with empty initial state.
// This implementation uses in-memory maps instead of blockchain transactions.
func NewMockRegistryClient() *MockRegistryClient {
	return &MockRegistryClient{
		configs:          make(map[[32]byte][]byte),
		secrets:          make(map[[32]byte][]byte),
		idToConfig:       make(map[[32]byte][32]byte),
		whitelisted:      make(map[[32]byte]bool),
		storageBackends:  []string{},
		domainNames:      []string{},
		allowTransacting: false,
	}
}

// SetTransactOpts enables transaction operations on the mock client.
// While the mock doesn't actually make transactions, this simulates the authorization flow.
func (m *MockRegistryClient) SetTransactOpts() {
	m.allowTransacting = true
}

// GetPKI returns the mock PKI information or an error if none is set.
func (m *MockRegistryClient) GetPKI() (*interfaces.AppPKI, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.pki == nil {
		return nil, errors.New("no PKI configured")
	}
	return m.pki, nil
}

// IsWhitelisted checks if an identity is in the mock whitelist.
func (m *MockRegistryClient) IsWhitelisted(identity [32]byte) (bool, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	return m.whitelisted[identity], nil
}

// GetConfig retrieves a configuration by its hash from the mock registry.
func (m *MockRegistryClient) GetConfig(configHash [32]byte) ([]byte, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	config, exists := m.configs[configHash]
	if !exists {
		return nil, errors.New("config not found")
	}
	return config, nil
}

// GetSecret retrieves a secret by its hash from the mock registry.
func (m *MockRegistryClient) GetSecret(secretHash [32]byte) ([]byte, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	secret, exists := m.secrets[secretHash]
	if !exists {
		return nil, errors.New("secret not found")
	}
	return secret, nil
}

// ComputeDCAPIdentity calculates a mock identity from a DCAP report.
// This implementation simply hashes the first two RTMRs for demonstration purposes.
func (m *MockRegistryClient) ComputeDCAPIdentity(report *interfaces.DCAPReport) ([32]byte, error) {
	// Simple mock implementation that hashes the first two RTMRs
	var data []byte
	data = append(data, report.RTMRs[0][:]...)
	data = append(data, report.RTMRs[1][:]...)

	return sha256.Sum256(data), nil
}

// ComputeMAAIdentity calculates a mock identity from an MAA report.
// This implementation simply hashes the first few PCRs for demonstration purposes.
func (m *MockRegistryClient) ComputeMAAIdentity(report *interfaces.MAAReport) ([32]byte, error) {
	// Simple mock implementation that hashes the first few PCRs
	var data []byte
	data = append(data, report.PCRs[0][:]...)
	data = append(data, report.PCRs[1][:]...)

	return sha256.Sum256(data), nil
}

// IdentityConfigMap gets the config hash assigned to an identity in the mock registry.
func (m *MockRegistryClient) IdentityConfigMap(identity [32]byte) ([32]byte, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	configHash, exists := m.idToConfig[identity]
	if !exists {
		return [32]byte{}, errors.New("no config mapped to this identity")
	}
	return configHash, nil
}

// AllStorageBackends returns all registered storage backends from the mock registry.
func (m *MockRegistryClient) AllStorageBackends() ([]string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Return a copy to prevent modification of internal state
	backends := make([]string, len(m.storageBackends))
	copy(backends, m.storageBackends)

	return backends, nil
}

// AddStorageBackend adds a storage backend to the mock registry.
// Returns a simulated transaction and error if transactions are not allowed.
func (m *MockRegistryClient) AddStorageBackend(locationURI string) (*types.Transaction, error) {
	if !m.allowTransacting {
		return nil, ErrNoTransactOpts
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check for duplicates
	for _, existing := range m.storageBackends {
		if existing == locationURI {
			return &types.Transaction{}, nil // Already exists, return empty TX
		}
	}

	m.storageBackends = append(m.storageBackends, locationURI)
	return &types.Transaction{}, nil
}

// RemoveStorageBackend removes a storage backend from the mock registry.
// Returns a simulated transaction and error if transactions are not allowed.
func (m *MockRegistryClient) RemoveStorageBackend(locationURI string) (*types.Transaction, error) {
	if !m.allowTransacting {
		return nil, ErrNoTransactOpts
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	for i, backend := range m.storageBackends {
		if backend == locationURI {
			// Remove the backend by replacing with the last element and shrinking the slice
			m.storageBackends[i] = m.storageBackends[len(m.storageBackends)-1]
			m.storageBackends = m.storageBackends[:len(m.storageBackends)-1]
			break
		}
	}

	return &types.Transaction{}, nil
}

// RegisterInstanceDomainName registers a new instance domain name in the mock registry.
// Returns a simulated transaction and error if transactions are not allowed.
func (m *MockRegistryClient) RegisterInstanceDomainName(domain string) (*types.Transaction, error) {
	if !m.allowTransacting {
		return nil, ErrNoTransactOpts
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check for duplicates
	for _, existing := range m.domainNames {
		if existing == domain {
			return &types.Transaction{}, nil // Already exists, return empty TX
		}
	}

	m.domainNames = append(m.domainNames, domain)
	return &types.Transaction{}, nil
}

// AllInstanceDomainNames retrieves all registered instance domain names from the mock registry.
func (m *MockRegistryClient) AllInstanceDomainNames() ([]string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Return a copy to prevent modification of internal state
	domains := make([]string, len(m.domainNames))
	copy(domains, m.domainNames)

	return domains, nil
}

// AddConfig adds a new configuration to the mock registry and returns its hash.
// Returns the content hash, transaction, and an error if transactions are not allowed.
func (m *MockRegistryClient) AddConfig(data []byte) ([32]byte, *types.Transaction, error) {
	if !m.allowTransacting {
		return [32]byte{}, nil, ErrNoTransactOpts
	}

	hash := sha256.Sum256(data)

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.configs[hash] = data

	return hash, &types.Transaction{}, nil
}

// AddSecret adds a new encrypted secret to the mock registry and returns its hash.
// Returns the content hash, transaction, and an error if transactions are not allowed.
func (m *MockRegistryClient) AddSecret(data []byte) ([32]byte, *types.Transaction, error) {
	if !m.allowTransacting {
		return [32]byte{}, nil, ErrNoTransactOpts
	}

	hash := sha256.Sum256(data)

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.secrets[hash] = data

	return hash, &types.Transaction{}, nil
}

// SetConfigForDCAP associates a configuration with a DCAP identity in the mock registry.
// It first computes the identity from the report, then maps it to the given config hash.
// Returns a simulated transaction and error if transactions are not allowed.
func (m *MockRegistryClient) SetConfigForDCAP(report *interfaces.DCAPReport, configHash [32]byte) (*types.Transaction, error) {
	if !m.allowTransacting {
		return nil, ErrNoTransactOpts
	}

	// Check if config exists
	m.mutex.RLock()
	_, exists := m.configs[configHash]
	m.mutex.RUnlock()

	if !exists {
		return nil, errors.New("config does not exist")
	}

	// Compute identity
	identity, err := m.ComputeDCAPIdentity(report)
	if err != nil {
		return nil, err
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Whitelist the identity and map it to the config
	m.whitelisted[identity] = true
	m.idToConfig[identity] = configHash

	return &types.Transaction{}, nil
}

// SetConfigForMAA associates a configuration with an MAA identity in the mock registry.
// It first computes the identity from the report, then maps it to the given config hash.
// Returns a simulated transaction and error if transactions are not allowed.
func (m *MockRegistryClient) SetConfigForMAA(report *interfaces.MAAReport, configHash [32]byte) (*types.Transaction, error) {
	if !m.allowTransacting {
		return nil, ErrNoTransactOpts
	}

	// Check if config exists
	m.mutex.RLock()
	_, exists := m.configs[configHash]
	m.mutex.RUnlock()

	if !exists {
		return nil, errors.New("config does not exist")
	}

	// Compute identity
	identity, err := m.ComputeMAAIdentity(report)
	if err != nil {
		return nil, err
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Whitelist the identity and map it to the config
	m.whitelisted[identity] = true
	m.idToConfig[identity] = configHash

	return &types.Transaction{}, nil
}

// RemoveWhitelistedIdentity removes an identity from the whitelist in the mock registry.
// It also removes any config mapping for this identity.
// Returns a simulated transaction and error if transactions are not allowed.
func (m *MockRegistryClient) RemoveWhitelistedIdentity(identity [32]byte) (*types.Transaction, error) {
	if !m.allowTransacting {
		return nil, ErrNoTransactOpts
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if the identity is whitelisted
	if !m.whitelisted[identity] {
		return nil, errors.New("identity not whitelisted")
	}

	// Remove from whitelist and config mapping
	delete(m.whitelisted, identity)
	delete(m.idToConfig, identity)

	return &types.Transaction{}, nil
}
