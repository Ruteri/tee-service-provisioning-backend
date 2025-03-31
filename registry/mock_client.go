package registry

import (
	"crypto/sha256"
	"errors"
	"sync"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// MockRegistryClient provides a simple in-memory implementation of the OnchainRegistry
// interface for testing purposes without requiring a blockchain connection.
type MockRegistryClient struct {
	mutex            sync.RWMutex
	artifacts        map[[32]byte][]byte // Storage for artifacts (configs, secrets, etc.)
	idToArtifact     map[[32]byte][32]byte // Maps identity to artifact hash
	storageBackends  []string
	domainNames      []string
	pki              *interfaces.AppPKI
	allowTransacting bool
}

// NewMockRegistryClient creates a new mock registry client with empty initial state.
// This implementation uses in-memory maps instead of blockchain transactions.
func NewMockRegistryClient() *MockRegistryClient {
	return &MockRegistryClient{
		artifacts:        make(map[[32]byte][]byte),
		idToArtifact:     make(map[[32]byte][32]byte),
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

// AddArtifact adds a new artifact to the mock registry and returns its hash.
// Returns the content hash, transaction, and an error if transactions are not allowed.
func (m *MockRegistryClient) AddArtifact(data []byte) ([32]byte, *types.Transaction, error) {
	if !m.allowTransacting {
		return [32]byte{}, nil, ErrNoTransactOpts
	}

	hash := sha256.Sum256(data)

	m.mutex.Lock()
	defer m.mutex.Unlock()

	m.artifacts[hash] = data

	return hash, &types.Transaction{}, nil
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

// IdentityConfigMap gets the artifact hash assigned to an identity in the mock registry.
func (m *MockRegistryClient) IdentityConfigMap(identity [32]byte) ([32]byte, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	artifactHash, exists := m.idToArtifact[identity]
	if !exists {
		return [32]byte{}, errors.New("no artifact mapped to this identity")
	}
	return artifactHash, nil
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

// GetArtifact retrieves an artifact by its hash from the mock registry.
func (m *MockRegistryClient) GetArtifact(artifactHash [32]byte) ([]byte, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	artifact, exists := m.artifacts[artifactHash]
	if !exists {
		return nil, errors.New("artifact not found")
	}
	return artifact, nil
}

// SetConfigForDCAP associates an artifact with a DCAP identity in the mock registry.
// It first computes the identity from the report, then maps it to the given artifact hash.
// Returns a simulated transaction and error if transactions are not allowed.
func (m *MockRegistryClient) SetConfigForDCAP(report *interfaces.DCAPReport, artifactHash [32]byte) (*types.Transaction, error) {
	if !m.allowTransacting {
		return nil, ErrNoTransactOpts
	}

	// Check if artifact exists
	m.mutex.RLock()
	_, exists := m.artifacts[artifactHash]
	m.mutex.RUnlock()

	if !exists {
		return nil, errors.New("artifact does not exist")
	}

	// Compute identity
	identity, err := m.ComputeDCAPIdentity(report)
	if err != nil {
		return nil, err
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Map the identity to the artifact
	m.idToArtifact[identity] = artifactHash

	return &types.Transaction{}, nil
}

// SetConfigForMAA associates an artifact with an MAA identity in the mock registry.
// It first computes the identity from the report, then maps it to the given artifact hash.
// Returns a simulated transaction and error if transactions are not allowed.
func (m *MockRegistryClient) SetConfigForMAA(report *interfaces.MAAReport, artifactHash [32]byte) (*types.Transaction, error) {
	if !m.allowTransacting {
		return nil, ErrNoTransactOpts
	}

	// Check if artifact exists
	m.mutex.RLock()
	_, exists := m.artifacts[artifactHash]
	m.mutex.RUnlock()

	if !exists {
		return nil, errors.New("artifact does not exist")
	}

	// Compute identity
	identity, err := m.ComputeMAAIdentity(report)
	if err != nil {
		return nil, err
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Map the identity to the artifact
	m.idToArtifact[identity] = artifactHash

	return &types.Transaction{}, nil
}

// RemoveWhitelistedIdentity removes an identity from the whitelist in the mock registry.
// It also removes any artifact mapping for this identity.
// Returns a simulated transaction and error if transactions are not allowed.
func (m *MockRegistryClient) RemoveWhitelistedIdentity(identity [32]byte) (*types.Transaction, error) {
	if !m.allowTransacting {
		return nil, ErrNoTransactOpts
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if the identity is whitelisted (has an artifact mapping)
	_, exists := m.idToArtifact[identity]
	if !exists {
		return nil, errors.New("identity not whitelisted")
	}

	// Remove the artifact mapping
	delete(m.idToArtifact, identity)

	return &types.Transaction{}, nil
}
