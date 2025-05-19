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
// It stores all registry data in memory and simulates blockchain operations.
type MockRegistryClient struct {
	mutex            sync.RWMutex
	artifacts        map[[32]byte][]byte   // Storage for artifacts (configs, secrets, etc.)
	idToArtifact     map[[32]byte][32]byte // Maps identity to artifact hash
	allowedOperators map[[20]byte]bool     // Stores allowed operators
	storageBackends  []string
	domainNames      []string
	pki              *interfaces.AppPKI
	allowTransacting bool
}

// NewMockRegistryClient creates a new mock registry client with empty initial state.
// This implementation uses in-memory maps instead of blockchain transactions.
// The client starts in a read-only state - call SetTransactOpts to enable transaction operations.
func NewMockRegistryClient() *MockRegistryClient {
	return &MockRegistryClient{
		artifacts:        make(map[[32]byte][]byte),
		idToArtifact:     make(map[[32]byte][32]byte),
		allowedOperators: make(map[[20]byte]bool),
		storageBackends:  []string{},
		domainNames:      []string{},
		allowTransacting: false,
	}
}

// SetTransactOpts enables transaction operations on the mock client.
// While the mock doesn't actually make blockchain transactions, this simulates
// the authorization flow by enabling write operations.
func (m *MockRegistryClient) SetTransactOpts() {
	m.allowTransacting = true
}

// PKI returns the mock PKI information or an error if none is set.
// The PKI includes CA certificate, application public key, and attestation data.
func (m *MockRegistryClient) PKI() (interfaces.AppPKI, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if m.pki == nil {
		return interfaces.AppPKI{}, errors.New("no PKI configured")
	}
	return *m.pki, nil
}

// RegisterPKI registers PKI information with the mock registry.
// This method is specific to the mock implementation and not part of the OnchainRegistry interface.
func (m *MockRegistryClient) RegisterPKI(pki *interfaces.AppPKI) {
	m.pki = pki
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

// DCAPIdentity calculates a mock identity from a DCAP report.
// This implementation simply hashes the first two RTMRs for demonstration purposes.
func (m *MockRegistryClient) DCAPIdentity(report interfaces.DCAPReport, events []interfaces.DCAPEvent) ([32]byte, error) {
	// Simple mock implementation that hashes the first two RTMRs
	var data []byte = append(report.RTMRs[0][:], report.RTMRs[1][:]...)
	return sha256.Sum256(data[:]), nil
}

// MAAIdentity calculates a mock identity from an MAA report.
// This implementation simply hashes the first few PCRs for demonstration purposes.
func (m *MockRegistryClient) MAAIdentity(report interfaces.MAAReport) ([32]byte, error) {
	// Simple mock implementation that hashes the first few PCRs
	var data []byte
	data = append(data, report.PCRs[0][:]...)
	data = append(data, report.PCRs[1][:]...)

	return sha256.Sum256(data), nil
}

// IdentityAllowed returns whether identity is allowed
func (m *MockRegistryClient) IdentityAllowed(identity [32]byte, operator [20]byte) (bool, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if !m.allowedOperators[operator] {
		return false, nil
	}

	_, exists := m.idToArtifact[identity]
	if !exists {
		return false, nil
	}
	return true, nil
}

// ConfigForIdentity gets the artifact hash assigned to an identity in the mock registry.
// Returns the artifact hash or an error if no mapping exists for the provided identity.
func (m *MockRegistryClient) ConfigForIdentity(identity [32]byte, operator [20]byte) ([32]byte, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	if !m.allowedOperators[operator] {
		return [32]byte{}, errors.New("operator not allowed")
	}

	artifactHash, exists := m.idToArtifact[identity]
	if !exists {
		return [32]byte{}, errors.New("no artifact mapped to this identity")
	}
	return artifactHash, nil
}

// StorageBackends returns all registered storage backends from the mock registry.
// These backends represent storage locations where artifacts can be stored and retrieved.
func (m *MockRegistryClient) StorageBackends() ([]string, error) {
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

// InstanceDomainNames retrieves all registered instance domain names from the mock registry.
// These domain names represent endpoints where TEE instances can be accessed.
func (m *MockRegistryClient) InstanceDomainNames() ([]string, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	// Return a copy to prevent modification of internal state
	domains := make([]string, len(m.domainNames))
	copy(domains, m.domainNames)

	return domains, nil
}

// GetArtifact retrieves an artifact by its hash from the mock registry.
// Returns the artifact data or an error if the artifact doesn't exist.
func (m *MockRegistryClient) GetArtifact(artifactHash [32]byte) ([]byte, error) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	artifact, exists := m.artifacts[artifactHash]
	if !exists {
		return nil, errors.New("artifact not found")
	}
	return artifact, nil
}

// SetConfigForIdentity associates an artifact with an identity in the mock registry.
// It first computes the identity from the report, then maps it to the given artifact hash.
// Returns a simulated transaction and error if transactions are not allowed.
func (m *MockRegistryClient) SetConfigForIdentity(identity [32]byte, artifactHash [32]byte) (*types.Transaction, error) {
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

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Map the identity to the artifact
	m.idToArtifact[identity] = artifactHash

	return &types.Transaction{}, nil
}

// RemoveAllowlistedIdentity removes an identity from the allowlist in the mock registry.
// It also removes any artifact mapping for this identity.
// Returns a simulated transaction and error if transactions are not allowed.
func (m *MockRegistryClient) RemoveAllowlistedIdentity(identity [32]byte) (*types.Transaction, error) {
	if !m.allowTransacting {
		return nil, ErrNoTransactOpts
	}

	m.mutex.Lock()
	defer m.mutex.Unlock()

	// Check if the identity is allowed (has an artifact mapping)
	_, exists := m.idToArtifact[identity]
	if !exists {
		return nil, errors.New("identity not allowed")
	}

	// Remove the artifact mapping
	delete(m.idToArtifact, identity)

	return &types.Transaction{}, nil
}

func (m *MockRegistryClient) AllowOperator(operator [20]byte) {
	m.mutex.RLock()
	defer m.mutex.RUnlock()

	m.allowedOperators[operator] = true
}
