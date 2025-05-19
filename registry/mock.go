package registry

import (
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/stretchr/testify/mock"
)

// MockRegistry mocks the OnchainRegistry interface
type MockRegistry struct {
	mock.Mock
}

// PKI mocks the PKI method
func (m *MockRegistry) PKI() (interfaces.AppPKI, error) {
	args := m.Called()
	return args.Get(0).(interfaces.AppPKI), args.Error(1)
}

// DCAPIdentity mocks the DCAPIdentity method
func (m *MockRegistry) DCAPIdentity(report interfaces.DCAPReport, events []interfaces.DCAPEvent) ([32]byte, error) {
	args := m.Called(report)
	return args.Get(0).([32]byte), args.Error(1)
}

// MAAIdentity mocks the MAAIdentity method
func (m *MockRegistry) MAAIdentity(report interfaces.MAAReport) ([32]byte, error) {
	args := m.Called(report)
	return args.Get(0).([32]byte), args.Error(1)
}

// AddArtifact mocks the AddArtifact method
func (m *MockRegistry) AddArtifact(data []byte) ([32]byte, *types.Transaction, error) {
	args := m.Called(data)
	return args.Get(0).([32]byte), args.Get(1).(*types.Transaction), args.Error(2)
}

// IdentityAllowed mocks the IdentityAllowed method
func (m *MockRegistry) IdentityAllowed(identity [32]byte, operator [20]byte) (bool, error) {
	args := m.Called(identity, operator)
	return args.Get(0).(bool), args.Error(1)
}

// ConfigForIdentity mocks the IdentityConfigMap method
func (m *MockRegistry) ConfigForIdentity(identity [32]byte, operator [20]byte) ([32]byte, error) {
	args := m.Called(identity, operator)
	return args.Get(0).([32]byte), args.Error(1)
}

// GetArtifact mocks the GetArtifact method
func (m *MockRegistry) GetArtifact(artifactHash [32]byte) ([]byte, error) {
	args := m.Called(artifactHash)
	return args.Get(0).([]byte), args.Error(1)
}

// SetConfigForIdentity mocks the SetConfigForDCAP method
func (m *MockRegistry) SetConfigForIdentity(identity [32]byte, configHash [32]byte) (*types.Transaction, error) {
	args := m.Called(identity, configHash)
	return args.Get(0).(*types.Transaction), args.Error(1)
}

// StorageBackends mocks the AllStorageBackends method
func (m *MockRegistry) StorageBackends() ([]string, error) {
	args := m.Called()
	return args.Get(0).([]string), args.Error(1)
}

// AddStorageBackend mocks the AddStorageBackend method
func (m *MockRegistry) AddStorageBackend(locationURI string) (*types.Transaction, error) {
	args := m.Called(locationURI)
	return args.Get(0).(*types.Transaction), args.Error(1)
}

// RemoveStorageBackend mocks the RemoveStorageBackend method
func (m *MockRegistry) RemoveStorageBackend(locationURI string) (*types.Transaction, error) {
	args := m.Called(locationURI)
	return args.Get(0).(*types.Transaction), args.Error(1)
}

// InstanceDomainNames mocks the AllInstanceDomainNames method
func (m *MockRegistry) InstanceDomainNames() ([]string, error) {
	args := m.Called()
	return args.Get(0).([]string), args.Error(1)
}

// RegisterInstanceDomainName mocks the RegisterInstanceDomainName method
func (m *MockRegistry) RegisterInstanceDomainName(domain string) (*types.Transaction, error) {
	args := m.Called(domain)
	return args.Get(0).(*types.Transaction), args.Error(1)
}

// RemoveAllowlistedIdentity mocks the RemoveAllowlistedIdentity method
func (m *MockRegistry) RemoveAllowlistedIdentity(identity [32]byte) (*types.Transaction, error) {
	args := m.Called(identity)
	return args.Get(0).(*types.Transaction), args.Error(1)
}

// MockRegistryFactory mocks the RegistryFactory interface
type MockRegistryFactory struct {
	mock.Mock
}

// RegistryFor mocks the RegistryFor method
func (m *MockRegistryFactory) RegistryFor(address interfaces.ContractAddress) (interfaces.OnchainRegistry, error) {
	args := m.Called(address)
	return args.Get(0).(interfaces.OnchainRegistry), args.Error(1)
}
