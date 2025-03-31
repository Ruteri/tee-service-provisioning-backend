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

func (m *MockRegistry) GetPKI() (*interfaces.AppPKI, error) {
	args := m.Called()
	return args.Get(0).(*interfaces.AppPKI), args.Error(1)
}

func (m *MockRegistry) IsWhitelisted(identity [32]byte) (bool, error) {
	args := m.Called(identity)
	return args.Bool(0), args.Error(1)
}

func (m *MockRegistry) ComputeDCAPIdentity(report *interfaces.DCAPReport) ([32]byte, error) {
	args := m.Called(report)
	return args.Get(0).([32]byte), args.Error(1)
}

func (m *MockRegistry) ComputeMAAIdentity(report *interfaces.MAAReport) ([32]byte, error) {
	args := m.Called(report)
	return args.Get(0).([32]byte), args.Error(1)
}

func (m *MockRegistry) GetConfig(configHash [32]byte) ([]byte, error) {
	args := m.Called(configHash)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockRegistry) GetSecret(secretHash [32]byte) ([]byte, error) {
	args := m.Called(secretHash)
	return args.Get(0).([]byte), args.Error(1)
}

func (m *MockRegistry) IdentityConfigMap(identity [32]byte) ([32]byte, error) {
	args := m.Called(identity)
	return args.Get(0).([32]byte), args.Error(1)
}

func (m *MockRegistry) AddConfig(data []byte) ([32]byte, *types.Transaction, error) {
	args := m.Called(data)
	return args.Get(0).([32]byte), nil, args.Error(1)
}

func (m *MockRegistry) AddSecret(data []byte) ([32]byte, *types.Transaction, error) {
	args := m.Called(data)
	return args.Get(0).([32]byte), nil, args.Error(1)
}

func (m *MockRegistry) SetConfigForDCAP(report *interfaces.DCAPReport, configHash [32]byte) (*types.Transaction, error) {
	args := m.Called(report, configHash)
	return nil, args.Error(0)
}

func (m *MockRegistry) SetConfigForMAA(report *interfaces.MAAReport, configHash [32]byte) (*types.Transaction, error) {
	args := m.Called(report, configHash)
	return nil, args.Error(0)
}

func (m *MockRegistry) AllStorageBackends() ([]string, error) {
	args := m.Called()
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockRegistry) AddStorageBackend(locationURI string) (*types.Transaction, error) {
	args := m.Called(locationURI)
	return nil, args.Error(0)
}

func (m *MockRegistry) RemoveStorageBackend(locationURI string) (*types.Transaction, error) {
	args := m.Called(locationURI)
	return nil, args.Error(0)
}

func (m *MockRegistry) AllInstanceDomainNames() ([]string, error) {
	args := m.Called()
	return args.Get(0).([]string), args.Error(1)
}

func (m *MockRegistry) RegisterInstanceDomainName(domain string) (*types.Transaction, error) {
	args := m.Called(domain)
	return nil, args.Error(0)
}

func (m *MockRegistry) RemoveWhitelistedIdentity(identity [32]byte) (*types.Transaction, error) {
	args := m.Called(identity)
	return nil, args.Error(0)
}

// MockRegistryFactory mocks the RegistryFactory interface
type MockRegistryFactory struct {
	mock.Mock
}

func (m *MockRegistryFactory) RegistryFor(address interfaces.ContractAddress) (interfaces.OnchainRegistry, error) {
	args := m.Called(address)
	return args.Get(0).(interfaces.OnchainRegistry), args.Error(1)
}
