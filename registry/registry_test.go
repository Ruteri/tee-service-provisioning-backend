package registry

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient/simulated"
	"github.com/ruteri/tee-service-provisioning-backend/bindings/registry"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegistryContract_Identity tests identity computation methods
func TestRegistryContract_Identity(t *testing.T) {
	// Skip if no local blockchain is available
	backend, auth, _, err := SetupTestChain()
	require.NoError(t, err)
	defer backend.Close()

	contractAddr, err := DeployContract(backend, auth, registry.DeployRegistry)
	require.NoError(t, err)

	// Create client
	regClient, err := NewOnchainRegistryClient(backend.Client(), backend.Client(), contractAddr)
	require.NoError(t, err)
	regClient.SetTransactOpts(auth)

	// Test DCAP identity calculation
	dcapReport := &interfaces.DCAPReport{
		MrTd: [48]byte{0x01},
		RTMRs: [4][48]byte{
			{0x01, 0x01}, // RTMR0
			{0x02, 0x02}, // RTMR1
			{0x03, 0x03}, // RTMR2
			{0x04, 0x04}, // RTMR3
		},
		MrOwner:       [48]byte{0x05},
		MrConfigId:    [48]byte{0x06},
		MrConfigOwner: [48]byte{0x07},
	}

	dcapIdentity, err := regClient.ComputeDCAPIdentity(dcapReport)
	assert.NoError(t, err)
	assert.NotEqual(t, [32]byte{}, dcapIdentity, "DCAP identity should not be empty")

	// Test MAA identity calculation
	maaReport := &interfaces.MAAReport{
		PCRs: [24][32]byte{},
	}
	// Set key PCRs used in identity calculation
	maaReport.PCRs[4] = [32]byte{0x04, 0x04}
	maaReport.PCRs[9] = [32]byte{0x09, 0x09}
	maaReport.PCRs[11] = [32]byte{0x0b, 0x0b}

	maaIdentity, err := regClient.ComputeMAAIdentity(maaReport)
	assert.NoError(t, err)
	assert.NotEqual(t, [32]byte{}, maaIdentity, "MAA identity should not be empty")
}

// TestRegistryContract_ArtifactAndIdentity tests artifact management and identity mapping
func TestRegistryContract_ArtifactAndIdentity(t *testing.T) {
	// Skip if no local blockchain is available
	backend, auth, _, err := SetupTestChain()
	require.NoError(t, err)
	defer backend.Close()

	contractAddr, err := DeployContract(backend, auth, registry.DeployRegistry)
	require.NoError(t, err)

	// Create client
	regClient, err := NewOnchainRegistryClient(backend.Client(), backend.Client(), contractAddr)
	require.NoError(t, err)
	regClient.SetTransactOpts(auth)

	// Test adding an artifact
	artifactData := []byte(`{"name":"test-app","version":"1.0","timeout":30}`)
	artifactHash, _, err := regClient.AddArtifact(artifactData)
	assert.NoError(t, err)
	backend.Commit()

	// Test retrieving the artifact
	storedArtifact, err := regClient.GetArtifact(artifactHash)
	assert.NoError(t, err)
	assert.Equal(t, artifactData, storedArtifact)

	// Test setting config for a DCAP report
	dcapReport := &interfaces.DCAPReport{
		RTMRs: [4][48]byte{
			{0x01, 0x02}, // RTMR0
			{0x03, 0x04}, // RTMR1
			{0x05, 0x06}, // RTMR2
			{0x07, 0x08}, // RTMR3
		},
	}

	_, err = regClient.SetConfigForDCAP(dcapReport, artifactHash)
	assert.NoError(t, err)
	backend.Commit()

	// Calculate the identity for this report
	identity, err := regClient.ComputeDCAPIdentity(dcapReport)
	assert.NoError(t, err)

	// Verify artifact mapping
	mappedArtifact, err := regClient.IdentityConfigMap(identity, auth.From)
	assert.NoError(t, err)
	assert.Equal(t, artifactHash, mappedArtifact)

	// Verify artifact mapping returns empty for unauthorized operator
	unmappedArtifact, err := regClient.IdentityConfigMap(identity, [20]byte{})
	assert.Error(t, err)
	assert.Equal(t, [32]byte{}, unmappedArtifact)

	// Test removing identity mapping
	_, err = regClient.RemoveConfigMapForIdentity(identity)
	assert.NoError(t, err)
	backend.Commit()

	// Verify identity no longer has an artifact mapping
	_, err = regClient.IdentityConfigMap(identity, [20]byte{})
	assert.Error(t, err)
}

// TestRegistryContract_StorageBackends tests storage backend management
func TestRegistryContract_StorageBackends(t *testing.T) {
	backend, auth, _, err := SetupTestChain()
	require.NoError(t, err)
	defer backend.Close()

	contractAddr, err := DeployContract(backend, auth, registry.DeployRegistry)
	require.NoError(t, err)

	// Create client
	regClient, err := NewOnchainRegistryClient(backend.Client(), backend.Client(), contractAddr)
	require.NoError(t, err)
	regClient.SetTransactOpts(auth)

	// Test adding storage backends
	backends := []string{
		"file:///tmp/registry-test",
		"ipfs://localhost:5001",
		"s3://test-bucket/registry",
	}

	for _, storageBackend := range backends {
		_, err := regClient.AddStorageBackend(storageBackend)
		assert.NoError(t, err)
		backend.Commit()
	}

	// Test retrieving all storage backends
	storedBackends, err := regClient.AllStorageBackends()
	assert.NoError(t, err)
	assert.Len(t, storedBackends, len(backends))

	// Test removing a storage backend
	_, err = regClient.RemoveStorageBackend(backends[0])
	assert.NoError(t, err)
	backend.Commit()

	// Verify backend was removed
	storedBackends, err = regClient.AllStorageBackends()
	assert.NoError(t, err)
	assert.Len(t, storedBackends, len(backends)-1)

	// Verify the specific backend was removed
	var found bool
	for _, backend := range storedBackends {
		if backend == backends[0] {
			found = true
			break
		}
	}
	assert.False(t, found, "Removed backend should not be in the list")
}

// TestRegistryContract_DomainNames tests domain name registration
func TestRegistryContract_DomainNames(t *testing.T) {
	backend, auth, _, err := SetupTestChain()
	require.NoError(t, err)
	defer backend.Close()

	contractAddr, err := DeployContract(backend, auth, registry.DeployRegistry)
	require.NoError(t, err)

	// Create client
	regClient, err := NewOnchainRegistryClient(backend.Client(), backend.Client(), contractAddr)
	require.NoError(t, err)
	regClient.SetTransactOpts(auth)

	// Test registering domain names
	domains := []string{
		"instance1.test.example.com",
		"instance2.test.example.com",
	}

	for _, domain := range domains {
		_, err := regClient.RegisterInstanceDomainName(domain)
		assert.NoError(t, err)
		backend.Commit()
	}

	// Test retrieving all domain names
	storedDomains, err := regClient.AllInstanceDomainNames()
	assert.NoError(t, err)
	assert.Len(t, storedDomains, len(domains))

	// Verify domains are in the list
	for _, domain := range domains {
		var found bool
		for _, storedDomain := range storedDomains {
			if domain == storedDomain {
				found = true
				break
			}
		}
		assert.True(t, found, "Domain %s should be in the list", domain)
	}
}

// TestLegacyMethods tests that the legacy methods still work correctly
func TestLegacyMethods(t *testing.T) {
	backend, auth, _, err := SetupTestChain()
	require.NoError(t, err)
	defer backend.Close()

	contractAddr, err := DeployContract(backend, auth, registry.DeployRegistry)
	require.NoError(t, err)

	// Create client
	regClient, err := NewOnchainRegistryClient(backend.Client(), backend.Client(), contractAddr)
	require.NoError(t, err)
	regClient.SetTransactOpts(auth)

	// Test legacy AddConfig
	configData := []byte(`{"name":"test-config","version":"1.0"}`)
	configHash, _, err := regClient.AddArtifact(configData)
	assert.NoError(t, err)
	backend.Commit()

	// Test legacy GetConfig
	storedConfig, err := regClient.GetArtifact(configHash)
	assert.NoError(t, err)
	assert.Equal(t, configData, storedConfig)

	// Test legacy AddSecret
	secretData := []byte(`{"password":"secret123"}`)
	secretHash, _, err := regClient.AddArtifact(secretData)
	assert.NoError(t, err)
	backend.Commit()

	// Test legacy GetSecret
	storedSecret, err := regClient.GetArtifact(secretHash)
	assert.NoError(t, err)
	assert.Equal(t, secretData, storedSecret)

	// Verify that legacy methods use the same storage as the new methods
	configFromArtifact, err := regClient.GetArtifact(configHash)
	assert.NoError(t, err)
	assert.Equal(t, configData, configFromArtifact)

	secretFromArtifact, err := regClient.GetArtifact(secretHash)
	assert.NoError(t, err)
	assert.Equal(t, secretData, secretFromArtifact)
}

// Helper function to generate random bytes
func randomBytes(length int) []byte {
	bytes := make([]byte, length)
	rand.Read(bytes)
	return bytes
}

// SetupTestChain creates a simulated blockchain for testing purposes.
// It returns:
// - A ethclient.Client that can be used with your code
// - The transaction auth with the funded account
// - The private key for the funded account
// - The simulated backend for direct control (commit blocks, etc.)
func SetupTestChain() (*simulated.Backend, *bind.TransactOpts, *ecdsa.PrivateKey, error) {
	// Generate a private key for the test account
	privateKey, err := crypto.GenerateKey()
	if err != nil {
		return nil, nil, nil, err
	}

	// Create a transaction auth with the test account
	auth, err := bind.NewKeyedTransactorWithChainID(privateKey, big.NewInt(1337))
	if err != nil {
		return nil, nil, nil, err
	}

	// Set up a funded account in the genesis block
	balance := new(big.Int)
	balance.SetString("10000000000000000000", 10) // 10 ETH

	address := auth.From
	genesisAlloc := map[common.Address]types.Account{
		address: {
			Balance: balance,
		},
	}

	// Create the simulated backend with the genesis allocation
	blockGasLimit := uint64(8000000)
	backend := simulated.NewBackend(genesisAlloc, simulated.WithBlockGasLimit(blockGasLimit))

	// Return the client, auth, private key, and backend
	return backend, auth, privateKey, nil
}

// DeployContract is a helper to deploy a contract and wait for it to be mined
func DeployContract[C any](backend *simulated.Backend, auth *bind.TransactOpts,
	deployer func(auth *bind.TransactOpts, backend bind.ContractBackend) (common.Address, *types.Transaction, C, error)) (common.Address, error) {
	contractAddr, tx, _, err := deployer(auth, backend.Client())
	if err != nil {
		return common.Address{}, err
	}

	backend.Commit() // Process the transaction

	// Optionally, wait for the transaction to be mined
	receipt, err := backend.Client().TransactionReceipt(context.Background(), tx.Hash())
	if err != nil {
		return common.Address{}, err
	}

	if receipt.Status != 1 {
		return common.Address{}, fmt.Errorf("contract deployment failed")
	}

	return contractAddr, nil
}
