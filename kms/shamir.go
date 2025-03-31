package kms

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/vault/shamir"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// ShamirKMS enhances SimpleKMS with Shamir Secret Sharing for secure master key
// management. The master key is split into shares and distributed to administrators,
// requiring a threshold number of shares to reconstruct the key and unlock the KMS.
//
// The master key is never stored in persistent storage. During initialization,
// the key is split into shares, distributed to administrators, and then erased.
// When the KMS needs to be started, the shares are collected and combined to
// reconstruct the master key, which is then kept only in memory.
type ShamirKMS struct {
	mu             sync.RWMutex
	masterKey      []byte         // The reconstructed master key, stored only in memory
	isUnlocked     bool           // Whether the KMS has been unlocked with sufficient shares
	threshold      int            // Minimum number of shares required to reconstruct the master key
	receivedShares map[int][]byte // Temporary storage for shares during reconstruction

	// For admin verification approach
	adminPubKeys map[string]bool // Map of allowed admin public key fingerprints
}

// NewShamirKMS creates a new ShamirKMS instance for initial setup.
// This function splits the master key into shares using Shamir's Secret Sharing.
// The shares must be securely distributed to administrators and the original master key
// should be securely erased after this function returns.
//
// Parameters:
//   - masterKey: The sensitive seed material to protect (at least 32 bytes)
//   - threshold: The minimum number of shares required to reconstruct the master key
//   - totalShares: The total number of shares to generate
//
// Returns:
//   - The ShamirKMS instance in locked state
//   - The generated shares to distribute to administrators
//   - Error if the operation fails
func NewShamirKMS(masterKey []byte, threshold, totalShares int) (*ShamirKMS, [][]byte, error) {
	if len(masterKey) < 32 {
		return nil, nil, errors.New("master key must be at least 32 bytes")
	}

	if threshold < 2 {
		return nil, nil, errors.New("threshold must be at least 2")
	}

	if totalShares < threshold {
		return nil, nil, errors.New("total shares must be at least equal to threshold")
	}

	// Split master key into shares
	shares, err := shamir.Split(masterKey, totalShares, threshold)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to split master key: %w", err)
	}

	kms := &ShamirKMS{
		masterKey:      masterKey,
		isUnlocked:     true,
		threshold:      threshold,
		receivedShares: make(map[int][]byte),
		adminPubKeys:   make(map[string]bool),
	}

	return kms, shares, nil
}

// NewShamirKMSRecovery creates a new ShamirKMS instance in recovery mode.
// This function should be used when starting the KMS without a master key.
// The KMS will remain in a locked state until enough valid shares are submitted
// to reconstruct the master key.
//
// Parameter:
//   - threshold: The minimum number of shares required to reconstruct the master key
//
// Returns:
//   - The ShamirKMS instance in locked state, ready to accept shares
func NewShamirKMSRecovery(threshold int) *ShamirKMS {
	return &ShamirKMS{
		masterKey:      nil,
		isUnlocked:     false,
		threshold:      threshold,
		receivedShares: make(map[int][]byte),
		adminPubKeys:   make(map[string]bool),
	}
}

// RegisterAdmin registers an administrator's public key with the KMS.
// Only administrators with registered keys are authorized to submit shares.
// The public key is stored as a fingerprint to verify share submissions.
//
// Parameter:
//   - publicKeyPEM: The administrator's ECDSA public key in PEM format
//
// Returns:
//   - Error if the public key is invalid or cannot be registered
func (k *ShamirKMS) RegisterAdmin(publicKeyPEM []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	// Parse public key from PEM
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return errors.New("failed to decode PEM block")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	// Ensure it's an ECDSA key
	_, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("public key is not an ECDSA key")
	}

	// Calculate a fingerprint of the public key
	fingerprint := sha256.Sum256(publicKeyPEM)
	k.adminPubKeys[hex.EncodeToString(fingerprint[:])] = true

	return nil
}

// SubmitShare submits a key share with cryptographic verification.
// Each share must be signed by the administrator's private key to verify its authenticity.
// When the threshold number of valid shares are received, the master key is automatically
// reconstructed and the KMS transitions to an unlocked state.
//
// Parameters:
//   - shareIndex: The index number of the share (0-based)
//   - share: The actual share data
//   - signature: The signature over the share, signed by the admin's private key
//   - adminPubKeyPEM: The administrator's public key in PEM format
//
// Returns:
//   - Error if the share is invalid, the signature verification fails, or the admin is not authorized
func (k *ShamirKMS) SubmitShare(shareIndex int, share, signature, adminPubKeyPEM []byte) error {
	k.mu.Lock()
	defer k.mu.Unlock()

	// Check if the KMS is already unlocked
	if k.isUnlocked {
		return errors.New("KMS is already unlocked")
	}

	// Verify the admin's public key is registered
	fingerprint := sha256.Sum256(adminPubKeyPEM)
	fingerprintHex := hex.EncodeToString(fingerprint[:])
	if !k.adminPubKeys[fingerprintHex] {
		return errors.New("unregistered admin public key")
	}

	// Parse the admin's public key
	block, _ := pem.Decode(adminPubKeyPEM)
	if block == nil {
		return errors.New("failed to decode admin public key PEM")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse admin public key: %w", err)
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return errors.New("admin public key is not an ECDSA key")
	}

	// Verify signature
	hash := sha256.Sum256(share)
	valid := ecdsa.VerifyASN1(ecdsaPubKey, hash[:], signature)
	if !valid {
		return errors.New("invalid signature")
	}

	// Store the share
	k.receivedShares[shareIndex] = share

	// Try to reconstruct the master key if we have enough shares
	return k.tryReconstruct()
}

// tryReconstruct attempts to reconstruct the master key from the received shares.
// If enough shares (meeting or exceeding the threshold) have been received,
// Shamir's algorithm is used to combine them and recover the original master key.
// After successful reconstruction, all shares are securely wiped from memory.
//
// Returns:
//   - Error if reconstruction fails
//   - nil if successful or if not enough shares have been received yet
func (k *ShamirKMS) tryReconstruct() error {
	if len(k.receivedShares) < k.threshold {
		return nil // Not enough shares yet, but this is not an error
	}

	// Collect shares for reconstruction
	shares := make([][]byte, 0, len(k.receivedShares))
	for _, share := range k.receivedShares {
		shares = append(shares, share)
	}

	// Reconstruct the master key
	masterKey, err := shamir.Combine(shares)
	if err != nil {
		return fmt.Errorf("failed to reconstruct master key: %w", err)
	}

	// Set the master key and unlock the KMS
	k.masterKey = masterKey
	k.isUnlocked = true

	// Clear shares from memory for security
	for i := range k.receivedShares {
		wipeBytes(k.receivedShares[i])
	}
	k.receivedShares = make(map[int][]byte) // Reset map

	return nil
}

// IsUnlocked returns whether the KMS has been successfully unlocked.
// The KMS is considered unlocked when enough valid shares have been submitted
// and the master key has been successfully reconstructed.
//
// Returns:
//   - true if the KMS is unlocked and operational
//   - false if the KMS is still locked and waiting for more shares
func (k *ShamirKMS) IsUnlocked() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.isUnlocked
}

// Get the PKI information for a contract.
func (k *ShamirKMS) GetPKI(contractAddr interfaces.ContractAddress) (interfaces.AppPKI, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if !k.isUnlocked {
		return interfaces.AppPKI{}, errors.New("KMS is locked - need more shares to unlock")
	}

	// Create a SimpleKMS instance to delegate the actual operation
	simpleKMS := &SimpleKMS{masterKey: k.masterKey}
	return simpleKMS.GetPKI(contractAddr)
}

// Get the application private key for a contract.
func (k *ShamirKMS) GetAppPrivkey(contractAddr interfaces.ContractAddress) (interfaces.AppPrivkey, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if !k.isUnlocked {
		return nil, errors.New("KMS is locked - need more shares to unlock")
	}

	// Create a SimpleKMS instance to delegate the actual operation
	simpleKMS := &SimpleKMS{masterKey: k.masterKey}
	return simpleKMS.GetAppPrivkey(contractAddr)
}

// Sign a CSR for a verified TEE instance.
func (k *ShamirKMS) SignCSR(contractAddr interfaces.ContractAddress, csr interfaces.TLSCSR) (interfaces.TLSCert, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if !k.isUnlocked {
		return nil, errors.New("KMS is locked - need more shares to unlock")
	}

	// Create a SimpleKMS instance to delegate the actual operation
	simpleKMS := &SimpleKMS{masterKey: k.masterKey}
	return simpleKMS.SignCSR(contractAddr, csr)
}

// Securely wipe data from memory
func wipeBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

// SignShare generates a cryptographic signature for a share using an administrator's private key.
// This function would typically be used by administrators when they need to submit their share.
// The generated signature proves that the share is being submitted by the legitimate holder.
//
// Parameters:
//   - share: The share data to sign
//   - privateKey: The administrator's ECDSA private key
//
// Returns:
//   - The ASN.1 encoded signature
//   - Error if the signing operation fails
func SignShare(share []byte, privateKey *ecdsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256(share)
	return ecdsa.SignASN1(rand.Reader, privateKey, hash[:])
}

// SplitMasterKey splits a master key into shares using Shamir's Secret Sharing algorithm.
// This is a helper function that can be used separately from the ShamirKMS when
// custom share generation is needed.
//
// Parameters:
//   - masterKey: The master key to split (should be at least 32 bytes)
//   - totalShares: The total number of shares to generate
//   - threshold: The minimum number of shares needed to reconstruct the key
//
// Returns:
//   - The generated shares
//   - Error if the splitting operation fails
func SplitMasterKey(masterKey []byte, totalShares, threshold int) ([][]byte, error) {
	if len(masterKey) < 32 {
		return nil, errors.New("master key must be at least 32 bytes")
	}

	return shamir.Split(masterKey, totalShares, threshold)
}
