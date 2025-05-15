package kms

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"sync"

	"github.com/hashicorp/vault/shamir"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
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
	adminPubKeys map[string][]byte // Map of allowed admin public key fingerprints

	attestationProvider cryptoutils.AttestationProvider
}

// ShamirConfig contains configuration parameters for creating a ShamirKMS instance.
type ShamirConfig struct {
	// Threshold is the minimum number of shares required to reconstruct the master key
	Threshold int
	// AdminPubKeys is the list of authorized administrator public keys in PEM format
	AdminPubKeys [][]byte
}

func (k *ShamirKMS) SimpleKMS() *SimpleKMS {
	return &SimpleKMS{masterKey: k.masterKey, attestationProvider: k.attestationProvider}
}

// NewShamirKMS creates a new ShamirKMS instance for initial setup.
// This function splits the master key into shares using Shamir's Secret Sharing.
// The shares must be securely distributed to administrators and the original master key
// should be securely erased after this function returns.
func NewShamirKMS(masterKey []byte, config ShamirConfig) (*ShamirKMS, [][]byte, error) {
	if len(masterKey) < 32 {
		return nil, nil, errors.New("master key must be at least 32 bytes")
	}

	if config.Threshold < 2 {
		return nil, nil, errors.New("threshold must be at least 2")
	}

	if len(config.AdminPubKeys) < config.Threshold {
		return nil, nil, errors.New("total shares must be at least equal to threshold")
	}

	// Split master key into shares
	shares, err := shamir.Split(masterKey, len(config.AdminPubKeys), config.Threshold)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to split master key: %w", err)
	}

	kms := &ShamirKMS{
		masterKey:      masterKey,
		isUnlocked:     true,
		threshold:      config.Threshold,
		receivedShares: make(map[int][]byte),
		adminPubKeys:   make(map[string][]byte),
	}

	for _, publicKeyPEM := range config.AdminPubKeys {
		if err := cryptoutils.AppPubkey(publicKeyPEM).Validate(); err != nil {
			return nil, nil, fmt.Errorf("invalid admin pubkey %s: %w", publicKeyPEM, err)
		}
		fingerprint := sha256.Sum256(publicKeyPEM)
		kms.adminPubKeys[hex.EncodeToString(fingerprint[:])] = publicKeyPEM
	}

	return kms, shares, nil
}

// NewShamirKMSRecovery creates a new ShamirKMS instance in recovery mode.
// This function should be used when starting the KMS without a master key.
// The KMS will remain in a locked state until enough valid shares are submitted
// to reconstruct the master key.
func NewShamirKMSRecovery(config ShamirConfig) (*ShamirKMS, error) {
	kms := &ShamirKMS{
		masterKey:           nil,
		isUnlocked:          false,
		threshold:           config.Threshold,
		receivedShares:      make(map[int][]byte),
		adminPubKeys:        make(map[string][]byte),
		attestationProvider: cryptoutils.DumyAttestationProvider{},
	}

	for _, publicKeyPEM := range config.AdminPubKeys {
		if err := cryptoutils.AppPubkey(publicKeyPEM).Validate(); err != nil {
			return nil, fmt.Errorf("invalid admin pubkey %s: %w", publicKeyPEM, err)
		}
		fingerprint := sha256.Sum256(publicKeyPEM)
		kms.adminPubKeys[hex.EncodeToString(fingerprint[:])] = publicKeyPEM
	}

	return kms, nil
}

// SetAttestationProvider sets the attestation provider for this ShamirKMS.
// This allows customizing how attestations are generated when providing PKI materials.
func (k *ShamirKMS) SetAttestationProvider(provider cryptoutils.AttestationProvider) *ShamirKMS {
	k.attestationProvider = provider
	return k
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
	pubkeyForFingerprint, found := k.adminPubKeys[fingerprintHex]
	if !found {
		return errors.New("unregistered admin public key")
	}

	if !bytes.Equal(pubkeyForFingerprint, adminPubKeyPEM) {
		return errors.New("invalid pubkey passed for a matching fingerprint")
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

	if ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey); ok {
		// TODO: should verify and sign the message rather than hash!
		if !ecdsa.VerifyASN1(ecdsaPubKey, share, signature) {
			return errors.New("invalid signature")
		}
		// Store the share
		k.receivedShares[shareIndex] = share
	} else if edPubKey, ok := pubKey.(ed25519.PublicKey); ok {
		// TODO: should verify and sign the message rather than hash!
		if !ed25519.Verify(edPubKey, share, signature) {
			return errors.New("invalid signature")
		}
		// Store the share
		k.receivedShares[shareIndex] = share
	} else {
		return errors.New("admin public key is neither ECDSA nor ED25519 key")
	}

	// Try to reconstruct the master key if we have enough shares
	return k.tryReconstruct()
}

// tryReconstruct attempts to reconstruct the master key from the received shares.
// If enough shares (meeting or exceeding the threshold) have been received,
// Shamir's algorithm is used to combine them and recover the original master key.
// After successful reconstruction, all shares are securely wiped from memory.
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
func (k *ShamirKMS) IsUnlocked() bool {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.isUnlocked
}

// GetPKI retrieves the PKI information for a contract.
// This method delegates to SimpleKMS once the ShamirKMS is unlocked.
// Returns an error if the KMS is locked.
func (k *ShamirKMS) GetPKI(contractAddr interfaces.ContractAddress) (interfaces.AppPKI, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if !k.isUnlocked {
		return interfaces.AppPKI{}, errors.New("KMS is locked - need more shares to unlock")
	}

	return k.SimpleKMS().GetPKI(contractAddr)
}

// GetAppPrivkey retrieves the application private key for a contract.
// This method delegates to SimpleKMS once the ShamirKMS is unlocked.
// Returns an error if the KMS is locked.
func (k *ShamirKMS) GetAppPrivkey(contractAddr interfaces.ContractAddress) (interfaces.AppPrivkey, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if !k.isUnlocked {
		return nil, errors.New("KMS is locked - need more shares to unlock")
	}

	return k.SimpleKMS().GetAppPrivkey(contractAddr)
}

// SignCSR signs a certificate signing request for a verified TEE instance.
// This method delegates to SimpleKMS once the ShamirKMS is unlocked.
// Returns an error if the KMS is locked.
func (k *ShamirKMS) SignCSR(contractAddr interfaces.ContractAddress, csr interfaces.TLSCSR) (interfaces.TLSCert, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if !k.isUnlocked {
		return nil, errors.New("KMS is locked - need more shares to unlock")
	}

	return k.SimpleKMS().SignCSR(contractAddr, csr)
}

func (k *ShamirKMS) AppSecrets(contractAddr interfaces.ContractAddress, csr interfaces.TLSCSR) (*interfaces.AppSecrets, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()

	if !k.isUnlocked {
		return nil, errors.New("KMS is locked - need more shares to unlock")
	}

	return k.SimpleKMS().AppSecrets(contractAddr, csr)
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
	return ecdsa.SignASN1(rand.Reader, privateKey, share)
}
