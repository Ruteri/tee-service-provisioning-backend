package shamirkms

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/kms"
)

// BootstrapState represents the current state of the KMS bootstrap process.
type BootstrapState int

const (
	// StateInitial is the initial state before any bootstrap action is taken.
	StateInitial BootstrapState = iota

	// StateGeneratingShares indicates the master key has been generated and shares are being distributed.
	StateGeneratingShares

	// StateRecovering indicates the recovery process is underway collecting shares.
	StateRecovering

	// StateComplete indicates the KMS is fully operational.
	StateComplete
)

// stateToString converts a BootstrapState to a string representation.
func stateToString(state BootstrapState) string {
	switch state {
	case StateInitial:
		return "initial"
	case StateGeneratingShares:
		return "generating_shares"
	case StateRecovering:
		return "recovering"
	case StateComplete:
		return "complete"
	default:
		return "unknown"
	}
}

// SecureShare represents a share that has been encrypted for a specific admin.
//
// Each share is:
//   - Assigned to a specific admin by ID
//   - Encrypted with that admin's public key
//   - Only retrievable by that admin
//   - Tracked for retrieval status
type SecureShare struct {
	// AdminID is the identifier of the admin for whom this share is intended.
	AdminID string

	// ShareIndex is the index of the share in the Shamir Secret Sharing scheme.
	ShareIndex int

	// EncryptedShare is the share encrypted with the admin's public key.
	EncryptedShare []byte

	// Retrieved indicates whether the admin has already retrieved this share.
	Retrieved bool
}

// AdminHandler processes HTTP requests for bootstrapping the KMS.
//
// The AdminHandler implements a secure bootstrap process for ShamirKMS that:
//   - Verifies admin identity with cryptographic signatures
//   - Encrypts each share for its designated admin
//   - Ensures no admin can access shares intended for other admins
//   - Provides secure share distribution and collection
//   - Tracks the bootstrap state and signals completion
type AdminHandler struct {
	mu           sync.RWMutex
	log          *slog.Logger
	state        BootstrapState
	adminPubKeys map[string][]byte       // Map of admin ID to public key PEM
	adminShares  map[string]*SecureShare // Map of admin ID to their encrypted share
	shamirKMS    *kms.ShamirKMS          // Will be nil until bootstrapped
	completeChan chan struct{}           // Signals when bootstrap is complete

	shamirConfig kms.ShamirConfig
}

// NewAdminHandler creates a new admin handler for KMS bootstrap operations.
//
// Parameters:
//   - log: Structured logger for operational insights
//   - adminPubKeys: Map of admin IDs to their public keys in PEM format
//
// Returns:
//   - Configured AdminHandler instance ready to handle bootstrap requests
func NewAdminHandler(log *slog.Logger, threshold int, adminPubKeys map[string][]byte) (*AdminHandler, error) {
	shamirConfig := kms.ShamirConfig{
		Threshold: threshold,
	}

	if len(adminPubKeys) < threshold {
		return nil, errors.New("threshold larger than total shares")
	}

	if threshold < 2 {
		return nil, errors.New("threshold smaller than 2")
	}

	for _, pubkey := range adminPubKeys {
		shamirConfig.AdminPubKeys = append(shamirConfig.AdminPubKeys, pubkey)
	}

	return &AdminHandler{
		log:          log,
		state:        StateInitial,
		adminPubKeys: adminPubKeys,
		adminShares:  make(map[string]*SecureShare),
		completeChan: make(chan struct{}),
		shamirConfig: shamirConfig,
	}, nil
}

// WaitForBootstrap blocks until the bootstrap process is complete or the context is cancelled.
//
// This method is typically called by the main application to coordinate startup:
// the registry server should wait for KMS bootstrap to complete before accepting
// regular TEE attestation requests.
func (h *AdminHandler) WaitForBootstrap(ctx context.Context) (*kms.ShamirKMS, error) {
	select {
	case <-h.completeChan:
		return h.GetKMS(), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// GetKMS returns the initialized ShamirKMS once bootstrap is complete.
//
// The returned KMS is nil until bootstrap is complete. Applications should
// check the bootstrap state or wait for completion before using this method.
func (h *AdminHandler) GetKMS() *kms.ShamirKMS {

	if h.state != StateComplete {
		return nil
	}
	return h.shamirKMS
}

// RegisterRoutes configures HTTP router for the admin API.
//
// The router provides endpoints:
//   - /admin/status: check bootstrap status
//   - /admin/init/generate: generate and distributing shares
//   - /admin/init/recover: initiate recovery
//   - /admin/share: fetch share during generation, or submit share during recovery
func (h *AdminHandler) RegisterRoutes(r chi.Router) {
	r.Get("/admin/status", h.handleStatus)
	r.Post("/admin/init/generate", h.handleInitGenerate)
	r.Post("/admin/init/recover", h.handleInitRecover)
	r.Post("/admin/share", h.handleSubmitShare)
	r.Get("/admin/share", h.handleGetShare) // Endpoint for admins to retrieve their shares
}

// handleStatus returns the current status of the bootstrap process.
//
// This endpoint provides information about:
//   - The current bootstrap state
//   - Threshold and total shares (when in generating or recovery state)
//   - Whether the KMS is operational
//
// Endpoint: GET /admin/status
func (h *AdminHandler) handleStatus(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	state := h.state
	threshold := h.shamirConfig.Threshold
	totalShares := len(h.shamirConfig.AdminPubKeys)
	h.mu.RUnlock()

	resp := map[string]interface{}{
		"state": stateToString(state),
	}

	// Add additional info based on state
	if state == StateGeneratingShares || state == StateRecovering {
		resp["threshold"] = threshold
		resp["total_shares"] = totalShares
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

// handleInitGenerate initiates the master key generation and share distribution.
//
// This endpoint:
//   - Verifies the requesting admin is authorized
//   - Generates a cryptographically strong master key
//   - Splits the key into shares using Shamir's Secret Sharing
//   - Encrypts each share with its designated admin's public key
//   - Returns metadata about the share distribution (not the actual shares)
//
// Endpoint: POST /admin/init/generate
func (h *AdminHandler) handleInitGenerate(w http.ResponseWriter, r *http.Request) {
	// Verify admin
	adminID, ok := h.verifyAdmin(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	h.mu.Lock()
	if h.state != StateInitial {
		h.mu.Unlock()
		http.Error(w, "Bootstrap already in progress or complete", http.StatusBadRequest)
		return
	}
	defer h.mu.Unlock()

	// Generate cryptographically secure master key
	masterKey := make([]byte, 32)
	if _, err := rand.Read(masterKey); err != nil {
		h.log.Error("Failed to generate master key", "err", err, "adminID", adminID)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	// Create ShamirKMS and generate shares
	shamirKMS, shares, err := kms.NewShamirKMS(masterKey, h.shamirConfig)
	if err != nil {
		h.log.Error("Failed to create ShamirKMS", "err", err, "adminID", adminID)
		http.Error(w, "Failed to create KMS: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Get admin IDs for share assignment
	adminIDs := make([]string, 0, len(h.adminPubKeys))
	for id := range h.adminPubKeys {
		adminIDs = append(adminIDs, id)
	}

	adminShares := make(map[string]*SecureShare)

	// Create secure shares (encrypt each share for its designated admin)
	for i, share := range shares {
		if i >= len(adminIDs) {
			break
		}

		targetAdminID := adminIDs[i]
		pubKeyPEM := h.adminPubKeys[targetAdminID]

		// Encrypt the share with the admin's public key
		encryptedShare, err := cryptoutils.EncryptWithPublicKey(pubKeyPEM, share)
		if err != nil {
			h.log.Error("Failed to encrypt share", "err", err, "adminID", targetAdminID)
			http.Error(w, "Failed to encrypt shares", http.StatusInternalServerError)
			return
		}

		// Store the encrypted share
		adminShares[targetAdminID] = &SecureShare{
			AdminID:        targetAdminID,
			ShareIndex:     i,
			EncryptedShare: encryptedShare,
			Retrieved:      false,
		}
	}

	// Store the KMS and parameters
	h.state = StateGeneratingShares
	h.shamirKMS = shamirKMS
	h.adminShares = adminShares

	// Return metadata about the shares, not the actual encrypted shares
	shareAssignments := make([]map[string]interface{}, 0, len(h.adminShares))
	for adminID, secureShare := range h.adminShares {
		shareAssignments = append(shareAssignments, map[string]interface{}{
			"admin_id":    adminID,
			"share_index": secureShare.ShareIndex,
		})
	}

	resp := map[string]interface{}{
		"message":           "KMS initialized and shares generated successfully",
		"share_assignments": shareAssignments,
		"threshold":         h.shamirConfig.Threshold,
		"total_shares":      len(h.shamirConfig.AdminPubKeys),
		"instructions":      "Each admin must retrieve their share using GET /admin/share",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	h.log.Info("Master key generated and shares prepared for distribution", "adminID", adminID,
		"threshold", h.shamirConfig.Threshold, "totalShares", len(h.shamirConfig.AdminPubKeys))
}

type AdminGetShareResponse struct {
	ShareIndex     int    `json:"share_index"`
	EncryptedShare string `json:"encrypted_share"` // base64 encoded
}

// handleGetShare allows an admin to retrieve their share.
//
// This endpoint:
//   - Verifies the requesting admin is authorized
//   - Ensures the server is in the share distribution state
//   - Checks if the admin has an assigned share
//   - Returns the share encrypted with the admin's public key
//   - Tracks that the share has been retrieved
//   - Transitions to complete state when all shares are retrieved
//
// Each admin can only retrieve their own share.
//
// Endpoint: GET /admin/share
func (h *AdminHandler) handleGetShare(w http.ResponseWriter, r *http.Request) {
	// Verify admin
	adminID, ok := h.verifyAdmin(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.state != StateGeneratingShares {
		http.Error(w, "No shares available for retrieval", http.StatusBadRequest)
		return
	}

	// Check if this admin has an assigned share
	secureShare, exists := h.adminShares[adminID]
	if !exists {
		http.Error(w, "No share assigned to this admin", http.StatusNotFound)
		return
	}

	// Mark the share as retrieved
	secureShare.Retrieved = true

	// Check if all shares have been retrieved
	allRetrieved := true
	for _, share := range h.adminShares {
		if !share.Retrieved {
			allRetrieved = false
			break
		}
	}

	if allRetrieved {
		h.state = StateComplete
		close(h.completeChan)
		h.log.Info("All shares have been retrieved, KMS bootstrap complete")
	}

	// Return the encrypted share to the admin
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(AdminGetShareResponse{
		ShareIndex:     secureShare.ShareIndex,
		EncryptedShare: base64.StdEncoding.EncodeToString(secureShare.EncryptedShare),
	})

	h.log.Info("Admin retrieved their share", "adminID", adminID, "shareIndex", secureShare.ShareIndex)
}

// handleInitRecover initiates the recovery process.
//
// This endpoint:
//   - Verifies the requesting admin is authorized
//   - Creates a ShamirKMS in recovery mode with the specified threshold
//   - Registers all admin public keys with the KMS
//   - Transitions to the recovery state
//
// Endpoint: POST /admin/init/recover
// Body: {"threshold": <int>}
func (h *AdminHandler) handleInitRecover(w http.ResponseWriter, r *http.Request) {
	// Verify admin
	adminID, ok := h.verifyAdmin(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	h.mu.Lock()
	if h.state != StateInitial {
		h.mu.Unlock()
		http.Error(w, "Bootstrap already in progress or complete", http.StatusBadRequest)
		return
	}
	defer h.mu.Unlock()

	// Create recovery KMS
	adminPubkeys := [][]byte{}
	for _, pubkey := range h.adminPubKeys {
		adminPubkeys = append(adminPubkeys, pubkey)
	}
	shamirKMS, err := kms.NewShamirKMSRecovery(h.shamirConfig)
	if err != nil {
		http.Error(w, fmt.Errorf("could not initialize kms: %w", err).Error(), http.StatusInternalServerError)
		return
	}

	h.shamirKMS = shamirKMS
	h.state = StateRecovering

	resp := map[string]interface{}{
		"message":      "Recovery mode initiated",
		"threshold":    h.shamirConfig.Threshold,
		"instructions": "Admins must submit their shares using POST /admin/share",
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)

	h.log.Info("KMS recovery process initiated", "adminID", adminID, "threshold", h.shamirConfig.Threshold)
}

// handleSubmitShare handles share submissions during recovery.
//
// This endpoint:
//   - Verifies the requesting admin is authorized
//   - Ensures the server is in recovery mode
//   - Validates the submitted share and signature
//   - Submits the share to the ShamirKMS
//   - Checks if enough shares have been collected for reconstruction
//   - Transitions to complete state when the master key is reconstructed
//
// Endpoint: POST /admin/share
// Body: {"share_index": <int>, "share": "<base64>", "signature": "<base64>"}
func (h *AdminHandler) handleSubmitShare(w http.ResponseWriter, r *http.Request) {
	// Verify admin
	adminID, ok := h.verifyAdmin(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	h.mu.Lock()
	defer h.mu.Unlock()

	if h.state != StateRecovering {
		http.Error(w, "KMS not in recovery mode", http.StatusBadRequest)
		return
	}

	// Parse submission
	var submission struct {
		ShareIndex int    `json:"share_index"`
		Share      string `json:"share"`     // base64 encoded
		Signature  string `json:"signature"` // base64 encoded
	}

	if err := json.NewDecoder(r.Body).Decode(&submission); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	// Decode share and signature
	share, err := base64.StdEncoding.DecodeString(submission.Share)
	if err != nil {
		http.Error(w, "Invalid share encoding", http.StatusBadRequest)
		return
	}

	signature, err := base64.StdEncoding.DecodeString(submission.Signature)
	if err != nil {
		http.Error(w, "Invalid signature encoding", http.StatusBadRequest)
		return
	}

	// Get admin's public key
	adminPubKeyPEM := h.adminPubKeys[adminID]

	// Submit the share
	err = h.shamirKMS.SubmitShare(submission.ShareIndex, share, signature, adminPubKeyPEM)
	if err != nil {
		h.log.Error("Share submission failed", "err", err, "adminID", adminID)
		http.Error(w, "Share submission failed: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Check if KMS is now unlocked
	if h.shamirKMS.IsUnlocked() {
		h.state = StateComplete
		close(h.completeChan)

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"message": "KMS unlocked successfully - recovery complete",
		})

		h.log.Info("KMS successfully unlocked - recovery complete", "adminID", adminID)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"message": "Share accepted, waiting for more shares",
	})

	h.log.Info("Share accepted", "adminID", adminID, "shareIndex", submission.ShareIndex)
}

// verifyAdmin checks if the request is from a whitelisted admin.
//
// The function verifies that:
//  1. The admin is in the whitelist (has a registered public key)
//  2. The request includes a valid signature created with the admin's private key
//
// Parameters:
//   - r: The HTTP request to verify
//
// Returns:
//   - The admin ID if verification is successful
//   - A boolean indicating if verification was successful
func (h *AdminHandler) verifyAdmin(r *http.Request) (string, bool) {
	// Extract admin ID and signature from headers
	adminID := r.Header.Get("X-Admin-ID")
	adminSignatureStr := r.Header.Get("X-Admin-Signature")

	// Basic validation
	if adminID == "" || adminSignatureStr == "" {
		return "", false
	}

	// Get admin's public key from the whitelist
	h.mu.RLock()
	pubKeyPEM, exists := h.adminPubKeys[adminID]
	h.mu.RUnlock()

	if !exists {
		h.log.Warn("Authentication failed: unknown admin ID", "adminID", adminID)
		return adminID, false
	}

	// Decode the base64 signature
	adminSignature, err := base64.StdEncoding.DecodeString(adminSignatureStr)
	if err != nil {
		h.log.Warn("Authentication failed: invalid signature encoding", "adminID", adminID, "err", err)
		return adminID, false
	}

	// Parse the admin's public key
	block, _ := pem.Decode(pubKeyPEM)
	if block == nil {
		h.log.Error("Failed to decode admin public key PEM", "adminID", adminID)
		return adminID, false
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		h.log.Error("Failed to parse admin public key", "adminID", adminID, "err", err)
		return adminID, false
	}

	ecdsaPubKey, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		h.log.Error("Admin public key is not an ECDSA key", "adminID", adminID)
		return adminID, false
	}

	// Read the request body without consuming it
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			h.log.Error("Failed to read request body", "err", err)
			return adminID, false
		}

		// Restore the body for later handlers
		r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
	}

	// Create the message to verify (path + body)
	message := r.URL.Path
	if len(bodyBytes) > 0 {
		message += string(bodyBytes)
	}

	// Compute the hash of the message
	hash := sha256.Sum256([]byte(message))

	// Verify the signature
	if !ecdsa.VerifyASN1(ecdsaPubKey, hash[:], adminSignature) {
		h.log.Warn("Authentication failed: invalid signature", "adminID", adminID)
		return adminID, false
	}

	h.log.Debug("Admin authentication successful", "adminID", adminID)
	return adminID, true
}

type ShamirAdminsConfig struct {
	Admins []ShamirAdminMetadata `json:"admins"`
}

type ShamirAdminMetadata struct {
	ID     string `json:"id"`
	PubKey string `json:"pubkey"`
}

// LoadAdminKeys loads admin public keys from a JSON file.
//
// The JSON file should contain an "admins" array with entries that include:
//   - "id": A unique identifier for the admin
//   - "pubkey": The admin's public key in PEM format
//
// Parameters:
//   - r: Reader containing the JSON data
//
// Returns:
//   - Map of admin IDs to their public keys in PEM format
//   - Error if loading fails
func LoadAdminKeys(r io.Reader) (map[string][]byte, error) {
	var data ShamirAdminsConfig

	if err := json.NewDecoder(r).Decode(&data); err != nil {
		return nil, fmt.Errorf("failed to decode admin keys JSON: %w", err)
	}

	result := make(map[string][]byte)
	for _, admin := range data.Admins {
		// Verify the public key is valid PEM
		block, _ := pem.Decode([]byte(admin.PubKey))
		if block == nil {
			return nil, fmt.Errorf("invalid PEM data for admin %s", admin.ID)
		}

		// Verify it's a valid public key
		_, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("invalid public key for admin %s: %w", admin.ID, err)
		}

		result[admin.ID] = []byte(admin.PubKey)
	}

	return result, nil
}

// GenerateAdminKeyPair generates a new ECDSA key pair for an administrator.
//
// This utility function can be used to create admin credentials for the KMS bootstrap process.
// The generated key pair can be used for admin authentication and share encryption.
//
// Returns:
//   - Private key PEM string (should be securely distributed to the admin)
//   - Public key PEM string (should be registered with the AdminHandler)
//   - Error if key generation fails
func GenerateAdminKeyPair() (string, string, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate ECDSA key: %w", err)
	}

	// Convert private key to PEM
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	// Convert public key to PEM
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})

	return string(privateKeyPEM), string(publicKeyPEM), nil
}

// ParsePrivateKey parses an ECDSA private key from PEM format.
//
// This utility function converts a PEM-encoded private key to an ecdsa.PrivateKey
// object that can be used for signing operations.
//
// Parameters:
//   - privateKeyPEM: The private key in PEM format
//
// Returns:
//   - The parsed ECDSA private key
//   - Error if parsing fails
func ParsePrivateKey(privateKeyPEM []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, errors.New("failed to decode PEM block containing private key")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA private key: %w", err)
	}

	return privateKey, nil
}

// ComputeFingerprint computes a fingerprint for a public key.
//
// The fingerprint is a SHA-256 hash of the public key in PEM format,
// encoded as a hex string. It can be used to verify public key identity.
//
// Parameters:
//   - publicKeyPEM: Public key in PEM format
//
// Returns:
//   - Hex-encoded fingerprint
//   - Error if computation fails
func ComputeFingerprint(publicKeyPEM []byte) (string, error) {
	h := sha256.Sum256(publicKeyPEM)
	return hex.EncodeToString(h[:]), nil
}
