package kmshandler

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-chi/chi/v5"
	"github.com/ruteri/tee-service-provisioning-backend/api"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// Handler processes HTTP requests for the TEE Key Management Service.
// It integrates with the on-chain governance contract to verify identity and authorization.
//
// The handler is responsible for critical security operations such as:
// - Verifying TEE instance attestation evidence
// - Validating operator signatures
// - Providing private keys for secret decryption
// - Signing CSRs for secure TLS communication
//
// All operations are performed only after verifying the instance's identity and authorization
// through the on-chain registry.
type Handler struct {
	kms             interfaces.KMS
	registryFactory interfaces.RegistryFactory
	log             *slog.Logger
}

// NewHandler creates a new HTTP request handler with the specified dependencies.
func NewHandler(kms interfaces.KMS, registryFactory interfaces.RegistryFactory, log *slog.Logger) *Handler {
	return &Handler{
		kms:             kms,
		registryFactory: registryFactory,
		log:             log,
	}
}

func (h *Handler) RegisterRoutes(r chi.Router) {
	r.Post("/api/attested/secrets/{contract_address}", h.HandleSecrets)
}

// HandleSecrets processes TEE instance secrets requests.
// It verifies the instance's identity against governance contract,
// and provides cryptographic materials and configuration if authorized.
//
// URL format: POST /api/attested/secrets/{contract_address}
// Required headers (cvm proxy):
//   - X-Flashbots-Attestation-Type: Type of attestation
//   - X-Flashbots-Measurement: JSON-encoded measurement values
//
// Request body: TLS Certificate Signing Request (CSR) in PEM format
// The CSR may optionally include an operator signature as an X.509 extension
// with OID api.OIDOperatorSignature. This signature provides additional
// authorization from an approved operator.
//
// Response: JSON, see api.SecretsResponse
func (h *Handler) HandleSecrets(w http.ResponseWriter, r *http.Request) {
	contractAddr, err := interfaces.NewContractAddressFromHex(r.PathValue("contract_address"))
	if err != nil {
		http.Error(w, fmt.Errorf("invalid contract address: %w", err).Error(), http.StatusBadRequest)
		return
	}

	// Read CSR from request body
	csr, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	if len(csr) == 0 {
		http.Error(w, "Empty CSR in request body", http.StatusBadRequest)
		return
	}

	// Get the registry for this contract
	registry, err := h.registryFactory.RegistryFor(contractAddr)
	if err != nil {
		h.log.Debug("Failed to get registry for contract", "err", err, slog.String("contractAddress", string(contractAddr[:])))
		http.Error(w, fmt.Errorf("registry access error: %w", err).Error(), http.StatusInternalServerError)
		return
	}

	// Extract workload identity and operator identity from attestation evidence and CSR
	identity, operatorAddress, err := ParseWorkloadAndOperatorIdentity(r, registry, csr)
	if err != nil {
		http.Error(w, fmt.Errorf("could not parse identity from request: %w", err).Error(), http.StatusBadRequest)
		return
	}

	identityAllowed, err := registry.IdentityAllowed(identity, operatorAddress)
	if err != nil {
		http.Error(w, fmt.Errorf("could not verify identity is allowed: %w", err).Error(), http.StatusUnauthorized)
		return
	}
	if !identityAllowed {
		http.Error(w, "identity not allowed", http.StatusUnauthorized)
		return
	}

	// Get application private key for this contract
	appPrivkey, err := h.kms.GetAppPrivkey(contractAddr)
	if err != nil {
		http.Error(w, fmt.Errorf("key retrieval error: %w", err).Error(), http.StatusUnauthorized)
		return
	}

	// Sign the CSR to create TLS certificate
	tlsCert, err := h.kms.SignCSR(contractAddr, csr)
	if err != nil {
		http.Error(w, fmt.Errorf("certificate signing error: %w", err).Error(), http.StatusUnauthorized)
		return
	}

	response := api.SecretsResponse{
		AppPrivkey: appPrivkey,
		TLSCert:    tlsCert,
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.log.Error("Failed to encode response", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// ParseWorkloadAndOperatorIdentity extracts and verifies the TEE instance identity and
// operator information from attestation evidence and CSR.
//
// It performs the following verification steps:
// 1. Extracts attestation type and measurements from ATLS headers
// 2. Computes the workload identity using the appropriate algorithm based on attestation type
// 3. Parses the CSR to extract any operator signature extensions
// 4. If an operator signature is present, verifies it and recovers the operator's Ethereum address
func ParseWorkloadAndOperatorIdentity(r *http.Request, registry interfaces.OnchainRegistry, csr interfaces.TLSCSR) ([32]byte, [20]byte, error) {
	// Extract attestation type and measurements from ATLS headers
	attestationType, measurements, err := cryptoutils.MeasurementsFromATLS(r)
	if err != nil {
		return [32]byte{}, [20]byte{}, fmt.Errorf("invalid measurements: %w", err)
	}

	// Calculate identity from attestation
	identity, err := api.AttestationToIdentity(attestationType, measurements, registry)
	if err != nil {
		return [32]byte{}, [20]byte{}, fmt.Errorf("identity computation error: %w", err)
	}

	// Parse CSR to extract any operator signature extensions
	parsedCsr, err := csr.GetX509CSR()
	if err != nil {
		return [32]byte{}, [20]byte{}, fmt.Errorf("csr parsing error: %w", err)
	}

	// Note: attestation could be passed through extensions as well
	// as long as we encrypt data to the pubkey embedded in it, for example
	// by validating the session's TLS cert uses the same pubkey.
	// This would let us avoid using the cvm proxy, and unify kms and pki handlers.

	// Extract operator address from signature extension if present
	// Note: it'd be better if the operator was passed through MROWNER for DCAP
	var operatorAddress [20]byte
	for _, ext := range parsedCsr.Extensions {
		if ext.Id.Equal(api.OIDOperatorSignature) {
			// Recover Ethereum address from signature over the CSR's public key
			pubkey, err := crypto.SigToPub(cryptoutils.DERPubkeyHash(parsedCsr.RawSubjectPublicKeyInfo), ext.Value)
			if err != nil {
				return [32]byte{}, [20]byte{}, fmt.Errorf("operator signature verification error: %w", err)
			}
			// Convert public key to Ethereum address
			operatorAddress = crypto.PubkeyToAddress(*pubkey)
		}
	}

	return identity, operatorAddress, nil
}
