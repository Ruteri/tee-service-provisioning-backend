package pkihandler

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/ruteri/tee-service-provisioning-backend/api"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// Handler processes HTTP requests for the TEE PKI service.
// It provides access to certificate authorities and public keys for 
// applications identified by contract addresses. The Handler integrates
// with a KMS to retrieve attested PKI information.
type Handler struct {
	kms interfaces.KMS
	log *slog.Logger
}

// NewHandler creates a new HTTP request handler for the PKI service.
//
// It requires a KMS implementation to retrieve PKI information and
// a structured logger for operational insights.
//
// Parameters:
//   - kms: Key Management Service for cryptographic operations and certificate retrieval
//   - log: Structured logger for operational insights
//
// Returns a configured Handler instance ready to serve PKI requests.
func NewHandler(kms interfaces.KMS, log *slog.Logger) *Handler {
	return &Handler{
		kms: kms,
		log: log,
	}
}

// RegisterRoutes configures the HTTP router with PKI service endpoints.
// It registers the following routes:
//   - GET /api/public/pki/{contract_address} - Retrieve attested PKI information
//
// This method should be called during server initialization to set up
// the necessary routing for PKI operations.
func (h *Handler) RegisterRoutes(r chi.Router) {
	r.Get("/api/public/pki/{contract_address}", h.HandlePki)
}

// HandlePki processes requests for attested PKI information for a specified contract address.
// It retrieves the CA certificate and application public key from the KMS, along with
// attestation evidence that can be verified by clients to ensure authenticity.
//
// URL format: GET /api/public/pki/{contract_address}
//
// Response: JSON-encoded api.PKIResponse
//
// Status codes:
//   - 200 OK: PKI information successfully retrieved
//   - 400 Bad Request: Invalid contract address format
//   - 500 Internal Server Error: Failed to retrieve PKI information or encode response
func (h *Handler) HandlePki(w http.ResponseWriter, r *http.Request) {
	// Parse contract address from hex
	contractAddr, err := interfaces.NewContractAddressFromHex(r.PathValue("contract_address"))
	if err != nil {
		h.log.Error("Invalid contract address", "err", err, "address", r.PathValue("contract_address"))
		http.Error(w, "Invalid contract address format", http.StatusBadRequest)
		return
	}

	pki, err := h.kms.GetPKI(contractAddr)
	if err != nil {
		h.log.Error("Failed to get PKI", "err", err, "contractAddress", contractAddr.String())
		http.Error(w, fmt.Errorf("Failed to get PKI: %w", err).Error(), http.StatusInternalServerError)
		return
	}

	// Prepare response
	response := api.PKIResponse{
		CACert:      pki.Ca,
		AppPubkey:   pki.Pubkey,
		Attestation: pki.Attestation,
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.log.Error("Failed to encode response", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}
