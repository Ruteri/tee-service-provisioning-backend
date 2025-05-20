package kmshandler

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-chi/chi/v5"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	simplekms "github.com/ruteri/tee-service-provisioning-backend/kms"
)

type HandlerKMS interface {
	interfaces.KMS
	VerifyOnboardRequest(interfaces.OnboardRequest) (map[int]string, error)
	OnboardRemote(interfaces.AppPubkey) ([]byte, error)
}

// Handler processes HTTP requests for the onchain-governed TEE Key Management Service.
// It integrates with blockchain-based governance contracts to verify identity,
// authenticate operators, and provide cryptographic materials to authorized instances.
//
// The handler is responsible for critical security operations such as:
// - Verifying TEE instance attestation evidence against onchain allowlist
// - Validating operator signatures with onchain authorization checks
// - Providing private keys for application-wide secret decryption
// - Issuing signed TLS certificates for secure communication
// - Supporting secure KMS onboarding through attestation verification
//
// All operations are performed only after verifying both the instance's identity and
// operator authorization through the onchain governance contracts, implementing
// a robust two-factor authorization model (attestation + operator signature).
type Handler struct {
	kms             HandlerKMS
	kmsGovernance   interfaces.KMSGovernance
	registryFactory interfaces.RegistryFactory
	log             *slog.Logger
}

// NewHandler creates a new HTTP request handler with the specified dependencies.
func NewHandler(kms HandlerKMS, kmsGovernance interfaces.KMSGovernance, registryFactory interfaces.RegistryFactory, log *slog.Logger) *Handler {
	return &Handler{
		kms:             kms,
		kmsGovernance:   kmsGovernance,
		registryFactory: registryFactory,
		log:             log,
	}
}

func (h *Handler) RegisterRoutes(r chi.Router) {
	r.Post("/api/attested/secrets/{contract_address}", h.HandleSecrets)
	r.Get("/api/attested/onboard/{onboard_id}", h.HandleOnboard)
}

// HandleOnboard processes KMS onboarding requests for new TEE instances.
// It retrieves onchain onboarding requests, verifies attestation, and provides
// encrypted KMS seed material for authorized instances.
//
// URL format: GET /api/attested/onboard/{onboard_id}
// The onboard_id is a 32-byte hex-encoded hash that identifies the onboarding request
// previously registered in the onchain governance contract.
//
// This allows secure distributed KMS deployment where new instances can receive
// encrypted master key material through attestation verification and onchain governance.
//
// Response: Raw encrypted seed material for KMS initialization
func (h *Handler) HandleOnboard(w http.ResponseWriter, r *http.Request) {
	onboardHashBytes, err := hex.DecodeString(r.PathValue("onboard_id"))
	if err != nil {
		http.Error(w, fmt.Errorf("invalid contract address: %w", err).Error(), http.StatusBadRequest)
		return
	}

	var onboardHash [32]byte
	copy(onboardHash[:], onboardHashBytes)

	onboardRequest, err := h.kmsGovernance.FetchOnboardRequest(onboardHash)
	if err != nil {
		http.Error(w, fmt.Errorf("could not fetch onboard request: %w", err).Error(), http.StatusUnauthorized)
		return
	}

	if onboardRequest.Nonce.Cmp(big.NewInt(0)) == 0 {
		http.Error(w, fmt.Sprintf("onchain onboard request %s not found", hex.EncodeToString(onboardHash[:])), http.StatusUnauthorized)
		return
	}

	measurementsMap, err := h.kms.VerifyOnboardRequest(onboardRequest)
	if err != nil {
		h.log.Info("attestation issue", "onboardHash", onboardHash, "onboardRequest", onboardRequest, "onboardRequest.Attestation", onboardRequest.Attestation)
		http.Error(w, fmt.Errorf("invalid attestation: %w", err).Error(), http.StatusBadRequest)
		return
	}

	measurments, err := interfaces.DCAPReportFromMeasurement(measurementsMap)
	if err != nil {
		http.Error(w, fmt.Errorf("invalid measurements: %w", err).Error(), http.StatusBadRequest)
		return
	}

	identity, err := h.kmsGovernance.DCAPIdentity(*measurments, nil)
	if err != nil {
		http.Error(w, fmt.Errorf("invalid identity: %w", err).Error(), http.StatusBadRequest)
		return
	}

	identityAllowed, err := h.kmsGovernance.IdentityAllowed(identity, onboardRequest.Operator)
	if err != nil {
		http.Error(w, fmt.Errorf("could not map identity: %w", err).Error(), http.StatusUnauthorized)
		return
	}

	if !identityAllowed {
		http.Error(w, fmt.Errorf("identity %s for operator %s unauthorized", hex.EncodeToString(identity[:]), hex.EncodeToString(onboardRequest.Operator[:])).Error(), http.StatusUnauthorized)
		return
	}

	// TODO: add to interface
	ecryptedSeed, err := h.kms.OnboardRemote(onboardRequest.Pubkey)
	if err != nil {
		http.Error(w, fmt.Errorf("could not process onboard request: %w", err).Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/octet-stream")
	_, err = w.Write(ecryptedSeed)
	if err != nil {
		http.Error(w, fmt.Errorf("could not encode response: %w", err).Error(), http.StatusInternalServerError)
		return
	}
}

// HandleSecrets processes TEE instance secrets requests with onchain authorization.
// It verifies both the instance's identity and operator authorization against
// the governance contract, then provides cryptographic materials if authorized.
//
// URL format: POST /api/attested/secrets/{contract_address}
// Required headers:
//   - X-Flashbots-Attestation-Type: Type of attestation (azure-tdx, qemu-tdx)
//   - X-Flashbots-Measurement: JSON-encoded measurement values
//
// Request body: TLS Certificate Signing Request (CSR) in PEM format
// The CSR may optionally include an operator signature as an X.509 extension
// with OID cryptoutils.OIDOperatorSignature. This signature provides additional
// authorization through onchain governance verification.
//
// Response: JSON-encoded AppSecrets containing:
//   - Application private key for decrypting secrets
//   - Signed TLS certificate for secure communication
//   - Operator's Ethereum address (if provided)
//   - Attestation evidence
func (h *Handler) HandleSecrets(w http.ResponseWriter, r *http.Request) {
	contractAddr, err := interfaces.NewContractAddressFromHex(r.PathValue("contract_address"))
	if err != nil {
		http.Error(w, fmt.Errorf("invalid contract address: %w", err).Error(), http.StatusBadRequest)
		return
	}

	// Should be cached
	appAllowed, err := h.kmsGovernance.ApplicationAllowed(contractAddr)
	if err != nil {
		http.Error(w, fmt.Errorf("could not verify application is allowed: %w", err).Error(), http.StatusInternalServerError)
		return
	}
	if !appAllowed {
		http.Error(w, fmt.Errorf("application not allowed: %w", err).Error(), http.StatusUnauthorized)
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
	response, err := h.kms.AppSecrets(contractAddr, csr)
	if err != nil {
		http.Error(w, fmt.Errorf("could not prepare app secrets: %w", err).Error(), http.StatusUnauthorized)
		return
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
// 1. Extracts attestation type and measurements from headers
// 2. Computes the workload identity through the onchain governance contract
// 3. Parses the CSR to extract any operator signature extensions
// 4. If an operator signature is present, recovers the operator's Ethereum address
//
// This implements a critical security verification step ensuring that only
// properly attested instances with authorized operators can receive cryptographic materials.
func ParseWorkloadAndOperatorIdentity(r *http.Request, registry interfaces.OnchainRegistry, csr interfaces.TLSCSR) ([32]byte, [20]byte, error) {
	// Extract attestation type and measurements from ATLS headers
	attestationType, measurements, err := cryptoutils.MeasurementsFromATLS(r)
	if err != nil {
		return [32]byte{}, [20]byte{}, fmt.Errorf("invalid measurements: %w", err)
	}

	// Calculate identity from attestation
	identity, err := interfaces.AttestationToIdentity(attestationType, measurements, registry)
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
		if ext.Id.Equal(cryptoutils.OIDOperatorSignature) {
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

type SimpleHandlerKMS struct {
	*simplekms.SimpleKMS
	kmsAddress interfaces.ContractAddress
}

func NewSimpleHandlerKMS(kms *simplekms.SimpleKMS, addr interfaces.ContractAddress) *SimpleHandlerKMS {
	return &SimpleHandlerKMS{
		SimpleKMS:  kms,
		kmsAddress: addr,
	}
}

func (k *SimpleHandlerKMS) VerifyOnboardRequest(onboardRequest interfaces.OnboardRequest) (map[int]string, error) {
	var onboardReportData [64]byte = simplekms.OnboardRequestReportData(k.kmsAddress, onboardRequest)
	measurementsMap, err := cryptoutils.VerifyDCAPAttestation(onboardReportData, onboardRequest.Attestation)
	if err != nil {
		return nil, fmt.Errorf("invalid attestation: %w", err)
	}
	return measurementsMap, nil
}
