package httpserver

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// Header constants used in HTTP requests and responses.
const (
	// AttestationTypeHeader specifies the TEE attestation mechanism used.
	// Supported values: "azure-tdx", "qemu-tdx"
	AttestationTypeHeader = "X-Flashbots-Attestation-Type"

	// MeasurementHeader contains a JSON-encoded map of measurement values.
	// Format: {"0":"00", "1":"01", ...} mapping register index to hex value.
	MeasurementHeader = "X-Flashbots-Measurement"

	// Supported attestation types
	azureTDX = "azure-tdx" // Azure confidential computing with TDX
	qemuTDX  = "qemu-tdx"  // Any DCAP-compatible TDX implementation

	// maxBodySize is the maximum allowed request body size (1MB).
	maxBodySize = 1024 * 1024
)

// RequestError provides structured error information for HTTP responses.
// It includes both an HTTP status code and the underlying error.
type RequestError struct {
	// StatusCode is the HTTP status code to return.
	StatusCode int

	// Err is the underlying error.
	Err error
}

// Error returns the error message from the underlying error.
func (e *RequestError) Error() string {
	return e.Err.Error()
}

// Handler processes HTTP requests for the TEE registry service.
// It integrates with the KMS, storage system, and on-chain registry.
// The handler is responsible for processing configuration templates,
// including decrypting any pre-encrypted secrets.
type Handler struct {
	kms             interfaces.KMS
	storageFactory  interfaces.StorageBackendFactory
	registryFactory interfaces.RegistryFactory
	log             *slog.Logger
}

// NewHandler creates a new HTTP request handler with the specified dependencies.
//
// Parameters:
//   - kms: Key Management Service for cryptographic operations and secret decryption
//   - storageFactory: Factory for creating storage backends
//   - registryFactory: Factory for creating registry clients
//   - log: Structured logger for operational insights
//
// Returns a configured Handler instance.
func NewHandler(kms interfaces.KMS, storageFactory interfaces.StorageBackendFactory, registryFactory interfaces.RegistryFactory, log *slog.Logger) *Handler {
	return &Handler{
		kms:             kms,
		storageFactory:  storageFactory,
		registryFactory: registryFactory,
		log:             log,
	}
}

// HandleRegister processes TEE instance registration requests.
// It validates attestation evidence, verifies the instance's identity,
// and provides cryptographic materials and configuration if authorized.
//
// URL format: POST /api/attested/register/{contract_address}
// Required headers:
//   - X-Flashbots-Attestation-Type: Type of attestation (azureTDX/qemuTDX)
//   - X-Flashbots-Measurement: JSON-encoded measurement values
//
// Request body: TLS Certificate Signing Request (CSR) in PEM format
//
// Response: JSON containing:
//   - app_privkey: Private key for the application
//   - tls_cert: Signed TLS certificate
//   - config: Instance configuration with resolved references and decrypted secrets
//
// The handler decrypts any pre-encrypted secrets referenced in the configuration template
// before sending the response, ensuring the TEE instance receives plaintext secrets.
func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	// Parse attestation type from header
	attestationType := r.Header.Get(AttestationTypeHeader)
	if attestationType == "" {
		http.Error(w, "Missing attestation type header", http.StatusBadRequest)
		return
	}

	// Parse measurements from header
	measurementsJSON := r.Header.Get(MeasurementHeader)
	if measurementsJSON == "" {
		http.Error(w, "Missing measurements header", http.StatusBadRequest)
		return
	}

	// Parse measurements JSON to map
	var measurements map[string]string
	if err := json.Unmarshal([]byte(measurementsJSON), &measurements); err != nil {
		h.log.Error("Failed to parse measurements JSON", "err", err, "json", measurementsJSON)
		http.Error(w, "Invalid measurements format", http.StatusBadRequest)
		return
	}

	contractAddrHex := r.PathValue("contract_address")
	if contractAddrHex == "" {
		http.Error(w, "Missing contract address in URL", http.StatusBadRequest)
		return
	}

	// Parse contract address from hex
	contractAddrBytes, err := hex.DecodeString(contractAddrHex)
	if err != nil || len(contractAddrBytes) != 20 {
		h.log.Error("Invalid contract address", "err", err, "address", contractAddrHex)
		http.Error(w, "Invalid contract address format", http.StatusBadRequest)
		return
	}

	var contractAddr interfaces.ContractAddress
	copy(contractAddr[:], contractAddrBytes)

	// Read CSR from request body
	csr, err := io.ReadAll(r.Body)
	if err != nil {
		h.log.Error("Failed to read request body", "err", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	if len(csr) == 0 {
		http.Error(w, "Empty CSR in request body", http.StatusBadRequest)
		return
	}

	// Process the registration
	appPrivkey, tlsCert, instanceConfig, err := h.handleRegister(r.Context(), attestationType, measurements, contractAddr, csr)
	if err != nil {
		h.log.Error("Registration failed", "err", err,
			"attestationType", attestationType,
			"contractAddress", contractAddrHex)

		// Return appropriate status code based on error type
		if strings.Contains(err.Error(), "invalid") {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Prepare response
	response := map[string]interface{}{
		"app_privkey": string(appPrivkey),
		"tls_cert":    string(tlsCert),
		"config":      string(instanceConfig),
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.log.Error("Failed to encode response", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// HandleAppMetadata retrieves application metadata for a specified contract address.
// It provides public cryptographic materials like CA certificate and public key.
//
// URL format: GET /api/public/app_metadata/{contract_address}
//
// Response: JSON containing:
//   - ca_cert: CA certificate in PEM format
//   - app_pubkey: Application public key in PEM format
//   - attestation: Attestation data
func (h *Handler) HandleAppMetadata(w http.ResponseWriter, r *http.Request) {
	contractAddrHex := r.PathValue("contract_address")

	// Parse contract address from hex
	contractAddrBytes, err := hex.DecodeString(contractAddrHex)
	if err != nil || len(contractAddrBytes) != 20 {
		h.log.Error("Invalid contract address", "err", err, "address", contractAddrHex)
		http.Error(w, "Invalid contract address format", http.StatusBadRequest)
		return
	}

	var contractAddr interfaces.ContractAddress
	copy(contractAddr[:], contractAddrBytes)

	// Get PKI from KMS
	pki, err := h.kms.GetPKI(contractAddr)
	if err != nil {
		h.log.Error("Failed to get PKI", "err", err, "contractAddress", contractAddrHex)
		http.Error(w, fmt.Sprintf("Failed to get PKI: %v", err), http.StatusInternalServerError)
		return
	}

	// Prepare response
	response := map[string]interface{}{
		"ca_cert":     string(pki.Ca),
		"app_pubkey":  string(pki.Pubkey),
		"attestation": string(pki.Attestation),
	}

	// Return JSON response
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.log.Error("Failed to encode response", "err", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
}

// attestationToIdentity converts attestation data to an identity hash.
// It uses the appropriate computation method based on attestation type.
//
// Parameters:
//   - attestationType: The type of attestation (azureTDX or qemuTDX)
//   - measurements: Map of measurement registers and their values
//   - registry: Registry client for computing identity hashes
//
// Returns:
//   - The computed identity hash
//   - Error if attestation type is unsupported or computation fails
func attestationToIdentity(attestationType string, measurements map[string]string, registry interfaces.OnchainRegistry) ([32]byte, error) {
	switch attestationType {
	case azureTDX:
		// For MAA the measurements are simply the PCRs encoded as map[uint32][]byte
		// Create an empty MAA report - this is a placeholder, you'll need to fill it properly
		maaReport := &interfaces.MAAReport{}
		return registry.ComputeMAAIdentity(maaReport)
	case qemuTDX:
		// For DCAP the measurements are RTMRs and MRTD encoded as map[uint32][]byte
		// Create an empty DCAP report - this is a placeholder, you'll need to fill it properly
		dcapReport := &interfaces.DCAPReport{}
		return registry.ComputeDCAPIdentity(dcapReport)
	default:
		return [32]byte{}, fmt.Errorf("unsupported attestation type: %s", attestationType)
	}
}

// handleRegister processes TEE instance registration requests.
// This is the core business logic implementation for HandleRegister.
//
// Parameters:
//   - ctx: Context for the operation
//   - attestationType: Type of attestation (azureTDX/qemuTDX)
//   - measurements: Map of measurement registers and their values
//   - contractAddress: Contract address for the application
//   - csr: Certificate Signing Request in PEM format
//
// Returns:
//   - Application private key
//   - Signed TLS certificate
//   - Instance configuration
//   - Error if registration fails
func (h *Handler) handleRegister(ctx context.Context, attestationType string, measurements map[string]string, contractAddr interfaces.ContractAddress, csr interfaces.TLSCSR) (interfaces.AppPrivkey, interfaces.TLSCert, interfaces.InstanceConfig, error) {
	// Get the registry for this contract
	registry, err := h.registryFactory.RegistryFor(contractAddr)
	if err != nil {
		h.log.Error("Failed to get registry for contract", "err", err, slog.String("contractAddress", string(contractAddr[:])))
		return nil, nil, nil, fmt.Errorf("registry access error: %w", err)
	}

	// Calculate identity from attestation
	identity, err := attestationToIdentity(attestationType, measurements, registry)
	if err != nil {
		h.log.Error("Failed to compute identity", "err", err, slog.String("attestationType", attestationType))
		return nil, nil, nil, fmt.Errorf("identity computation error: %w", err)
	}

	// Get config template hash for this identity. This also makes sure the identity is whitelisted.
	configTemplateHash, err := registry.IdentityConfigMap(identity)
	if err != nil {
		h.log.Error("Failed to get config template hash", "err", err, slog.String("identity", string(identity[:])))
		return nil, nil, nil, fmt.Errorf("config lookup error: %w", err)
	}

	if configTemplateHash == [32]byte{} {
		h.log.Error("No config template assigned to identity", slog.String("identity", string(identity[:])))
		return nil, nil, nil, errors.New("no config template assigned to identity")
	}

	// Get application private key for this contract
	appPrivkey, err := h.kms.GetAppPrivkey(contractAddr)
	if err != nil {
		h.log.Error("Failed to get app private key", "err", err, slog.String("contractAddress", string(contractAddr[:])))
		return nil, nil, nil, fmt.Errorf("key retrieval error: %w", err)
	}

	// Sign the CSR to create TLS certificate
	tlsCert, err := h.kms.SignCSR(contractAddr, csr)
	if err != nil {
		h.log.Error("Failed to sign CSR", "err", err, slog.String("contractAddress", string(contractAddr[:])))
		return nil, nil, nil, fmt.Errorf("certificate signing error: %w", err)
	}

	// Get all storage backends from registry
	backendLocations, err := registry.AllStorageBackends()
	if err != nil {
		h.log.Error("Failed to get storage backends", "err", err)
		return nil, nil, nil, fmt.Errorf("storage backend retrieval error: %w", err)
	}

	// Convert []string to []StorageBackendLocation for CreateMultiBackend
	locationURIs := make([]interfaces.StorageBackendLocation, len(backendLocations))
	for i, loc := range backendLocations {
		locationURIs[i] = interfaces.StorageBackendLocation(loc)
	}

	lazyTlsAuthCert := func() (tls.Certificate, error) {
		// TODO: cache and move to a standalone structure

		// Note: reusing app privkey here, might not be secure
		tmpPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return tls.Certificate{}, err
		}

		tmpKeyBytes, err := x509.MarshalPKCS8PrivateKey(tmpPrivateKey)
		if err != nil {
			return tls.Certificate{}, err
		}

		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: tmpKeyBytes})

		// Create a CSR template
		csrTemplate := x509.CertificateRequest{
			Subject: pkix.Name{
				CommonName: fmt.Sprintf("%x.app", contractAddr),
			},
			SignatureAlgorithm: x509.ECDSAWithSHA256,
		}

		// Create a CSR using the private key and template
		csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, tmpPrivateKey)
		if err != nil {
			return tls.Certificate{}, err
		}

		// Encode the CSR in PEM format
		csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

		tlsCert, err := h.kms.SignCSR(contractAddr, csrPEM)
		if err != nil {
			return tls.Certificate{}, err
		}

		return tls.X509KeyPair(tlsCert, keyPEM)
	}

	// Create multi-storage backend
	multiStorage, err := h.storageFactory.WithTLSAuth(lazyTlsAuthCert).CreateMultiBackend(locationURIs)
	if err != nil {
		h.log.Error("Failed to create multi-storage backend", "err", err)
		return nil, nil, nil, fmt.Errorf("multi-storage creation error: %w", err)
	}

	// Fetch config template
	configTemplate, err := multiStorage.Fetch(ctx, configTemplateHash, interfaces.ConfigType)
	if err != nil {
		h.log.Error("Failed to fetch config template", "err", err, slog.String("configHash", string(configTemplateHash[:])))
		return nil, nil, nil, fmt.Errorf("config template retrieval error: %w", err)
	}

	// Process the config template - pass the app private key for decryption
	processedConfig, err := h.processConfigTemplate(ctx, multiStorage, configTemplate, appPrivkey)
	if err != nil {
		h.log.Error("Failed to process config template", "err", err)
		return nil, nil, nil, fmt.Errorf("config processing error: %w", err)
	}

	return appPrivkey, tlsCert, processedConfig, nil
}

// Reference represents a reference to another content item in a configuration template.
// It contains both the full reference string and the hash of the referenced content.
type Reference struct {
	fullRef string // The full reference string (e.g., "__CONFIG_REF_<hash>")
	hash    string // The hash part of the reference
}

// findReferences locates all pattern matches in a template string.
// It returns a slice of Reference objects for each match found.
//
// Parameters:
//   - templateStr: The template string to search
//   - prefix: The reference prefix to look for (e.g., "__CONFIG_REF_")
//
// Returns:
//   - Slice of found references
//   - Error if regex compilation fails
func findReferences(templateStr, prefix string) ([]Reference, error) {
	pattern := prefix + `([0-9a-fA-F]{64})`
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	matches := re.FindAllStringSubmatch(templateStr, -1)
	refs := make([]Reference, 0, len(matches))

	for _, match := range matches {
		if len(match) >= 2 {
			refs = append(refs, Reference{
				fullRef: match[0],
				hash:    match[1],
			})
		}
	}

	return refs, nil
}

// hexToHash converts a hex string to a [32]byte hash.
//
// Parameters:
//   - hexStr: Hex string representation of the hash
//
// Returns:
//   - [32]byte hash value
//   - Error if the hex string is invalid or wrong length
func hexToHash(hexStr string) ([32]byte, error) {
	var hash [32]byte

	decoded, err := hex.DecodeString(hexStr)
	if err != nil {
		return hash, err
	}

	if len(decoded) != 32 {
		return hash, fmt.Errorf("invalid hash length: %d", len(decoded))
	}

	copy(hash[:], decoded)
	return hash, nil
}

// replaceReference replaces a reference string with new content.
//
// Parameters:
//   - templateStr: Original template string
//   - oldStr: String to replace (the reference)
//   - newStr: New content to insert
//
// Returns:
//   - Updated string with replacement
func replaceReference(templateStr, oldStr, newStr string) string {
	return regexp.MustCompile(`["]*`+regexp.QuoteMeta(oldStr)+`["]*`).ReplaceAllString(templateStr, newStr)
}

// processConfigTemplate resolves all references in a configuration template.
// It replaces config and secret references with their actual content.
// For secret references, it retrieves pre-encrypted secrets from storage and
// decrypts them using the application's private key before inclusion in the
// configuration.
//
// Parameters:
//   - ctx: Context for the operation
//   - storage: Storage backend to fetch referenced content
//   - configTemplate: Original template with references
//   - appPrivKey: Application private key for decrypting secrets
//
// Returns:
//   - Processed configuration with all references resolved and secrets decrypted
//   - Error if reference resolution or decryption fails
//
// Secret references have the form: __SECRET_REF_<hash>
// These are replaced with the decrypted content of the referenced secret.
func (h *Handler) processConfigTemplate(ctx context.Context, storage interfaces.StorageBackend, configTemplate []byte, appPrivKey interfaces.AppPrivkey) (interfaces.InstanceConfig, error) {
	// Convert to string for easier processing
	templateStr := string(configTemplate)

	// Define constants for reference patterns
	const (
		configRefPrefix = "__CONFIG_REF_"
		secretRefPrefix = "__SECRET_REF_"
	)

	// Process config references - find all instances of "__CONFIG_REF_<hash>"
	configRefs, err := findReferences(templateStr, configRefPrefix)
	if err != nil {
		return nil, fmt.Errorf("error finding config references: %w", err)
	}

	// Replace each config reference with actual content
	for _, ref := range configRefs {
		configHash, err := hexToHash(ref.hash)
		if err != nil {
			h.log.Error("Invalid config hash format", slog.String("hash", ref.hash), "err", err)
			return nil, fmt.Errorf("invalid config hash format %s: %w", ref.hash, err)
		}

		configData, err := storage.Fetch(ctx, configHash, interfaces.ConfigType)
		if err != nil {
			h.log.Error("Failed to fetch config", "err", err, slog.String("hash", ref.hash))
			return nil, fmt.Errorf("failed to fetch config %s: %w", ref.hash, err)
		}

		// Replace the reference with the actual config
		templateStr = replaceReference(templateStr, ref.fullRef, string(configData))
	}

	// Process secret references - find all instances of "__SECRET_REF_<hash>"
	secretRefs, err := findReferences(templateStr, secretRefPrefix)
	if err != nil {
		return nil, fmt.Errorf("error finding secret references: %w", err)
	}

	// Replace each secret reference with the decrypted secret value
	for _, ref := range secretRefs {
		secretHash, err := hexToHash(ref.hash)
		if err != nil {
			h.log.Error("Invalid secret hash format", slog.String("hash", ref.hash), "err", err)
			return nil, fmt.Errorf("invalid secret hash format %s: %w", ref.hash, err)
		}

		// Fetch the pre-encrypted secret
		encryptedSecretData, err := storage.Fetch(ctx, secretHash, interfaces.SecretType)
		if err != nil {
			h.log.Error("Failed to fetch secret", "err", err, slog.String("hash", ref.hash))
			return nil, fmt.Errorf("failed to fetch secret %s: %w", ref.hash, err)
		}

		// Decrypt the secret with the app's private key
		decryptedData, err := cryptoutils.DecryptWithPrivateKey(appPrivKey, encryptedSecretData)
		if err != nil {
			h.log.Error("Failed to decrypt secret", "err", err, slog.String("hash", ref.hash))
			return nil, fmt.Errorf("failed to decrypt secret %s: %w", ref.hash, err)
		}

		// Note: might need escaping
		templateStr = replaceReference(templateStr, ref.fullRef, string(decryptedData))
	}

	return []byte(templateStr), nil
}
