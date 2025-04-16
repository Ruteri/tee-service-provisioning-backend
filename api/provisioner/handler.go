package provisioner

import (
	"bytes"
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

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-chi/chi/v5"
	"github.com/ruteri/tee-service-provisioning-backend/api"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// Header constants used in HTTP requests and responses.
const (
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

func (h *Handler) RegisterRoutes(r chi.Router) {
	r.Post("/api/attested/register/{contract_address}", h.HandleRegister)
	r.Get("/api/public/app_metadata/{contract_address}", h.HandleAppMetadata)
}

// HandleRegister processes TEE instance registration requests.
// It validates attestation evidence, verifies the instance's identity,
// and provides cryptographic materials and configuration if authorized.
//
// URL format: POST /api/attested/register/{contract_address}
//
// Request body: TLS Certificate Signing Request (CSR) in PEM format
// The CSR may optionally include an operator signature as an X.509 extension
// with OID api.OIDOperatorSignature. This signature provides additional
// authorization from an approved operator.
//
// Both CSR and client certificate must be attested, their pubkey must be the same, and their measurements must match
//
// Response: JSON, see api.RegistrationResponse
//
// The handler decrypts any pre-encrypted secrets referenced in the configuration template
// before sending the response, ensuring the TEE instance receives plaintext secrets.
func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	// TODO: note that contract could be a part of the attestation as well
	contractAddr, err := interfaces.NewContractAddressFromHex(r.PathValue("contract_address"))
	if err != nil {
		h.log.Error("Invalid contract address", "err", err, "address", r.PathValue("contract_address"))
		http.Error(w, "Invalid contract address format", http.StatusBadRequest)
		return
	}

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
	appPrivkey, tlsCert, instanceConfig, err := h.handleRegister(r.Context(), r.TLS.PeerCertificates[0], contractAddr, csr)
	if err != nil {
		h.log.Error("Registration failed", "err", err,
			"contractAddress", contractAddr.String())

		// Return appropriate status code based on error type
		if strings.Contains(err.Error(), "invalid") {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Prepare response
	response := api.RegistrationResponse{
		AppPrivkey: appPrivkey,
		TLSCert:    tlsCert,
		Config:     instanceConfig,
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
// Response: JSON, see api.MetadataResponse
func (h *Handler) HandleAppMetadata(w http.ResponseWriter, r *http.Request) {
	// Parse contract address from hex
	contractAddr, err := interfaces.NewContractAddressFromHex(r.PathValue("contract_address"))
	if err != nil {
		h.log.Error("Invalid contract address", "err", err, "address", r.PathValue("contract_address"))
		http.Error(w, "Invalid contract address format", http.StatusBadRequest)
		return
	}

	registry, err := h.registryFactory.RegistryFor(contractAddr)
	if err != nil {
		h.log.Error("Failed to get registry", "err", err, "contractAddress", contractAddr.String())
		http.Error(w, fmt.Errorf("Failed to get registry: %w", err).Error(), http.StatusInternalServerError)
		return
	}

	pki, err := h.kms.GetPKI(contractAddr)
	if err != nil {
		h.log.Error("Failed to get PKI", "err", err, "contractAddress", contractAddr.String())
		http.Error(w, fmt.Errorf("Failed to get PKI: %w", err).Error(), http.StatusInternalServerError)
		return
	}

	domainNamesFromRegistry, err := registry.AllInstanceDomainNames()
	if err != nil {
		h.log.Error("Failed to get domain names", "err", err, "contractAddress", contractAddr.String())
		http.Error(w, fmt.Errorf("Failed to get domain names: %w", err).Error(), http.StatusInternalServerError)
		return
	}

	domainNames := []interfaces.AppDomainName{}
	for _, rawDN := range domainNamesFromRegistry {
		dn, err := interfaces.NewAppDomainName(rawDN)
		if err != nil {
			h.log.Debug("invalid domain received from registry", "raw domain name", rawDN)
		} else {
			domainNames = append(domainNames, dn)
		}
	}

	// Prepare response
	response := api.MetadataResponse{
		CACert:      pki.Ca,
		AppPubkey:   pki.Pubkey,
		DomainNames: domainNames,
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

// handleRegister processes TEE instance registration requests.
// This is the core business logic implementation for HandleRegister.
//
// Parameters:
//   - ctx: Context for the operation
//   - attestationType: Type of attestation
//   - measurements: Map of measurement registers and their values
//   - contractAddress: Contract address for the application
//   - csr: Certificate Signing Request in PEM format
//
// The function performs dual authorization:
//  1. TEE Identity Verification: Computes an identity hash from attestation evidence
//     and verifies it against the on-chain registry.
//  2. Optional Operator Authorization: If the CSR contains an operator signature
//     extension (OID api.OIDOperatorSignature), the function extracts and validates
//     the operator's Ethereum address and passes on to on-chain contract for authorization.
//
// Returns:
//   - Application private key
//   - Signed TLS certificate
//   - Instance configuration
//   - Error if registration fails
func (h *Handler) handleRegister(ctx context.Context, clientCert *x509.Certificate, contractAddr interfaces.ContractAddress, csr cryptoutils.TLSCSR) (interfaces.AppPrivkey, interfaces.TLSCert, interfaces.InstanceConfig, error) {
	// Parse attestation type from header
	attestationType, measurements, err := cryptoutils.VerifyCertificateAttestation(clientCert)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("could not verify client cert attestation: %w", err)
	}

	// Parse CSR to extract any operator signature extensions
	parsedCsr, err := csr.GetX509CSR()
	if err != nil {
		h.log.Error("Failed to parse csr", "err", err)
		return nil, nil, nil, fmt.Errorf("csr parsing error: %w", err)
	}

	if !bytes.Equal(parsedCsr.RawSubjectPublicKeyInfo, clientCert.RawSubjectPublicKeyInfo) {
		return nil, nil, nil, fmt.Errorf("mismatched client and csr public keys")
	}

	csrAttestationType, csrMeasurements, err := cryptoutils.VerifyCertificateRequestAttestation(parsedCsr)
	if csrAttestationType != attestationType {
		return nil, nil, nil, fmt.Errorf("mismatched attestation type in request (%s) and csr (%s)", attestationType, csrAttestationType)
	}
	if len(csrMeasurements) != len(measurements) {
		return nil, nil, nil, fmt.Errorf("mismatched measurements\nreq: %v\ncsr: %v", measurements, csrMeasurements)
	}
	for i, v := range measurements {
		if !bytes.Equal(csrMeasurements[i], v) {
			return nil, nil, nil, fmt.Errorf("mismatched measurements\nreq: %v\ncsr: %v", measurements, csrMeasurements)
		}
	}

	// TODO: also verify all extensions match (including the raw attestation)

	// Get the registry for this contract
	registry, err := h.registryFactory.RegistryFor(contractAddr)
	if err != nil {
		h.log.Error("Failed to get registry for contract", "err", err, slog.String("contractAddress", string(contractAddr[:])))
		return nil, nil, nil, fmt.Errorf("registry access error: %w", err)
	}

	// Calculate identity from attestation
	identity, err := api.AttestationToIdentity(attestationType, measurements, registry)
	if err != nil {
		h.log.Error("Failed to compute identity", "err", err, slog.String("attestationType", attestationType))
		return nil, nil, nil, fmt.Errorf("identity computation error: %w", err)
	}

	// Extract operator address from signature extension if present
	// This is used for additional authorization beyond the TEE attestation
	var operatorAddress [20]byte
	for _, ext := range parsedCsr.Extensions {
		if ext.Id.Equal(api.OIDOperatorSignature) {
			// Recover Ethereum address from signature over the CSR's public key
			pubkey, err := crypto.SigToPub(cryptoutils.DERPubkeyHash(parsedCsr.RawSubjectPublicKeyInfo), ext.Value)
			if err != nil {
				h.log.Error("Failed to recover signer from operator signature", "err", err)
				return nil, nil, nil, fmt.Errorf("operator signature verification error: %w", err)
			}
			// Convert public key to Ethereum address
			operatorAddress = crypto.PubkeyToAddress(*pubkey)
			h.log.Info("Operator signature present", "operator", hex.EncodeToString(operatorAddress[:]))
		}
	}

	// Get config template hash for this identity, validating both TEE identity and operator if provided
	// If operatorAddress is empty (no signature), authorization is based solely on TEE identity
	configTemplateHash, err := registry.IdentityConfigMap(identity, operatorAddress)
	if err != nil {
		h.log.Error("Failed to get config template hash", "err", err,
			slog.String("identity", string(identity[:])),
			slog.String("operator", hex.EncodeToString(operatorAddress[:])))
		return nil, nil, nil, fmt.Errorf("config lookup error for %x: %w", identity, err)
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
		locationURI, err := interfaces.NewStorageBackendLocation(loc)
		if err != nil {
			h.log.Debug("invalid location uri, ignoring", "err", err)
		} else {
			locationURIs[i] = locationURI
		}
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
