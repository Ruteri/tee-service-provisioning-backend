package provisioner

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
	r.Get("/api/public/app_metadata/{contract_address}", h.HandleAppMetadata)
	r.Post("/api/attested/register/{contract_address}", h.HandleRegister)
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

// HandleRegister processes TEE instance registration requests.
// It validates attestation evidence, verifies the instance's identity,
// and provides cryptographic materials and configuration if authorized.
//
// URL format: POST /api/attested/register/{contract_address}
// Required headers:
//   - X-Flashbots-Attestation-Type: Type of attestation
//   - X-Flashbots-Measurement: JSON-encoded measurement values
//
// Request body: TLS Certificate Signing Request (CSR) in PEM format
// The CSR may optionally include an operator signature as an X.509 extension
// with OID api.OIDOperatorSignature. This signature provides additional
// authorization from an approved operator.
//
// Response: JSON, see api.RegistrationResponse
//
// The handler decrypts any pre-encrypted secrets referenced in the configuration template
// before sending the response, ensuring the TEE instance receives plaintext secrets.
func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
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
	response, err := h.handleRegister(r, contractAddr, csr)
	if err != nil {
		h.log.Error("Registration failed", "err", err,
			"contractAddress", contractAddrHex)

		// Return appropriate status code based on error type
		if strings.Contains(err.Error(), "invalid") {
			http.Error(w, err.Error(), http.StatusBadRequest)
		} else {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
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

// handleRegister processes TEE instance registration requests and manages the overall registration flow.
// It coordinates identity verification, cryptographic material preparation, and configuration resolution.
//
// Parameters:
//   - r: HTTP request containing attestation evidence
//   - contractAddr: Contract address identifying the application
//   - csr: Certificate Signing Request in PEM format
//
// Returns:
//   - Application private key for secret decryption
//   - Signed TLS certificate for secure communication
//   - Resolved instance configuration with all references and secrets processed
//   - Error if any step of the registration process fails
func (h *Handler) handleRegister(r *http.Request, contractAddr interfaces.ContractAddress, csr interfaces.TLSCSR) (api.RegistrationResponse, error) {
	// Get the registry for this contract
	registry, err := h.registryFactory.RegistryFor(contractAddr)
	if err != nil {
		h.log.Debug("Failed to get registry for contract", "err", err, slog.String("contractAddress", string(contractAddr[:])))
		return api.RegistrationResponse{}, fmt.Errorf("registry access error: %w", err)
	}

	// Extract workload identity and operator identity from attestation evidence and CSR
	identity, operatorAddress, err := h.parseWorkloadAndOperatorIdentity(r, registry, csr)
	if err != nil {
		return api.RegistrationResponse{}, fmt.Errorf("could not parse identity from request: %w", err)
	}

	identityAllowed, err := registry.IdentityAllowed(identity, operatorAddress)
	if err != nil {
		return api.RegistrationResponse{}, fmt.Errorf("could not verify identity is allowed: %w", err)
	}
	if !identityAllowed {
		return api.RegistrationResponse{}, fmt.Errorf("identity not allowed")
	}

	// Prepare cryptographic materials (app private key and TLS certificate)
	appPrivkey, tlsCert, err := h.prepareAppMaterials(contractAddr, csr)
	if err != nil {
		return api.RegistrationResponse{}, err
	}

	// Get config template hash for this identity, validating both TEE identity and operator if provided
	configTemplateHash, err := registry.IdentityConfigMap(identity, operatorAddress)
	if err != nil {
		return api.RegistrationResponse{}, fmt.Errorf("config lookup error for %x: %w", identity, err)
	}

	var processedConfig interfaces.InstanceConfig
	if configTemplateHash != [32]byte{} {
		// Resolve configuration template with all references
		processedConfig, err = h.resolveConfiguration(r.Context(), registry, configTemplateHash, contractAddr, appPrivkey)
		if err != nil {
			return api.RegistrationResponse{}, fmt.Errorf("could not process config: %w", err)
		}
	}

	return api.RegistrationResponse{AppPrivkey: appPrivkey, TLSCert: tlsCert, Config: processedConfig}, nil
}

// parseWorkloadAndOperatorIdentity extracts workload identity from attestation measurements
// and operator address from CSR signature extension if present. It performs the first phase of
// the dual authorization process by validating the TEE attestation evidence and extracting any
// operator signature.
//
// Parameters:
//   - r: HTTP request containing attestation headers
//   - registry: Application governance contract
//   - csr: Certificate Signing Request potentially containing operator signature
//
// Returns:
//   - Computed identity hash from attestation data
//   - Recovered operator Ethereum address (zero if no signature present)
//   - Error if attestation verification or signature recovery fails
func (h *Handler) parseWorkloadAndOperatorIdentity(r *http.Request, registry interfaces.OnchainRegistry, csr interfaces.TLSCSR) ([32]byte, [20]byte, error) {
	// Extract attestation type and measurements from ATLS headers
	attestationType, measurements, err := cryptoutils.MeasurementsFromATLS(r)
	if err != nil {
		return [32]byte{}, [20]byte{}, fmt.Errorf("invalid measurements: %w", err)
	}

	// Calculate identity from attestation
	identity, err := api.AttestationToIdentity(attestationType, measurements, registry)
	if err != nil {
		h.log.Debug("Failed to compute identity", "err", err, slog.String("attestationType", attestationType.StringID))
		return [32]byte{}, [20]byte{}, fmt.Errorf("identity computation error: %w", err)
	}

	// Parse CSR to extract any operator signature extensions
	parsedCsr, err := csr.GetX509CSR()
	if err != nil {
		h.log.Error("Failed to parse csr", "err", err)
		return [32]byte{}, [20]byte{}, fmt.Errorf("csr parsing error: %w", err)
	}

	// Extract operator address from signature extension if present
	var operatorAddress [20]byte
	for _, ext := range parsedCsr.Extensions {
		if ext.Id.Equal(api.OIDOperatorSignature) {
			// Recover Ethereum address from signature over the CSR's public key
			pubkey, err := crypto.SigToPub(cryptoutils.DERPubkeyHash(parsedCsr.RawSubjectPublicKeyInfo), ext.Value)
			if err != nil {
				h.log.Debug("Failed to recover signer from operator signature", "err", err)
				return [32]byte{}, [20]byte{}, fmt.Errorf("operator signature verification error: %w", err)
			}
			// Convert public key to Ethereum address
			operatorAddress = crypto.PubkeyToAddress(*pubkey)
			h.log.Debug("Operator signature present", "operator", hex.EncodeToString(operatorAddress[:]))
		}
	}

	return identity, operatorAddress, nil
}

// prepareAppMaterials retrieves the application private key and creates a signed TLS certificate.
// It interacts with the KMS to obtain the cryptographic materials needed for the TEE instance
// to function securely.
//
// Parameters:
//   - contractAddr: Contract address identifying the application
//   - csr: Certificate Signing Request to be signed by the application CA
//
// Returns:
//   - Application private key for secret decryption
//   - Signed TLS certificate for secure communication
//   - Error if key retrieval or certificate signing fails
func (h *Handler) prepareAppMaterials(contractAddr interfaces.ContractAddress, csr interfaces.TLSCSR) (interfaces.AppPrivkey, interfaces.TLSCert, error) {
	// Get application private key for this contract
	appPrivkey, err := h.kms.GetAppPrivkey(contractAddr)
	if err != nil {
		return nil, nil, fmt.Errorf("key retrieval error: %w", err)
	}

	// Sign the CSR to create TLS certificate
	tlsCert, err := h.kms.SignCSR(contractAddr, csr)
	if err != nil {
		return nil, nil, fmt.Errorf("certificate signing error: %w", err)
	}

	return appPrivkey, tlsCert, nil
}

// resolveConfiguration fetches the configuration template and resolves all references.
// It creates a multi-storage backend from registered locations, retrieves the configuration
// template, and processes it by resolving all references and decrypting any secret references.
//
// Parameters:
//   - ctx: Context for storage operations
//   - registry: Registry interface for retrieving storage backend locations
//   - configTemplateHash: Content hash of the configuration template to fetch
//   - contractAddr: Contract address for creating TLS auth certificates
//   - appPrivkey: Application private key for decrypting secret references
//
// Returns:
//   - Fully resolved instance configuration with all references processed
//   - Error if storage access, template retrieval, or reference processing fails
func (h *Handler) resolveConfiguration(ctx context.Context, registry interfaces.OnchainRegistry, configTemplateHash [32]byte, contractAddr interfaces.ContractAddress, appPrivkey interfaces.AppPrivkey) (interfaces.InstanceConfig, error) {
	// Get all storage backends from registry
	backendLocations, err := registry.AllStorageBackends()
	if err != nil {
		return nil, fmt.Errorf("storage backend retrieval error: %w", err)
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

	// Create client certificate generator function for authenticated backends
	lazyTlsAuthCert := CreateTLSAuthCertGenerator(h.kms, contractAddr)

	// Create multi-storage backend
	multiStorage, err := h.storageFactory.WithTLSAuth(lazyTlsAuthCert).CreateMultiBackend(locationURIs)
	if err != nil {
		h.log.Error("Failed to create multi-storage backend", "err", err)
		return nil, fmt.Errorf("multi-storage creation error: %w", err)
	}

	// Fetch config template
	configTemplate, err := multiStorage.Fetch(ctx, configTemplateHash, interfaces.ConfigType)
	if err != nil {
		h.log.Error("Failed to fetch config template", "err", err, slog.String("configHash", string(configTemplateHash[:])))
		return nil, fmt.Errorf("config template retrieval error: %w", err)
	}

	// Process the config template - pass the app private key for decryption
	processedConfig, err := h.processConfigTemplate(ctx, multiStorage, configTemplate, appPrivkey)
	if err != nil {
		h.log.Error("Failed to process config template", "err", err)
		return nil, fmt.Errorf("config processing error: %w", err)
	}

	return processedConfig, nil
}

// CreateTLSAuthCertGenerator returns a function that generates a TLS client certificate
// for authenticated storage backends like Vault. This generator function creates temporary
// key pairs, issues certificate signing requests, and obtains signed certificates from
// the KMS for authenticated access to storage backends.
//
// Parameter:
//   - contractAddr: Contract address used as the Common Name in certificate requests
//
// Returns:
//   - A generator function that produces TLS certificates when called
func CreateTLSAuthCertGenerator(kms interfaces.KMS, contractAddr interfaces.ContractAddress) func() (tls.Certificate, error) {
	return func() (tls.Certificate, error) {
		// Generate a temporary key pair
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

		// Get signed certificate from KMS
		tlsCert, err := kms.SignCSR(contractAddr, csrPEM)
		if err != nil {
			return tls.Certificate{}, err
		}

		return tls.X509KeyPair(tlsCert, keyPEM)
	}
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
