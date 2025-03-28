package httpserver

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"

	"github.com/ruteri/poc-tee-registry/interfaces"
)

const (
	AttestationTypeHeader = "X-Flashbots-Attestation-Type"
	MeasurementHeader     = "X-Flashbots-Measurement"
	ContractAddrHeader    = "X-Flashbots-Contract-Address"
	
	azureTDX  = "azure-tdx"
	qemuTDX   = "qemu-tdx" // Any DCAP
	
	maxBodySize = 1024 * 1024 // 1MB request body size limit
)

// RequestError provides structured error information for HTTP responses
type RequestError struct {
	StatusCode int
	Err        error
}

func (e *RequestError) Error() string {
	return e.Err.Error()
}

// Handler handles HTTP requests for the registry service
type Handler struct {
	kms             interfaces.KMS
	storageFactory  interfaces.StorageBackendFactory
	registryFactory interfaces.RegistryFactory
	log             *slog.Logger
}

// NewHandler creates a new request handler
func NewHandler(kms interfaces.KMS, storageFactory interfaces.StorageBackendFactory, registryFactory interfaces.RegistryFactory, log *slog.Logger) *Handler {
	return &Handler{
		kms:             kms,
		storageFactory:  storageFactory,
		registryFactory: registryFactory,
		log:             log,
	}
}

// HandleRegister handles HTTP requests for TEE instance registration
func (h *Handler) HandleRegister(w http.ResponseWriter, r *http.Request) {
	// Implementation will go here
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error":"Not implemented yet"}`))
}

// HandleAppMetadata handles HTTP requests for application metadata
func (h *Handler) HandleAppMetadata(w http.ResponseWriter, r *http.Request) {
	// Implementation will go here
	w.WriteHeader(http.StatusNotImplemented)
	w.Write([]byte(`{"error":"Not implemented yet"}`))
}

// attestationToIdentity converts attestation data to an identity hash
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

// handleRegister processes instance registration requests
func (h *Handler) handleRegister(ctx context.Context, attestationType string, measurements map[string]string, contractAddress interfaces.ContractAddress, csr interfaces.TLSCSR) (interfaces.AppPrivkey, interfaces.TLSCert, interfaces.InstanceConfig, error) {
	// Get the registry for this contract
	registry, err := h.registryFactory.RegistryFor(contractAddress)
	if err != nil {
		h.log.Error("Failed to get registry for contract", err, slog.String("contractAddress", string(contractAddress[:])))
		return nil, nil, nil, fmt.Errorf("registry access error: %w", err)
	}

	// Calculate identity from attestation
	identity, err := attestationToIdentity(attestationType, measurements, registry)
	if err != nil {
		h.log.Error("Failed to compute identity", err, slog.String("attestationType", attestationType))
		return nil, nil, nil, fmt.Errorf("identity computation error: %w", err)
	}
	
	// Check if identity is whitelisted
	isWhitelisted, err := registry.IsWhitelisted(identity)
	if err != nil {
		h.log.Error("Failed to check if identity is whitelisted", err, slog.String("identity", string(identity[:])))
		return nil, nil, nil, fmt.Errorf("whitelist check error: %w", err)
	}
	
	if !isWhitelisted {
		h.log.Warn("Identity not whitelisted", slog.String("identity", string(identity[:])))
		return nil, nil, nil, errors.New("identity not whitelisted")
	}

	// Get application private key for this contract
	appPrivkey, err := h.kms.GetAppPrivkey(contractAddress)
	if err != nil {
		h.log.Error("Failed to get app private key", err, slog.String("contractAddress", string(contractAddress[:])))
		return nil, nil, nil, fmt.Errorf("key retrieval error: %w", err)
	}

	// Sign the CSR to create TLS certificate
	tlsCert, err := h.kms.SignCSR(contractAddress, csr)
	if err != nil {
		h.log.Error("Failed to sign CSR", err, slog.String("contractAddress", string(contractAddress[:])))
		return nil, nil, nil, fmt.Errorf("certificate signing error: %w", err)
	}

	// Get config template hash for this identity
	configTemplateHash, err := registry.IdentityConfigMap(identity)
	if err != nil {
		h.log.Error("Failed to get config template hash", err, slog.String("identity", string(identity[:])))
		return nil, nil, nil, fmt.Errorf("config lookup error: %w", err)
	}
	
	if configTemplateHash == [32]byte{} {
		h.log.Error("No config template assigned to identity", slog.String("identity", string(identity[:])))
		return nil, nil, nil, errors.New("no config template assigned to identity")
	}

	// Get all storage backends from registry
	backendLocations, err := registry.AllStorageBackends()
	if err != nil {
		h.log.Error("Failed to get storage backends", err)
		return nil, nil, nil, fmt.Errorf("storage backend retrieval error: %w", err)
	}

	// Create a slice to hold all storage backends
	var storageBackends []interfaces.StorageBackend
	for _, location := range backendLocations {
		// Convert string to StorageBackendLocation since that's what the factory expects
		backend, err := h.storageFactory.StorageBackendFor(interfaces.StorageBackendLocation(location))
		if err != nil {
			h.log.Warn("Failed to create storage backend", err, slog.String("location", location))
			continue // Skip this backend if it fails
		}
		storageBackends = append(storageBackends, backend)
	}

	if len(storageBackends) == 0 {
		h.log.Error("No valid storage backends available")
		return nil, nil, nil, errors.New("no storage backends available")
	}

	// Convert []string to []StorageBackendLocation for CreateMultiBackend
	locationURIs := make([]interfaces.StorageBackendLocation, len(backendLocations))
	for i, loc := range backendLocations {
		locationURIs[i] = interfaces.StorageBackendLocation(loc)
	}
	
	// Create multi-storage backend
	multiStorage, err := h.storageFactory.CreateMultiBackend(locationURIs)
	if err != nil {
		h.log.Error("Failed to create multi-storage backend", err)
		return nil, nil, nil, fmt.Errorf("multi-storage creation error: %w", err)
	}

	// Fetch config template
	configTemplate, err := multiStorage.Fetch(ctx, configTemplateHash, interfaces.ConfigType)
	if err != nil {
		h.log.Error("Failed to fetch config template", err, slog.String("configHash", string(configTemplateHash[:])))
		return nil, nil, nil, fmt.Errorf("config template retrieval error: %w", err)
	}

	// Process the config template by resolving references to configs and secrets
	processedConfig, err := h.processConfigTemplate(ctx, multiStorage, configTemplate)
	if err != nil {
		h.log.Error("Failed to process config template", err)
		return nil, nil, nil, fmt.Errorf("config processing error: %w", err)
	}

	return appPrivkey, tlsCert, processedConfig, nil
}

// Reference holds a reference to a config or secret
type Reference struct {
	fullRef string
	hash    string
}

// findReferences finds all occurrences of a pattern in the template
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

// hexToHash converts a hex string to a [32]byte hash
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

// replaceReference replaces a reference with its content
func replaceReference(templateStr, oldStr, newStr string) string {
	return regexp.MustCompile(regexp.QuoteMeta(oldStr)).ReplaceAllString(templateStr, newStr)
}

// processConfigTemplate processes a config template by resolving all references
func (h *Handler) processConfigTemplate(ctx context.Context, storage interfaces.StorageBackend, configTemplate []byte) (interfaces.InstanceConfig, error) {
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
			h.log.Warn("Invalid config hash format", slog.String("hash", ref.hash))
			continue
		}

		configData, err := storage.Fetch(ctx, configHash, interfaces.ConfigType)
		if err != nil {
			h.log.Warn("Failed to fetch config", err, slog.String("hash", ref.hash))
			continue
		}

		// Replace the reference with the actual config
		templateStr = replaceReference(templateStr, ref.fullRef, string(configData))
	}

	// Process secret references - find all instances of "__SECRET_REF_<hash>"
	secretRefs, err := findReferences(templateStr, secretRefPrefix)
	if err != nil {
		return nil, fmt.Errorf("error finding secret references: %w", err)
	}

	// Replace each secret reference with actual content
	for _, ref := range secretRefs {
		secretHash, err := hexToHash(ref.hash)
		if err != nil {
			h.log.Warn("Invalid secret hash format", slog.String("hash", ref.hash))
			continue
		}

		secretData, err := storage.Fetch(ctx, secretHash, interfaces.SecretType)
		if err != nil {
			h.log.Warn("Failed to fetch secret", err, slog.String("hash", ref.hash))
			continue
		}

		// Replace the reference with the actual secret
		templateStr = replaceReference(templateStr, ref.fullRef, string(secretData))
	}

	return []byte(templateStr), nil
}
