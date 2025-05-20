package configresolver

import (
	"context"
	"encoding/hex"
	"fmt"
	"log/slog"
	"regexp"

	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// ResolveConfiguration uses provided data availability backends to resolve the configuration
// pointed to by the config governance contract, and decrypts any secrets using the
// provided app private key.
//
// This implementation retrieves storage backend locations from the governance contract,
// fetches the configuration template, and processes it by resolving all references and
// decrypting encrypted secrets.
//
// Parameters:
//   - ctx: Context for storage operations
//   - log: Structured logger for operational insights
//   - configGovernance: Contract providing storage backend locations
//   - storageFactory: Factory for creating storage backends
//   - configTemplateHash: Content hash of the configuration template to fetch
//   - appPrivkey: Application private key for decrypting secret references
//
// Returns:
//   - Fully resolved instance configuration with all references processed
//   - Error if storage access, template retrieval, or reference processing fails
func ResolveConfiguration(ctx context.Context, log *slog.Logger, configGovernance interfaces.ConfigGovernance, storageFactory interfaces.StorageBackendFactory, configTemplateHash [32]byte, appPrivkey interfaces.AppPrivkey) (interfaces.InstanceConfig, error) {
	// Get all storage backends from registry
	backendLocations, err := configGovernance.StorageBackends()
	if err != nil {
		return nil, fmt.Errorf("storage backend retrieval error: %w", err)
	}

	// Convert []string to []StorageBackendLocation for CreateMultiBackend
	locationURIs := make([]interfaces.StorageBackendLocation, len(backendLocations))
	for i, loc := range backendLocations {
		locationURI, err := interfaces.NewStorageBackendLocation(loc)
		if err != nil {
			log.Debug("invalid location uri, ignoring", "err", err)
		} else {
			locationURIs[i] = locationURI
		}
	}

	// Create multi-storage backend
	multiStorage, err := storageFactory.CreateMultiBackend(locationURIs)
	if err != nil {
		log.Error("Failed to create multi-storage backend", "err", err)
		return nil, fmt.Errorf("multi-storage creation error: %w", err)
	}

	// Fetch config template
	configTemplate, err := multiStorage.Fetch(ctx, configTemplateHash, interfaces.ConfigType)
	if err != nil {
		return nil, fmt.Errorf("config template retrieval error: %w", err)
	}

	// Process the config template - pass the app private key for decryption
	processedConfig, err := processConfigTemplate(ctx, log, multiStorage, configTemplate, appPrivkey)
	if err != nil {
		log.Error("Failed to process config template", "err", err)
		return nil, fmt.Errorf("config processing error: %w", err)
	}

	return processedConfig, nil
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
func processConfigTemplate(ctx context.Context, log *slog.Logger, storage interfaces.StorageBackend, configTemplate []byte, appPrivKey interfaces.AppPrivkey) (interfaces.InstanceConfig, error) {
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
			log.Error("Invalid config hash format", slog.String("hash", ref.hash), "err", err)
			return nil, fmt.Errorf("invalid config hash format %s: %w", ref.hash, err)
		}

		configData, err := storage.Fetch(ctx, configHash, interfaces.ConfigType)
		if err != nil {
			log.Error("Failed to fetch config", "err", err, slog.String("hash", ref.hash))
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
			log.Error("Invalid secret hash format", slog.String("hash", ref.hash), "err", err)
			return nil, fmt.Errorf("invalid secret hash format %s: %w", ref.hash, err)
		}

		// Fetch the pre-encrypted secret
		encryptedSecretData, err := storage.Fetch(ctx, secretHash, interfaces.SecretType)
		if err != nil {
			log.Error("Failed to fetch secret", "err", err, slog.String("hash", ref.hash))
			return nil, fmt.Errorf("failed to fetch secret %s: %w", ref.hash, err)
		}

		// Decrypt the secret with the app's private key
		decryptedData, err := cryptoutils.DecryptWithPrivateKey(appPrivKey, encryptedSecretData)
		if err != nil {
			log.Error("Failed to decrypt secret", "err", err, slog.String("hash", ref.hash))
			return nil, fmt.Errorf("failed to decrypt secret %s: %w", ref.hash, err)
		}

		// Note: might need escaping
		templateStr = replaceReference(templateStr, ref.fullRef, string(decryptedData))
	}

	return []byte(templateStr), nil
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
