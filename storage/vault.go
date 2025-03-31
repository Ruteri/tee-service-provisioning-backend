package storage

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"
	"github.com/ruteri/poc-tee-registry/interfaces"
)

// VaultBackend implements a storage backend using HashiCorp Vault.
// It uses TLS client certificate authentication with certificates signed
// by the application's CA from the KMS.
type VaultBackend struct {
	client      *api.Client
	mountPath   string
	dataPath    string
	log         *slog.Logger
	locationURI string
}

// NewVaultBackend creates a new Vault storage backend with TLS client certificate authentication.
// The client certificate must be signed by the application CA for authentication.
//
// Parameters:
//   - address: Vault server address (e.g. https://vault.example.com:8200)
//   - mountPath: Vault mount path (e.g. "secret")
//   - dataPath: Path within the mount (e.g. "registry")
//   - clientCert: PEM-encoded TLS certificate signed by the application CA
//   - clientKey: PEM-encoded private key corresponding to the certificate
//   - log: Structured logger for operational insights
func NewVaultBackend(address, mountPath, dataPath string, clientCert tls.Certificate, log *slog.Logger) (*VaultBackend, error) {
	// Create TLS config
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{clientCert},
	}

	// Create HTTP transport with TLS config
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	// Create Vault config
	config := api.DefaultConfig()
	config.Address = address
	config.HttpClient = &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}

	// Create Vault client
	client, err := api.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Ensure paths are properly formatted
	mountPath = strings.TrimSuffix(mountPath, "/")
	dataPath = strings.TrimPrefix(dataPath, "/")
	dataPath = strings.TrimSuffix(dataPath, "/")

	return &VaultBackend{
		client:      client,
		mountPath:   mountPath,
		dataPath:    dataPath,
		log:         log,
		locationURI: fmt.Sprintf("vault://%s/%s/%s", address, mountPath, dataPath),
	}, nil
}

// Fetch retrieves data from Vault by its content identifier and type.
// It uses the KV v2 API which requires a specific path structure.
func (b *VaultBackend) Fetch(ctx context.Context, id interfaces.ContentID, contentType interfaces.ContentType) ([]byte, error) {
	start := time.Now()
	contentIDStr := hex.EncodeToString(id[:])

	// Construct path based on content type
	var typeStr string
	switch contentType {
	case interfaces.ConfigType:
		typeStr = "config"
	case interfaces.SecretType:
		typeStr = "secret"
	default:
		return nil, fmt.Errorf("unsupported content type: %v", contentType)
	}

	// Vault KV v2 path structure
	path := fmt.Sprintf("%s/data/%s/%s/%s", b.mountPath, b.dataPath, typeStr, contentIDStr)

	// Read from Vault
	secret, err := b.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		b.log.Error("Failed to read from Vault",
			slog.String("path", path),
			slog.String("content_id", contentIDStr),
			"err", err)
		return nil, fmt.Errorf("%w: %v", interfaces.ErrBackendUnavailable, err)
	}

	if secret == nil || secret.Data == nil {
		b.log.Debug("Content not found in Vault",
			slog.String("path", path),
			slog.String("content_id", contentIDStr))
		return nil, interfaces.ErrContentNotFound
	}

	// Extract data from the response (KV v2 format)
	data, ok := secret.Data["data"]
	if !ok {
		b.log.Error("Invalid data format in Vault response",
			slog.String("path", path),
			slog.String("content_id", contentIDStr))
		return nil, fmt.Errorf("invalid data format in Vault response")
	}

	// Extract content from the data map
	content, ok := data.(map[string]interface{})["content"]
	if !ok {
		b.log.Error("Content key not found in Vault data",
			slog.String("path", path),
			slog.String("content_id", contentIDStr))
		return nil, fmt.Errorf("content key not found in Vault data")
	}

	// Convert content to string and then to bytes
	contentStr, ok := content.(string)
	if !ok {
		b.log.Error("Invalid content format in Vault data",
			slog.String("path", path),
			slog.String("content_id", contentIDStr))
		return nil, fmt.Errorf("invalid content format in Vault data")
	}

	b.log.Info("Successfully fetched content from Vault",
		slog.String("content_id", contentIDStr),
		slog.Duration("duration", time.Since(start)))

	return []byte(contentStr), nil
}

// Store saves data to Vault and returns its content identifier.
// The content ID is the SHA-256 hash of the data.
func (b *VaultBackend) Store(ctx context.Context, data []byte, contentType interfaces.ContentType) (interfaces.ContentID, error) {
	start := time.Now()

	// Calculate content ID (SHA-256 hash)
	hash := sha256.Sum256(data)
	id := interfaces.ContentID(hash)
	contentIDStr := hex.EncodeToString(id[:])

	// Construct path based on content type
	var typeStr string
	switch contentType {
	case interfaces.ConfigType:
		typeStr = "config"
	case interfaces.SecretType:
		typeStr = "secret"
	default:
		return id, fmt.Errorf("unsupported content type: %v", contentType)
	}

	// Vault KV v2 path structure
	path := fmt.Sprintf("%s/data/%s/%s/%s", b.mountPath, b.dataPath, typeStr, contentIDStr)

	// Prepare data for Vault (KV v2 format)
	secretData := map[string]interface{}{
		"data": map[string]interface{}{
			"content": string(data),
		},
	}

	// Write to Vault
	_, err := b.client.Logical().WriteWithContext(ctx, path, secretData)
	if err != nil {
		b.log.Error("Failed to write to Vault",
			slog.String("path", path),
			slog.String("content_id", contentIDStr),
			"err", err)
		return id, fmt.Errorf("%w: %v", interfaces.ErrBackendUnavailable, err)
	}

	b.log.Info("Successfully stored content in Vault",
		slog.String("content_id", contentIDStr),
		slog.Duration("duration", time.Since(start)))

	return id, nil
}

// Available checks if the Vault backend is accessible.
// It uses the health endpoint to verify that Vault is initialized and unsealed.
func (b *VaultBackend) Available(ctx context.Context) bool {
	// Check if we can access the Vault server
	healthCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	health, err := b.client.Sys().HealthWithContext(healthCtx)
	if err != nil {
		b.log.Debug("Vault health check failed", "err", err)
		return false
	}

	// Check if Vault is initialized and unsealed
	if !health.Initialized || health.Sealed {
		b.log.Debug("Vault is not available",
			slog.Bool("initialized", health.Initialized),
			slog.Bool("sealed", health.Sealed))
		return false
	}

	return true
}

// Name returns a unique identifier for this storage backend.
func (b *VaultBackend) Name() string {
	return fmt.Sprintf("vault-%s-%s", b.mountPath, b.dataPath)
}

// LocationURI returns the URI that identifies this storage backend.
func (b *VaultBackend) LocationURI() string {
	return b.locationURI
}
