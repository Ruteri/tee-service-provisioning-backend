package storage

import (
	"context"
	"crypto/sha256"
	"fmt"
	"log/slog"
	"os" // Updated import
	"path/filepath"

	"github.com/ruteri/poc-tee-registry/interfaces"
)

// FileBackend implements interfaces.StorageBackend using the local file system
type FileBackend struct {
	baseDir     string
	prefixes    map[interfaces.ContentType]string
	log         *slog.Logger
	locationURI string
}

// NewFileBackend creates a new file storage backend
func NewFileBackend(baseDir string, log *slog.Logger) (*FileBackend, error) {
	// Ensure base directory exists
	if err := os.MkdirAll(baseDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create base directory: %w", err)
	}
	
	// Create subdirectories for different content types
	configDir := filepath.Join(baseDir, "configs")
	secretDir := filepath.Join(baseDir, "secrets")
	
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create configs directory: %w", err)
	}
	
	if err := os.MkdirAll(secretDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create secrets directory: %w", err)
	}
	
	// Format the URI for tracking
	uri := fmt.Sprintf("file://%s", baseDir)
	
	return &FileBackend{
		baseDir: baseDir,
		prefixes: map[interfaces.ContentType]string{
			interfaces.ConfigType: "configs",
			interfaces.SecretType: "secrets",
		},
		log:        log,
		locationURI: uri,
	}, nil
}

// Fetch retrieves data from the file system by its identifier and type
func (b *FileBackend) Fetch(ctx context.Context, id interfaces.ContentID, contentType interfaces.ContentType) ([]byte, error) {
	// Get file path
	filePath := b.getFilePath(id, contentType)
	
	// Check if file exists
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return nil, interfaces.ErrContentNotFound
	}
	
	// Read file content - UPDATED: use os.ReadFile instead of ioutil.ReadFile
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	
	b.log.Debug("Fetched content from file",
		slog.String("path", filePath),
		slog.Int("size", len(data)))
	
	return data, nil
}

// Store saves data to the file system and returns its identifier
func (b *FileBackend) Store(ctx context.Context, data []byte, contentType interfaces.ContentType) (interfaces.ContentID, error) {
	// Generate content ID by hashing the data
	hash := sha256.Sum256(data)
	id := interfaces.ContentID(hash)
	
	// Get file path
	filePath := b.getFilePath(id, contentType)
	
	// Create parent directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(filePath), 0755); err != nil {
		return id, fmt.Errorf("failed to create directory: %w", err)
	}
	
	// Write data to file - UPDATED: use os.WriteFile instead of ioutil.WriteFile
	if err := os.WriteFile(filePath, data, 0644); err != nil {
		return id, fmt.Errorf("failed to write file: %w", err)
	}
	
	b.log.Debug("Stored content in file",
		slog.String("path", filePath),
		slog.String("contentID", fmt.Sprintf("%x", id)))
	
	return id, nil
}

// Other methods remain unchanged
func (b *FileBackend) Available(ctx context.Context) bool {
	_, err := os.Stat(b.baseDir)
	if err != nil {
		b.log.Debug("File backend unavailable", "err", err)
		return false
	}
	return true
}

func (b *FileBackend) Name() string {
	return fmt.Sprintf("file-%s", filepath.Base(b.baseDir))
}

func (b *FileBackend) LocationURI() string {
	return b.locationURI
}

func (b *FileBackend) getFilePath(id interfaces.ContentID, contentType interfaces.ContentType) string {
	subdir := b.prefixes[contentType]
	idStr := fmt.Sprintf("%x", id)
	return filepath.Join(b.baseDir, subdir, idStr)
}
