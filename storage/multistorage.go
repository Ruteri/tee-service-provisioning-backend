package storage

import (
	"context"
	"fmt"
	"log/slog"
	"strings" // Added missing import
	"time"

	"github.com/ruteri/poc-tee-registry/interfaces"
)

// MultiStorageBackend implements interfaces.StorageBackend using multiple backends with fallback
type MultiStorageBackend struct {
	backends []interfaces.StorageBackend
	log      *slog.Logger
}

// NewMultiStorageBackend creates a new multi-storage backend with fallback
func NewMultiStorageBackend(backends []interfaces.StorageBackend, logger *slog.Logger) *MultiStorageBackend {
	// If no logger is provided, create a default one
	if logger == nil {
		logger = slog.Default()
	}
	
	return &MultiStorageBackend{
		backends: backends,
		log:      logger,
	}
}

func (m *MultiStorageBackend) Fetch(ctx context.Context, id interfaces.ContentID, contentType interfaces.ContentType) ([]byte, error) {
    start := time.Now()
    var errs []error
    contentIDStr := fmt.Sprintf("%x", id[:8])

    for _, backend := range m.backends {
        if !backend.Available(ctx) {
            m.log.Debug("Backend unavailable",
                slog.String("backend_name", backend.Name()),
                slog.String("content_id", contentIDStr))
            continue
        }

        data, err := backend.Fetch(ctx, id, contentType)
        if err == nil {
            m.log.Info("Successfully fetched content",
                slog.String("backend_name", backend.Name()),
                slog.String("content_id", contentIDStr),
                slog.Duration("duration", time.Since(start)))
            return data, nil
        }

        errs = append(errs, fmt.Errorf("%s: %w", backend.Name(), err))
        m.log.Debug("Failed to fetch from backend",
            slog.String("backend_name", backend.Name()),
            slog.String("content_id", contentIDStr),
            err)
    }

    m.log.Error("All backends failed to fetch content",
        slog.String("content_id", contentIDStr),
        slog.Int("failed_backends", len(errs)),
        slog.Duration("duration", time.Since(start)))

    return nil, fmt.Errorf("all backends failed to fetch %s: %v", contentIDStr, errs)
}

// Store saves data to all available backends
func (m *MultiStorageBackend) Store(ctx context.Context, data []byte, contentType interfaces.ContentType) (interfaces.ContentID, error) {
    start := time.Now()
    var result [32]byte
    var success bool
    var errs []error

    for _, backend := range m.backends {
        if !backend.Available(ctx) {
            m.log.Debug("Backend unavailable", slog.String("backend_name", backend.Name()))
            continue
        }

        id, err := backend.Store(ctx, data, contentType)
        if err == nil {
            contentIDStr := fmt.Sprintf("%x", id)
            if !success {
                result = id
                success = true
                m.log.Info("Successfully stored content",
                    slog.String("backend_name", backend.Name()),
                    slog.String("content_id", contentIDStr),
                    slog.Duration("duration", time.Since(start)))
            } else if result != id {
                // This should not happen - same data should produce same hash
                m.log.Warn("Inconsistent hashes from backends",
                    slog.String("backend_name", backend.Name()),
                    slog.String("expected_id", fmt.Sprintf("%x", result[:])),
                    slog.String("actual_id", fmt.Sprintf("%x", id[:])))
            }
        } else {
            errs = append(errs, fmt.Errorf("%s: %w", backend.Name(), err))
            m.log.Debug("Failed to store to backend",
                slog.String("backend_name", backend.Name()),
                err)
        }
    }

    if !success {
        m.log.Error("All backends failed to store data",
            slog.Int("failed_backends", len(errs)),
            slog.Duration("duration", time.Since(start)))
        return result, fmt.Errorf("all backends failed to store data: %v", errs)
    }

    return result, nil
}

// Available checks if any backend is available
func (m *MultiStorageBackend) Available(ctx context.Context) bool {
	for _, backend := range m.backends {
		if backend.Available(ctx) {
			return true
		}
	}
	return false
}

// Name returns the name of this backend
func (m *MultiStorageBackend) Name() string {
	return "multi-storage"
}

// LocationURI returns the URI of this backend
// ADDED: to complete the interface implementation
func (m *MultiStorageBackend) LocationURI() string {
	// Build a combined location URI from all backends
	var locations []string
	for _, backend := range m.backends {
		locations = append(locations, backend.LocationURI())
	}
	
	return "multi:[" + strings.Join(locations, ",") + "]"
}
