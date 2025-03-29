package storage

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/ruteri/poc-tee-registry/interfaces"
)

// MultiStorageBackend implements a storage backend that aggregates multiple backends.
// It provides redundancy by attempting operations across all available backends.
type MultiStorageBackend struct {
	backends []interfaces.StorageBackend
	log      *slog.Logger
}

// NewMultiStorageBackend creates a storage backend that uses multiple underlying backends.
// For reads, it tries each backend until content is found.
// For writes, it attempts to store in all available backends.
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

// Fetch retrieves data by trying each backend sequentially until content is found.
// Returns an error if all backends fail to fetch the content.
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
            "err", err)
    }

    m.log.Error("All backends failed to fetch content",
        slog.String("content_id", contentIDStr),
        slog.Int("failed_backends", len(errs)),
        slog.Duration("duration", time.Since(start)))

    return nil, fmt.Errorf("all backends failed to fetch %s: %v", contentIDStr, errs)
}

// Store attempts to save data to all available backends, succeeding if at least one succeeds.
// Returns an error only if all backends fail to store the data.
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
                "err", err)
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

// Available returns true if any of the underlying backends is available.
func (m *MultiStorageBackend) Available(ctx context.Context) bool {
	for _, backend := range m.backends {
		if backend.Available(ctx) {
			return true
		}
	}
	return false
}

// Name returns the identifier for this aggregated storage backend.
func (m *MultiStorageBackend) Name() string {
	return "multi-storage"
}

// LocationURI returns a comma-separated list of all backend URIs in this multi-backend.
func (m *MultiStorageBackend) LocationURI() string {
	var locations []string
	for _, backend := range m.backends {
		locations = append(locations, backend.LocationURI())
	}
	
	return "multi:[" + strings.Join(locations, ",") + "]"
}
