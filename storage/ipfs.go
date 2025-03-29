package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	shell "github.com/ipfs/go-ipfs-api"
	"github.com/ruteri/poc-tee-registry/interfaces"
)

// IPFSBackend implements a storage backend using the InterPlanetary File System (IPFS).
// It can connect to either an IPFS node or a gateway.
type IPFSBackend struct {
	shell       *shell.Shell
	host        string
	port        string
	useGateway  bool
	prefixes    map[interfaces.ContentType]string
	log         *slog.Logger
	locationURI string
}

// NewIPFSBackend creates a new IPFS storage backend connected to the specified host and port.
// When useGateway is true, it uses the IPFS HTTP gateway instead of the IPFS API.
func NewIPFSBackend(host, port string, useGateway bool, timeout string, log *slog.Logger) (*IPFSBackend, error) {
	// Construct API URL
	apiURL := fmt.Sprintf("%s:%s", host, port)

	// Format the URI for tracking
	var uri string
	if useGateway {
		uri = fmt.Sprintf("ipfs://%s/?gateway=true&timeout=%s", apiURL, timeout)
	} else {
		uri = fmt.Sprintf("ipfs://%s/?timeout=%s", apiURL, timeout)
	}

	return &IPFSBackend{
		shell:       shell.NewShell(apiURL),
		host:        host,
		port:        port,
		useGateway:  useGateway,
		prefixes: map[interfaces.ContentType]string{
			interfaces.ConfigType: "config",
			interfaces.SecretType: "secret",
		},
		log:         log,
		locationURI: uri,
	}, nil
}

// Fetch retrieves data from IPFS by its content identifier and type.
// Returns ErrContentNotFound if the content doesn't exist or ErrBackendUnavailable
// if the IPFS node is not accessible.
func (b *IPFSBackend) Fetch(ctx context.Context, id interfaces.ContentID, contentType interfaces.ContentType) ([]byte, error) {
    start := time.Now()
    path := b.getIPFSPath(id, contentType)
    contentIDStr := fmt.Sprintf("%x", id[:8])

    // Check if the IPFS node is available
    if !b.shell.IsUp() {
        b.log.Warn("IPFS node unavailable",
            slog.String("host", b.host),
            slog.String("port", b.port))
        return nil, interfaces.ErrBackendUnavailable
    }

    // Fetch data from IPFS
    reader, err := b.shell.Cat(path)
    if err != nil {
        if strings.Contains(err.Error(), "no link named") {
            b.log.Debug("Content not found in IPFS",
                slog.String("path", path),
                slog.String("content_id", contentIDStr),
                slog.Duration("duration", time.Since(start)))
            return nil, interfaces.ErrContentNotFound
        }

        b.log.Error("Failed to fetch data from IPFS",
            slog.String("path", path),
            slog.String("content_id", contentIDStr),
            "err", err,
            slog.Duration("duration", time.Since(start)))
        return nil, fmt.Errorf("failed to fetch data from IPFS: %w", err)
    }
    defer reader.Close()

    // Read data
    data, err := io.ReadAll(reader)
    if err != nil {
        b.log.Error("Failed to read data from IPFS",
            slog.String("path", path),
            slog.String("content_id", contentIDStr),
            "err", err,
            slog.Duration("duration", time.Since(start)))
        return nil, fmt.Errorf("failed to read data from IPFS: %w", err)
    }

    b.log.Debug("Fetched content from IPFS",
        slog.String("path", path),
        slog.String("content_id", contentIDStr),
        slog.Int("size", len(data)),
        slog.Duration("duration", time.Since(start)))

    return data, nil
}

// Store adds data to IPFS and returns its content identifier.
// The identifier is the SHA-256 hash of the data.
// Returns ErrBackendUnavailable if the IPFS node is not accessible.
func (b *IPFSBackend) Store(ctx context.Context, data []byte, contentType interfaces.ContentType) (interfaces.ContentID, error) {
	// Generate content ID by hashing the data
	hash := sha256.Sum256(data)
	id := interfaces.ContentID(hash)

	// Check if the IPFS node is available
	if !b.shell.IsUp() {
		return id, interfaces.ErrBackendUnavailable
	}

	// Add data to IPFS
	cid, err := b.shell.Add(bytes.NewReader(data))
	if err != nil {
		return id, fmt.Errorf("failed to add data to IPFS: %w", err)
	}

	b.log.Debug("Stored content in IPFS",
		slog.String("ipfsCID", cid),
		slog.String("contentID", fmt.Sprintf("%x", id)),
		slog.String("contentType", fmt.Sprintf("%v", contentType)))

	return id, nil
}

// Available checks if the IPFS node is accessible.
func (b *IPFSBackend) Available(ctx context.Context) bool {
	return b.shell.IsUp()
}

// Name returns a unique identifier for this storage backend.
func (b *IPFSBackend) Name() string {
	return fmt.Sprintf("ipfs-%s-%s", b.host, b.port)
}

// LocationURI returns the URI that identifies this storage backend.
func (b *IPFSBackend) LocationURI() string {
	return b.locationURI
}

// getIPFSPath generates an IPFS path based on content ID and type.
func (b *IPFSBackend) getIPFSPath(id interfaces.ContentID, contentType interfaces.ContentType) string {
	prefix := b.prefixes[contentType]
	idStr := fmt.Sprintf("%x", id)
	return fmt.Sprintf("/ipfs/%s-%s", prefix, idStr)
}
