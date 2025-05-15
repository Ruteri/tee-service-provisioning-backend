package storage

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// OnchainBackend implements a storage backend using the Ethereum blockchain via a Registry contract.
type OnchainBackend struct {
	registry     interfaces.OnchainRegistry
	contractAddr interfaces.ContractAddress
	log          *slog.Logger
	locationURI  string
}

// NewOnchainBackend creates a new blockchain storage backend for a specific contract.
func NewOnchainBackend(registry interfaces.OnchainRegistry, contractAddr interfaces.ContractAddress, log *slog.Logger) *OnchainBackend {
	return &OnchainBackend{
		registry:     registry,
		contractAddr: contractAddr,
		log:          log,
		locationURI:  fmt.Sprintf("onchain://%x", contractAddr),
	}
}

// Fetch retrieves data from the blockchain by its content identifier and type.
func (b *OnchainBackend) Fetch(ctx context.Context, id interfaces.ContentID, contentType interfaces.ContentType) ([]byte, error) {
	data, err := b.registry.GetArtifact(id)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch data from chain: %w", err)
	}

	if len(data) == 0 {
		return nil, interfaces.ErrContentNotFound
	}

	b.log.Debug("Fetched content from blockchain",
		slog.String("contentID", fmt.Sprintf("%x", id)),
		slog.Int("size", len(data)))

	return data, nil
}

// Store saves data to the blockchain and returns its content identifier.
func (b *OnchainBackend) Store(ctx context.Context, data []byte, contentType interfaces.ContentType) (interfaces.ContentID, error) {
	id := interfaces.ComputeID(data)

	storedID, tx, err := b.registry.AddArtifact(data)
	if err != nil {
		return id, fmt.Errorf("failed to store data on chain: %w", err)
	}

	// Verify the ID matches what we calculated
	if storedID != id {
		b.log.Warn("Content ID mismatch",
			slog.String("expected", fmt.Sprintf("%x", id)),
			slog.String("actual", fmt.Sprintf("%x", storedID)))
	}

	b.log.Debug("Stored content on blockchain",
		slog.String("contentID", fmt.Sprintf("%x", id)),
		slog.String("txHash", tx.Hash().Hex()))

	return id, nil
}

// Available checks if the blockchain backend is accessible.
func (b *OnchainBackend) Available(ctx context.Context) bool {
	// Try to call a simple function to check availability
	backends, err := b.registry.StorageBackends()
	if err != nil {
		b.log.Debug("Blockchain backend unavailable", "err", err)
		return false
	}

	b.log.Debug("Blockchain backend available",
		slog.Int("connectedBackends", len(backends)))
	return true
}

// Name returns a unique identifier for this storage backend.
func (b *OnchainBackend) Name() string {
	return fmt.Sprintf("onchain-%s", b.contractAddr)
}

// LocationURI returns the URI that identifies this storage backend.
func (b *OnchainBackend) LocationURI() string {
	return b.locationURI
}
