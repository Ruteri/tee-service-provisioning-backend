package storage

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// GitHubBackend implements a read-only storage backend using GitHub's Git blob API.
// It directly uses ContentID bytes as the git blob SHA.
type GitHubBackend struct {
	owner       string
	repo        string
	client      *http.Client
	log         *slog.Logger
	locationURI string
}

// GitHubBlob represents a Git blob object from GitHub's API
type GitHubBlob struct {
	Content  string `json:"content"`
	Encoding string `json:"encoding"`
	URL      string `json:"url"`
	SHA      string `json:"sha"`
	Size     int    `json:"size"`
}

// NewGitHubBackend creates a new GitHub storage backend for reading from Git repositories.
func NewGitHubBackend(owner, repo string, log *slog.Logger) *GitHubBackend {
	return &GitHubBackend{
		owner:       owner,
		repo:        repo,
		client:      &http.Client{Timeout: 30 * time.Second},
		log:         log,
		locationURI: fmt.Sprintf("github://%s/%s", owner, repo),
	}
}

// Fetch retrieves data from GitHub by directly using the ContentID as a blob SHA.
func (b *GitHubBackend) Fetch(ctx context.Context, id interfaces.ContentID, contentType interfaces.ContentType) ([]byte, error) {
	// Convert the ContentID to a hex string to use as blob SHA
	blobSHA := hex.EncodeToString(id[:])

	// Fetch the blob directly
	blob, err := b.fetchBlob(ctx, blobSHA)
	if err != nil {
		return nil, err
	}

	// Decode the content
	if blob.Encoding != "base64" {
		return nil, fmt.Errorf("unexpected blob encoding: %s", blob.Encoding)
	}

	data, err := base64.StdEncoding.DecodeString(strings.ReplaceAll(blob.Content, "\n", ""))
	if err != nil {
		return nil, fmt.Errorf("failed to decode blob content: %w", err)
	}

	// Verify the content hash matches what we requested
	// (this step could be skipped if using git's hash directly)
	hash := sha256.Sum256(data)
	if hash != id {
		b.log.Warn("Content hash mismatch",
			slog.String("expected", hex.EncodeToString(id[:])),
			slog.String("actual", hex.EncodeToString(hash[:])))
		return nil, fmt.Errorf("content hash mismatch")
	}

	b.log.Debug("Fetched content from GitHub",
		slog.String("blobSHA", blobSHA),
		slog.Int("size", len(data)))

	return data, nil
}

// Store is not implemented for this read-only backend.
func (b *GitHubBackend) Store(ctx context.Context, data []byte, contentType interfaces.ContentType) (interfaces.ContentID, error) {
	// Calculate the ID for compatibility with the interface
	hash := sha256.Sum256(data)
	id := interfaces.ContentID(hash)

	return id, fmt.Errorf("GitHub backend is read-only")
}

// Available checks if the GitHub backend is accessible.
func (b *GitHubBackend) Available(ctx context.Context) bool {
	// Try to access the repository
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s", b.owner, b.repo)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		b.log.Debug("Failed to create request", "err", err)
		return false
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := b.client.Do(req)
	if err != nil {
		b.log.Debug("GitHub backend unavailable", "err", err)
		return false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		b.log.Debug("GitHub backend unavailable",
			slog.String("status", resp.Status))
		return false
	}

	return true
}

// Name returns a unique identifier for this storage backend.
func (b *GitHubBackend) Name() string {
	return fmt.Sprintf("github-%s-%s", b.owner, b.repo)
}

// LocationURI returns the URI that identifies this storage backend.
func (b *GitHubBackend) LocationURI() string {
	return b.locationURI
}

// fetchBlob fetches a Git blob directly by its SHA.
func (b *GitHubBackend) fetchBlob(ctx context.Context, sha string) (*GitHubBlob, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/%s/git/blobs/%s",
		b.owner, b.repo, sha)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Accept", "application/vnd.github.v3+json")

	resp, err := b.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, interfaces.ErrContentNotFound
	}

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("GitHub API error: %s, %s", resp.Status, string(body))
	}

	var blob GitHubBlob
	if err := json.NewDecoder(resp.Body).Decode(&blob); err != nil {
		return nil, fmt.Errorf("failed to decode blob: %w", err)
	}

	return &blob, nil
}
