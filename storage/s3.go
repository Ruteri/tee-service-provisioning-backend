package storage

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"path"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// S3Backend implements a storage backend using Amazon S3 or compatible services.
// It supports both public read-only access and authenticated write access.
type S3Backend struct {
	client         *s3.S3
	writeClient    *s3.S3
	bucketName     string
	prefix         string
	log            *slog.Logger
	locationURI    string
	hasWriteAccess bool
}

// NewS3Backend creates a new S3 storage backend.
// If accessKey and secretKey are provided, the backend will have write access.
// Otherwise, it will be read-only for publicly accessible objects.
func NewS3Backend(bucketName, prefix, region, endpoint, accessKey, secretKey string, log *slog.Logger) (*S3Backend, error) {
	// Format the URI for tracking
	uri := fmt.Sprintf("s3://%s/%s?region=%s", bucketName, prefix, region)
	if endpoint != "" {
		uri += fmt.Sprintf("&endpoint=%s", endpoint)
	}
	if accessKey != "" {
		uri = fmt.Sprintf("s3://%s:***@%s/%s?region=%s", accessKey, bucketName, prefix, region)
		if endpoint != "" {
			uri += fmt.Sprintf("&endpoint=%s", endpoint)
		}
	}

	// Configure base AWS SDK for read-only public access
	baseCfg := aws.Config{
		Region: aws.String(region),
	}

	if endpoint != "" {
		baseCfg.Endpoint = aws.String(endpoint)
	}

	// Create AWS session for read operations (no credentials required for public buckets)
	baseSess, err := session.NewSession(&baseCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS session: %w", err)
	}

	// Create read-only S3 client
	readClient := s3.New(baseSess)

	// Check if we have write credentials
	hasWriteAccess := accessKey != "" && secretKey != ""
	var writeClient *s3.S3

	if hasWriteAccess {
		// Configure AWS SDK with credentials for write access
		writeCfg := baseCfg.Copy()
		writeCfg.Credentials = credentials.NewStaticCredentials(accessKey, secretKey, "")

		// Create AWS session for write operations
		writeSess, err := session.NewSession(writeCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create AWS write session: %w", err)
		}

		// Create write-enabled S3 client
		writeClient = s3.New(writeSess)
	} else {
		// No write credentials provided, use the read client for both
		// This may work for public writable buckets (not recommended for production)
		writeClient = readClient
		log.Warn("No S3 credentials provided - write operations may fail unless bucket is public writable")
	}

	return &S3Backend{
		client:      readClient,
		writeClient: writeClient,
		bucketName:  bucketName,
		prefix:      strings.TrimSuffix(prefix, "/"),
		log:            log,
		locationURI:    uri,
		hasWriteAccess: hasWriteAccess,
	}, nil
}

// Fetch retrieves an object from S3 by its content identifier and type.
// Returns ErrContentNotFound if the object doesn't exist.
func (b *S3Backend) Fetch(ctx context.Context, id interfaces.ContentID, contentType interfaces.ContentType) ([]byte, error) {
	start := time.Now()
	key := b.getObjectKey(id, contentType)
	contentIDStr := fmt.Sprintf("%x", id[:8])

	// Get object from S3
	result, err := b.client.GetObjectWithContext(ctx, &s3.GetObjectInput{
		Bucket: aws.String(b.bucketName),
		Key:    aws.String(key),
	})

	if err != nil {
		if strings.Contains(err.Error(), "NoSuchKey") || strings.Contains(err.Error(), "404") {
			b.log.Debug("Content not found in S3",
				slog.String("content_id", contentIDStr),
				slog.String("bucket", b.bucketName),
				slog.String("key", key),
				slog.Duration("duration", time.Since(start)))
			return nil, interfaces.ErrContentNotFound
		}

		b.log.Error("Failed to get object from S3",
			slog.String("content_id", contentIDStr),
			slog.String("bucket", b.bucketName),
			slog.String("key", key),
			"err", err,
			slog.Duration("duration", time.Since(start)))
		return nil, fmt.Errorf("failed to get object from S3: %w", err)
	}
	defer result.Body.Close()

	// Read object body
	data, err := io.ReadAll(result.Body)
	if err != nil {
		b.log.Error("Failed to read object body",
			slog.String("content_id", contentIDStr),
			slog.String("bucket", b.bucketName),
			slog.String("key", key),
			"err", err,
			slog.Duration("duration", time.Since(start)))
		return nil, fmt.Errorf("failed to read object body: %w", err)
	}

	b.log.Debug("Fetched content from S3",
		slog.String("content_id", contentIDStr),
		slog.String("bucket", b.bucketName),
		slog.String("key", key),
		slog.Int("size", len(data)),
		slog.Duration("duration", time.Since(start)))

	return data, nil
}

// Store saves data to S3 and returns its content identifier.
// The identifier is the SHA-256 hash of the data.
// Objects are stored with public-read ACL by default.
func (b *S3Backend) Store(ctx context.Context, data []byte, contentType interfaces.ContentType) (interfaces.ContentID, error) {
	// Generate content ID by hashing the data
	hash := sha256.Sum256(data)
	id := interfaces.ContentID(hash)

	// Get object key
	key := b.getObjectKey(id, contentType)

	// Upload object to S3 using the write client
	_, err := b.writeClient.PutObjectWithContext(ctx, &s3.PutObjectInput{
		Bucket: aws.String(b.bucketName),
		Key:    aws.String(key),
		Body:   bytes.NewReader(data),
		ACL:    aws.String("public-read"), // Make object publicly readable
	})
	if err != nil {
		if !b.hasWriteAccess {
			return id, fmt.Errorf("failed to upload object to S3 (no write credentials provided): %w", err)
		}
		return id, fmt.Errorf("failed to upload object to S3: %w", err)
	}

	b.log.Debug("Stored content in S3",
		slog.String("bucket", b.bucketName),
		slog.String("key", key),
		slog.String("contentID", fmt.Sprintf("%x", id)))

	return id, nil
}

// Available checks if the S3 backend is accessible by attempting to head the bucket.
func (b *S3Backend) Available(ctx context.Context) bool {
	start := time.Now()

	// Try to head the bucket to check if it's accessible
	_, err := b.client.HeadBucketWithContext(ctx, &s3.HeadBucketInput{
		Bucket: aws.String(b.bucketName),
	})

	if err != nil {
		b.log.Warn("S3 backend unavailable",
			slog.String("bucket", b.bucketName),
			"err", err,
			slog.Duration("duration", time.Since(start)))
		return false
	}

	return true
}

// Name returns a unique identifier for this storage backend.
func (b *S3Backend) Name() string {
	return fmt.Sprintf("s3-%s", b.bucketName)
}

// LocationURI returns the URI that identifies this storage backend.
func (b *S3Backend) LocationURI() string {
	return b.locationURI
}

// getObjectKey generates an S3 object key based on content ID and type.
func (b *S3Backend) getObjectKey(id interfaces.ContentID, contentType interfaces.ContentType) string {
	idStr := fmt.Sprintf("%x", id)

	if b.prefix == "" {
		return idStr
	}

	return path.Join(b.prefix, idStr)
}
