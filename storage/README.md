# Storage Package

Simple content-addressed storage system with pluggable backends and URI-based configuration.

## Storage URI Format

Storage backends are identified using standard URI format:

```
[scheme]://[auth@]host[:port][/path][?params]
```

### Supported Backends

**IPFS**
```
ipfs://ipfs.example.com:5001/
ipfs://localhost:8080/?gateway=true&timeout=30s
```

**S3** (Public Buckets)
```
s3://bucket-name/prefix/
s3://bucket-name/path/?region=us-west-2&endpoint=custom.s3.com
```

**S3** (With Write Access)
```
s3://ACCESS_KEY:SECRET_KEY@bucket-name/path/
```

**File System**
```
file:///var/lib/registry/configs/
file://./relative/path/
```

## Content Addressing

Content is stored and retrieved using content addressing:

1. **Content ID Generation**: SHA-256 hash of the content
2. **Storage Path**: Determined by backend type and content type
3. **Types**: `ConfigType` and `SecretType` are stored in separate namespaces

## S3 Bucket Access

- **Reading**: S3 buckets are expected to be publicly readable
- **Writing**: API keys only required for pushing content to S3
- Objects are stored with `public-read` ACL by default

## MultiStorageBackend

The `MultiStorageBackend` aggregates multiple backends:

- **Store**: Attempts to store in all available backends
- **Fetch**: Tries each backend until content is found
- **Availability**: Backend is available if any sub-backend is available

## Security Notes

- S3 buckets should be configured for public read access
- Write credentials should be protected and not embedded in URIs
- Use IAM roles or environment variables for S3 credentials when possible
