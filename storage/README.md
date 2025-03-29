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

**On-Chain**
```
onchain://0x1234567890abcdef1234567890abcdef12345678
```

**GitHub** (Read-Only)
```
github://owner/repo
```

## Content Addressing

Content is stored and retrieved using content addressing:

1. **Content ID Generation**: SHA-256 hash of the content
2. **Storage Path**: Determined by backend type and content type
3. **Types**: `ConfigType` and `SecretType` are stored in separate namespaces

## On-Chain Storage

The on-chain backend stores content directly in the Registry smart contract:

- **Configurations**: Uses the `configs` mapping in the contract
- **Secrets**: Uses the `encryptedSecrets` mapping in the contract
- **Gas Cost**: Be mindful of gas costs when storing large content
- **Size Limits**: Subject to contract's `MAX_BYTES_SIZE` limit (20KB by default)

## GitHub Storage (Read-Only)

The GitHub backend fetches content from public repositories using Git's blob objects:

- **Direct Blob Access**: Uses ContentID directly as a Git blob SHA
- **Maximum Simplicity**: No trees, no searching - just direct blob retrieval
- **Perfect Git Integration**: Directly uses Git's content-addressed objects
- **Efficiency**: Single API call fetches content by its identifier

## MultiStorageBackend

The `MultiStorageBackend` aggregates multiple backends:

- **Store**: Attempts to store in all available backends
- **Fetch**: Tries each backend until content is found
- **Availability**: Backend is available if any sub-backend is available

## Security Notes

- **On-Chain Storage**: All data is public and visible on the blockchain
- **GitHub Blobs**: Create blob objects directly using `git hash-object -w <file>`
- **Size Considerations**: 
  - On-chain storage is expensive for large content
  - GitHub has file size limits (typically 100MB)
- **Token Protection**: Avoid embedding GitHub tokens in URI strings in production
