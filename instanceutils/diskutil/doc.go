// Package diskutil provides utilities for managing encrypted persistent storage in TEE environments.
//
// This package enables secure disk management with LUKS encryption for Trusted
// Execution Environment instances. It supports deriving encryption keys from
// application credentials, provisioning new disks, and mounting existing encrypted
// volumes.
//
// Main features:
//   - LUKS2 encrypted volume management
//   - Secure key derivation from application private keys
//   - Metadata storage in LUKS tokens
//   - Support for both new disk provisioning and remounting
//
// Basic usage:
//
//	// Create disk configuration
//	diskConfig := diskutil.NewDiskConfig("/dev/sda", "/persistent", "cryptdisk")
//
//	// Provision new disk or mount existing one
//	diskLabel, isNew, err := diskutil.ProvisionOrMountDisk(diskConfig, appPrivKey)
//	if err != nil {
//		log.Fatalf("Failed to provision/mount disk: %v", err)
//	}
//
//	// Work with mounted disk at diskConfig.MountPoint
//	// ...
//
//	// Clean up when done
//	diskutil.CleanupMount(diskConfig)
package diskutil
