package diskutil

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// LUKSTokenIDDiskLabel is the token ID used for storing disk labels in LUKS metadata.
const LUKSTokenIDDiskLabel = "1"

// DiskConfig contains configuration for encrypted disk operations.
type DiskConfig struct {
	DevicePath   string
	MountPoint   string
	MapperName   string
	MapperDevice string
}

// DiskLabel is a unique identifier for a disk used in key derivation.
type DiskLabel [8]byte

// String returns the disk label as a hex string.
func (d DiskLabel) String() string {
	return hex.EncodeToString(d[:])
}

// DiskLabelFromString creates a DiskLabel from a hex string.
func DiskLabelFromString(data string) (DiskLabel, error) {
	labelBytes, err := hex.DecodeString(data)
	if err != nil {
		return DiskLabel{}, err
	}
	if len(labelBytes) != 8 {
		return DiskLabel{}, errors.New("invalid disk label length")
	}

	var label DiskLabel
	copy(label[:], labelBytes)
	return label, nil
}

// RandomDiskLabel generates a random disk label.
func RandomDiskLabel() (DiskLabel, error) {
	var diskLabel DiskLabel
	_, err := rand.Read(diskLabel[:])
	if err != nil {
		return DiskLabel{}, err
	}
	return diskLabel, nil
}

// LUKSToken represents a LUKS token structure for metadata.
type LUKSToken struct {
	Type     string            `json:"type"`
	Keyslots []string          `json:"keyslots"`
	UserData map[string]string `json:"user_data"`
}

// DevicePathForGlob finds a device path matching the provided glob pattern.
func DevicePathForGlob(deviceGlob string) (string, error) {
	devices, err := filepath.Glob(deviceGlob)
	if err != nil {
		return "", err
	} else if len(devices) == 0 {
		return "", errors.New("no devices matched")
	}
	return devices[0], nil
}

// IsLUKS checks if a device is formatted with LUKS.
func IsLUKS(diskConfig DiskConfig) bool {
	cmd := exec.Command("cryptsetup", "isLuks", diskConfig.DevicePath)
	return cmd.Run() == nil
}

// SetupNewDisk formats and mounts a new encrypted disk.
func SetupNewDisk(diskConfig DiskConfig, passphrase string) error {
	// Format with LUKS2
	cmd := exec.Command("cryptsetup", "luksFormat", "--type", "luks2", "-q", diskConfig.DevicePath)
	cmd.Stdin = strings.NewReader(passphrase)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("could not format disk: %w", err)
	}

	// Open the LUKS container
	cmd = exec.Command("cryptsetup", "open", diskConfig.DevicePath, diskConfig.MapperName)
	cmd.Stdin = strings.NewReader(passphrase)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("could not open LUKS device: %w", err)
	}

	// Create ext4 filesystem
	if err := exec.Command("mkfs.ext4", diskConfig.MapperDevice).Run(); err != nil {
		exec.Command("cryptsetup", "close", diskConfig.MapperName).Run()
		return fmt.Errorf("could not create filesystem: %w", err)
	}

	// Mount the filesystem
	os.MkdirAll(diskConfig.MountPoint, 0755)
	if err := exec.Command("mount", diskConfig.MapperDevice, diskConfig.MountPoint).Run(); err != nil {
		exec.Command("cryptsetup", "close", diskConfig.MapperName).Run()
		return fmt.Errorf("could not mount filesystem: %w", err) // TODO: this could leak the passphrase.
	}

	return nil
}

// WriteMetadataToLUKS stores metadata as a LUKS token.
func WriteMetadataToLUKS(diskConfig DiskConfig, tokenID, data string) error {
	token := LUKSToken{
		Type:     "user",
		Keyslots: []string{},
		UserData: map[string]string{
			"metadata": string(data),
		},
	}

	tokenJSON, err := json.Marshal(token)
	if err != nil {
		return err
	}

	cmd := exec.Command("cryptsetup", "token", "import", "--token-id", tokenID, diskConfig.DevicePath)
	cmd.Stdin = strings.NewReader(string(tokenJSON))

	return cmd.Run()
}

// ReadMetadataFromLUKS retrieves metadata from a LUKS token.
func ReadMetadataFromLUKS(diskConfig DiskConfig, tokenID string) (string, error) {
	cmd := exec.Command("cryptsetup", "token", "export", "--token-id", tokenID, diskConfig.DevicePath)
	output, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("could not export LUKS token: %w", err)
	}

	var token LUKSToken
	if err := json.Unmarshal(output, &token); err != nil {
		return "", fmt.Errorf("could not unmarshal LUKS token: %w", err)
	}

	data, ok := token.UserData["metadata"]
	if !ok {
		return "", errors.New("luks token metadata is empty")
	}

	return data, nil
}

// MountExistingDisk mounts an already formatted LUKS-encrypted disk.
func MountExistingDisk(diskConfig DiskConfig, passphrase string) error {
	// Open the LUKS container
	cmd := exec.Command("cryptsetup", "open", diskConfig.DevicePath, diskConfig.MapperName)
	cmd.Stdin = strings.NewReader(passphrase)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("could not open LUKS device: %w", err)
	}

	// Mount the filesystem
	os.MkdirAll(diskConfig.MountPoint, 0755)
	if err := exec.Command("mount", diskConfig.MapperDevice, diskConfig.MountPoint).Run(); err != nil {
		exec.Command("cryptsetup", "close", diskConfig.MapperName).Run()
		return fmt.Errorf("could not mount filesystem: %w", err)
	}

	return nil
}

// IsMounted checks if a mountpoint is currently mounted.
func IsMounted(diskConfig DiskConfig) bool {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), " "+diskConfig.MountPoint+" ")
}

// CleanupMount unmounts and closes the encrypted device.
func CleanupMount(diskConfig DiskConfig) {
	exec.Command("umount", diskConfig.MountPoint).Run()
	exec.Command("cryptsetup", "close", diskConfig.MapperName).Run()
}

// DeriveDiskKeyFromPrivateKey derives a disk encryption key from application private key and disk label.
func DeriveDiskKeyFromPrivateKey(diskLabel DiskLabel, appPrivKey interfaces.AppPrivkey) (string, error) {
	return cryptoutils.DeriveDiskKey(diskLabel[:], []byte(appPrivKey))
}

// ProvisionNewDisk provisions a new disk with application credentials.
func ProvisionNewDisk(diskConfig DiskConfig, appPrivKey interfaces.AppPrivkey) (DiskLabel, error) {
	diskLabel, err := RandomDiskLabel()
	if err != nil {
		return DiskLabel{}, fmt.Errorf("could not generate random disk label: %w", err)
	}

	diskKey, err := DeriveDiskKeyFromPrivateKey(diskLabel, appPrivKey)
	if err != nil {
		return DiskLabel{}, fmt.Errorf("could not derive disk key: %w", err)
	}

	if err := SetupNewDisk(diskConfig, diskKey); err != nil {
		return DiskLabel{}, fmt.Errorf("disk setup failed: %w", err)
	}

	if err := WriteMetadataToLUKS(diskConfig, LUKSTokenIDDiskLabel, diskLabel.String()); err != nil {
		CleanupMount(diskConfig)
		return DiskLabel{}, fmt.Errorf("failed to write metadata to LUKS: %w", err)
	}

	return diskLabel, nil
}

// MountProvisionedDisk mounts a previously provisioned disk.
func MountProvisionedDisk(diskConfig DiskConfig, appPrivKey interfaces.AppPrivkey) (DiskLabel, error) {
	diskLabelString, err := ReadMetadataFromLUKS(diskConfig, LUKSTokenIDDiskLabel)
	if err != nil {
		return DiskLabel{}, fmt.Errorf("failed to read metadata from LUKS: %w", err)
	}

	diskLabel, err := DiskLabelFromString(diskLabelString)
	if err != nil {
		return DiskLabel{}, fmt.Errorf("failed to parse disk label: %w", err)
	}

	diskKey, err := DeriveDiskKeyFromPrivateKey(diskLabel, appPrivKey)
	if err != nil {
		return DiskLabel{}, fmt.Errorf("could not derive disk key: %w", err)
	}

	if err := MountExistingDisk(diskConfig, diskKey); err != nil {
		return DiskLabel{}, fmt.Errorf("disk mounting failed: %w", err)
	}

	return diskLabel, nil
}

// NewDiskConfig creates a new DiskConfig with default values for the mapper device.
func NewDiskConfig(devicePath, mountPoint, mapperName string) DiskConfig {
	mapperDevice := "/dev/mapper/" + mapperName
	return DiskConfig{
		DevicePath:   devicePath,
		MountPoint:   mountPoint,
		MapperName:   mapperName,
		MapperDevice: mapperDevice,
	}
}

// ProvisionOrMountDisk automatically provisions a new disk or mounts an existing one.
func ProvisionOrMountDisk(diskConfig DiskConfig, appPrivKey interfaces.AppPrivkey) (DiskLabel, bool, error) {
	if IsMounted(diskConfig) {
		return DiskLabel{}, false, errors.New("disk already mounted")
	}

	isLuks := IsLUKS(diskConfig)

	if isLuks {
		diskLabel, err := MountProvisionedDisk(diskConfig, appPrivKey)
		if err != nil {
			return DiskLabel{}, false, err
		}
		return diskLabel, false, nil
	} else {
		diskLabel, err := ProvisionNewDisk(diskConfig, appPrivKey)
		if err != nil {
			return DiskLabel{}, true, err
		}
		return diskLabel, true, nil
	}
}
