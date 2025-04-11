package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

const LUKS_TOKEN_ID_CSR string = "1"

type DiskConfig struct {
	DevicePath   string
	MountPoint   string
	MapperName   string
	MapperDevice string
}

func devicePathForGlob(deviceGlob string) (string, error) {
	devices, err := filepath.Glob(deviceGlob)
	if err != nil {
		return "", err
	} else if len(devices) == 0 {
		return "", errors.New("no devices matched")
	}
	return devices[0], nil
}

type LUKSToken struct {
	Type     string            `json:"type"`
	Keyslots []string          `json:"keyslots"`
	UserData map[string]string `json:"user_data"`
}

func isLuks(diskConfig DiskConfig) bool {
	cmd := exec.Command("cryptsetup", "isLuks", diskConfig.DevicePath)
	return cmd.Run() == nil
}

func setupNewDisk(diskConfig DiskConfig, passphrase string) error {
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
		return fmt.Errorf("could not open LUKS device: %w", err) // TODO: this could leak the passphrase.
	}

	// Create ext4 filesystem
	if err := exec.Command("mkfs.ext4", diskConfig.MapperDevice).Run(); err != nil {
		exec.Command("cryptsetup", "close", diskConfig.MapperName).Run()
		return fmt.Errorf("could note create filesystem: %w", err)
	}

	// Mount the filesystem
	os.MkdirAll(diskConfig.MountPoint, 0755)
	if err := exec.Command("mount", diskConfig.MapperDevice, diskConfig.MountPoint).Run(); err != nil {
		exec.Command("cryptsetup", "close", diskConfig.MapperName).Run()
		return fmt.Errorf("could not mount filesystem: %w", err)
	}

	return nil
}

func writeMetadataToLUKS(diskConfig DiskConfig, tokenId, data string) error {
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

	cmd := exec.Command("cryptsetup", "token", "import", "--token-id", tokenId, diskConfig.DevicePath)
	cmd.Stdin = strings.NewReader(string(tokenJSON))

	if err := cmd.Run(); err != nil {
		return err
	}
	return nil
}

func readMetadataFromLUKS(diskConfig DiskConfig, tokenId string) (string, error) {
	cmd := exec.Command("cryptsetup", "token", "export", "--token-id", tokenId, diskConfig.DevicePath)
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

func mountExistingDisk(diskConfig DiskConfig, passphrase string) error {
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

func checkMounted(diskConfig DiskConfig) bool {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	return strings.Contains(string(data), " "+diskConfig.MountPoint+" ")
}

func cleanupMount(diskConfig DiskConfig) {
	exec.Command("umount", diskConfig.MountPoint).Run()
	exec.Command("cryptsetup", "close", diskConfig.MapperName).Run()
}
