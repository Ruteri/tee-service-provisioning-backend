package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/instanceutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/urfave/cli/v2"
)

var flags []cli.Flag = []cli.Flag{
	&cli.StringFlag{
		Name:  "provisioning-server-addr",
		Value: "http://127.0.0.1:8080",
		Usage: "Provisioning server address to request",
	},
	&cli.StringFlag{
		Name:     "app-contract",
		Required: true,
		Usage:    "Application governance contract address to request provisioning for. 40-char hex string with no 0x prefix",
	},
	&cli.StringFlag{
		Name:  "mount-point",
		Value: "/persistent",
		Usage: "path to mount (decrypted) persistent disk on",
	},
	&cli.StringFlag{
		Name:  "config-file",
		Usage: "path to store resolved config file at. Defaults to <mount point>/autoprovisioning/config",
	},
	&cli.StringFlag{
		Name:  "tls-cert-file",
		Usage: "path to store tls cert file at. Defaults to <mount point>/autoprovisioning/tls.cert",
	},
	&cli.StringFlag{
		Name:  "tls-key-file",
		Usage: "path to store tls key file at. Defaults to <mount point>/autoprovisioning/tls.key",
	},
	&cli.StringFlag{
		Name:  "app-privkey-file",
		Usage: "path to store app key (secrets deriviation) file at. Defaults to <mount point>/autoprovisioning/app.key",
	},
	&cli.StringFlag{
		Name:  "device-path",
		Value: "/persistent",
		Usage: "path to mount (decrypted) persistent disk on",
	},
	&cli.StringFlag{
		Name:  "device-glob",
		Value: "/dev/disk/by-path/*scsi-0:0:0:10",
		Usage: "Device glob pattern",
	},
	&cli.StringFlag{
		Name:  "mapper-name",
		Value: "cryptdisk",
		Usage: "Mapper name for encrypted persistent disk",
	},
	&cli.StringFlag{
		Name:  "mapper-device",
		Usage: "Mapper device to use. If unset defaults to '/dev/mapper/<mapper name>'",
	},
	&cli.StringFlag{
		Name:  "debug-set-attestation-type-header",
		Usage: "If provided the provisioner will set the attestation type header",
	},
	&cli.StringFlag{
		Name:  "debug-set-attestation-measurement-header",
		Usage: "If provided the provisioner will set the attestation measurement header",
	},
}

const usage string = `Instance auto-provisioning tool
Will exit once instance is fully provisioned:
* Encrypted disk is mounted
* TLS certificate and key are written to files
* App secrets derivation key is written to a file
* Configuration is resolved and written to a file`

func main() {
	app := &cli.App{
		Name:  "autoprovision",
		Usage: usage,
		Flags: flags,
		Action: func(cCtx *cli.Context) error {
			provisioner, err := NewProvisioner(cCtx)
			if err != nil {
				return err
			}

			return provisioner.Do()
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

type Provisioner struct {
	AppContract    interfaces.ContractAddress
	DiskConfig     DiskConfig
	ConfigFilePath string
	TLSCertPath    string
	TLSKeyPath     string
	AppPrivkeyPath string

	RegistrationProvider instanceutils.RegistrationProvider
}

func NewProvisioner(cCtx *cli.Context) (*Provisioner, error) {
	devicePath, err := devicePathForGlob(cCtx.String("device-glob"))
	if err != nil {
		return nil, fmt.Errorf("could not find device path: %w", err)
	}

	mapperDevice := cCtx.String("mapper-device")
	if mapperDevice == "" {
		mapperDevice = "/dev/mapper/" + cCtx.String("mapper-name")
	}

	mountPoint := cCtx.String("mount-point")
	configFile := cCtx.String("config-file")
	if configFile == "" {
		configFile = mountPoint + "/autoprovisioning/config"
	}

	tlsCertFile := cCtx.String("tls-cert-file")
	if tlsCertFile == "" {
		tlsCertFile = mountPoint + "/autoprovisioning/tls.cert"
	}

	tlsKeyFile := cCtx.String("tls-key-file")
	if tlsKeyFile == "" {
		tlsKeyFile = mountPoint + "/autoprovisioning/tls.key"
	}

	appKeyFile := cCtx.String("app-privkey-file")
	if appKeyFile == "" {
		appKeyFile = mountPoint + "/autoprovisioning/app.key"
	}

	var appContract interfaces.ContractAddress
	appContractBytes, err := hex.DecodeString(cCtx.String("app-contract"))
	if err != nil {
		return nil, fmt.Errorf("could not parse app contract address: %w", err)
	}
	if len(appContractBytes) != 20 {
		return nil, fmt.Errorf("app contract address has incorrect length %d (expected 20)", len(appContractBytes))
	}
	copy(appContract[:], appContractBytes)

	return &Provisioner{
		AppContract: appContract,
		DiskConfig: DiskConfig{
			DevicePath:   devicePath,
			MountPoint:   mountPoint,
			MapperName:   cCtx.String("mapper-name"),
			MapperDevice: mapperDevice,
		},
		ConfigFilePath: configFile,
		TLSCertPath:    tlsCertFile,
		TLSKeyPath:     tlsKeyFile,
		AppPrivkeyPath: appKeyFile,
		RegistrationProvider: &instanceutils.ProvisioningClient{
			ServerAddr:                cCtx.String("provisioning-server-addr"),
			SetAttestationType:        cCtx.String("debug-set-attestation-type-header"),
			SetAttestationMeasurement: cCtx.String("debug-set-attestation-measurement-header"),
		},
	}, nil
}

func (p *Provisioner) Do() error {
	if checkMounted(p.DiskConfig) {
		return errors.New("encrypted disk already mounted, refusing to continue")
	}

	CN := fmt.Sprintf("%x.app", p.AppContract)

	if !isLuks(p.DiskConfig) {
		// Brand new disk!
		tlskey, csr, err := cryptoutils.CreateCSRWithRandomKey(CN)
		if err != nil {
			return fmt.Errorf("could not create instance CSR: %w", err)
		}

		parsedResponse, err := p.RegistrationProvider.Register(p.AppContract, csr)
		if err != nil {
			return fmt.Errorf("registration failed: %w", err)
		}

		diskKey := cryptoutils.DeriveDiskKey(csr, []byte(parsedResponse.AppPrivkey))

		if err = cryptoutils.VerifyCertificate(tlskey, []byte(parsedResponse.TLSCert), CN); err != nil {
			return fmt.Errorf("invalid certificate in registration response: %w", err)
		}

		err = setupNewDisk(p.DiskConfig, diskKey)
		if err != nil {
			return fmt.Errorf("disk setup failed: %w", err)
		}

		// Create directory structure with proper permissions
		provisioningDir := filepath.Dir(p.ConfigFilePath)
		if err := os.MkdirAll(provisioningDir, 0700); err != nil {
			return fmt.Errorf("failed to create provisioning directory: %w", err)
		}

		err = writeMetadataToLUKS(p.DiskConfig, LUKS_TOKEN_ID_CSR, string(csr))
		if err != nil {
			cleanupMount(p.DiskConfig)
			return fmt.Errorf("failed to write metadata to LUKS: %w", err)
		}

		// Write files with error handling
		fileWrites := []struct {
			path    string
			content []byte
			mode    os.FileMode
		}{
			{p.ConfigFilePath, []byte(parsedResponse.Config), 0600},
			{p.TLSCertPath, []byte(parsedResponse.TLSCert), 0600},
			{p.AppPrivkeyPath, []byte(parsedResponse.AppPrivkey), 0600},
			{p.TLSKeyPath, tlskey, 0600},
		}

		for _, fw := range fileWrites {
			if err := os.WriteFile(fw.path, fw.content, fw.mode); err != nil {
				cleanupMount(p.DiskConfig)
				return fmt.Errorf("failed to write %s: %w", fw.path, err)
			}
		}
	} else {
		// Mounting already provisioned disk
		csrString, err := readMetadataFromLUKS(p.DiskConfig, LUKS_TOKEN_ID_CSR)
		if err != nil {
			return fmt.Errorf("failed to read metadata from LUKS: %w", err)
		}

		parsedResponse, err := p.RegistrationProvider.Register(p.AppContract, []byte(csrString))
		if err != nil {
			return fmt.Errorf("registration failed: %w", err)
		}

		diskKey := cryptoutils.DeriveDiskKey([]byte(csrString), []byte(parsedResponse.AppPrivkey))

		if err = mountExistingDisk(p.DiskConfig, diskKey); err != nil {
			return fmt.Errorf("disk mounting failed: %w", err)
		}

		// Make sure data on disk matches what we received
		appPrivkeyBytes, err := os.ReadFile(p.AppPrivkeyPath)
		if err != nil {
			return errors.New("misconfigured application: app privkey does not exist, refusing to continue")
		}
		if !bytes.Equal(appPrivkeyBytes, []byte(parsedResponse.AppPrivkey)) {
			return errors.New("misconfigured application: app privkey does not match, refusing to continue")
		}

		tlsKey, err := os.ReadFile(p.TLSKeyPath)
		if err != nil {
			return fmt.Errorf("could note read tls key for verification: %w, refusing to continue", err)
		}

		if err = cryptoutils.VerifyCertificate(tlsKey, []byte(parsedResponse.TLSCert), CN); err != nil {
			return fmt.Errorf("certificate verification failed: %w, refusing to continue", err)
		}

		if err = os.WriteFile(p.ConfigFilePath, []byte(parsedResponse.Config), 0600); err != nil {
			return fmt.Errorf("could not overwrite config file: %w", err)
		}
		if err = os.WriteFile(p.TLSCertPath, []byte(parsedResponse.TLSCert), 0600); err != nil {
			return fmt.Errorf("could not overwrite tls certificate: %w", err)
		}
	}

	return nil
}
