package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-chi/chi/v5"
	"github.com/ruteri/tee-service-provisioning-backend/api"
	"github.com/ruteri/tee-service-provisioning-backend/api/provisioner"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/instanceutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/ruteri/tee-service-provisioning-backend/kms"
	"github.com/urfave/cli/v2"
)

var provisionerFlags []cli.Flag = []cli.Flag{
	&cli.StringFlag{
		Name:    "provisioning-server-addr",
		Value:   "http://127.0.0.1:8080",
		Usage:   "Provisioning server address to request",
		EnvVars: []string{"PROVISIONING_SERVER_ADDR"},
	},
	&cli.StringFlag{
		Name:     "app-contract",
		Required: true,
		Usage:    "Application governance contract address to request provisioning for",
		EnvVars:  []string{"APP_CONTRACT"},
	},
}

var operatorFlags []cli.Flag = []cli.Flag{
	&cli.BoolFlag{
		Name:    "await-operator-signature",
		Usage:   "If set, script will pause and wait for operator to provide their signature over CSR",
		EnvVars: []string{"AWAIT_OPERATOR_SIGNATURE"},
	},
	&cli.StringFlag{
		Name:    "operator-signature-listen-addr",
		Value:   "http://127.0.0.1:8082",
		Usage:   "Listen address for signature",
		EnvVars: []string{"OPERATOR_SIGNATURE_LISTEN_ADDR"},
	},
}

var debugFlags []cli.Flag = []cli.Flag{
	&cli.BoolFlag{
		Name:    "debug-local-provider",
		Usage:   "If provided the provisioner will use a dummy provider instead of a remote one",
		EnvVars: []string{"DEBUG_LOCAL_PROVIDER"},
	},
	&cli.BoolFlag{
		Name:    "debug-local-kms-remote-attestaion-provider",
		Usage:   "Address to use for remote attestations (dummy dcap) with local kms",
		EnvVars: []string{"DEBUG_LOCAL_KMS_REMOTE_ATTESTATION_PROVIDER"},
	},
	&cli.StringFlag{
		Name:    "debug-set-attestation-type-header",
		Usage:   "If provided the provisioner will set the attestation type header",
		EnvVars: []string{"DEBUG_SET_ATTESTATION_TYPE_HEADER"},
	},
	&cli.StringFlag{
		Name:    "debug-set-attestation-measurement-header",
		Usage:   "If provided the provisioner will set the attestation measurement header",
		EnvVars: []string{"DEBUG_SET_ATTESTATION_MEASUREMENT_HEADER"},
	},
}

var diskFlags []cli.Flag = []cli.Flag{
	&cli.StringFlag{
		Name:    "mount-point",
		Value:   "/persistent",
		Usage:   "path to mount (decrypted) persistent disk on",
		EnvVars: []string{"MOUNT_POINT"},
	},
	&cli.StringFlag{
		Name:    "device-glob",
		Value:   "/dev/disk/by-path/*scsi-0:0:0:10",
		Usage:   "Device glob pattern",
		EnvVars: []string{"DEVICE_GLOB"},
	},
	&cli.StringFlag{
		Name:    "mapper-name",
		Value:   "cryptdisk",
		Usage:   "Mapper name for encrypted persistent disk",
		EnvVars: []string{"MAPPER_NAME"},
	},
	&cli.StringFlag{
		Name:    "mapper-device",
		Usage:   "Mapper device to use. If unset defaults to '/dev/mapper/<mapper name>'",
		EnvVars: []string{"MAPPER_DEVICE"},
	},
}

var filesFlags []cli.Flag = []cli.Flag{
	&cli.StringFlag{
		Name:    "config-file",
		Usage:   "path to store resolved config file at. Defaults to <mount point>/autoprovisioning/config",
		EnvVars: []string{"CONFIG_FILE"},
	},
	&cli.StringFlag{
		Name:    "tls-cert-file",
		Usage:   "path to store tls cert file at. Defaults to <mount point>/autoprovisioning/cert.pem",
		EnvVars: []string{"TLS_CERT_FILE"},
	},
	&cli.StringFlag{
		Name:    "tls-key-file",
		Usage:   "path to store tls key file at. Defaults to <mount point>/autoprovisioning/key.pem",
		EnvVars: []string{"TLS_KEY_FILE"},
	},
	&cli.StringFlag{
		Name:    "tls-cacert-file",
		Usage:   "path to store tls ca cert (application's CA cert) file at. Defaults to <mount point>/autoprovisioning/cacert.pem",
		EnvVars: []string{"TLS_CACERT_FILE"},
	},
	&cli.StringFlag{
		Name:    "app-privkey-file",
		Usage:   "path to store app key (secrets deriviation) file at. Defaults to <mount point>/autoprovisioning/app_privkey.pem",
		EnvVars: []string{"APP_PRIVKEY_FILE"},
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
		Flags: slices.Concat(provisionerFlags, operatorFlags, diskFlags, filesFlags, debugFlags),
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
	TLSCACertPath  string
	AppPrivkeyPath string

	OperatorSignatureConfig OperatorSignatureConfig

	RegistrationProvider api.RegistrationProvider
	MetadataProvider     api.MetadataProvider
}

type OperatorSignatureConfig struct {
	Enabled    bool
	ListenAddr string
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
		tlsCertFile = mountPoint + "/autoprovisioning/cert.pem"
	}

	tlsCACertFile := cCtx.String("tls-cert-file")
	if tlsCACertFile == "" {
		tlsCACertFile = mountPoint + "/autoprovisioning/cacert.pem"
	}

	tlsKeyFile := cCtx.String("tls-key-file")
	if tlsKeyFile == "" {
		tlsKeyFile = mountPoint + "/autoprovisioning/key.pem"
	}

	appKeyFile := cCtx.String("app-privkey-file")
	if appKeyFile == "" {
		appKeyFile = mountPoint + "/autoprovisioning/app_privkey.pem"
	}

	appContract, err := interfaces.NewContractAddressFromHex(cCtx.String("app-contract"))
	if err != nil {
		return nil, err
	}

	var registrationProvider api.RegistrationProvider
	var metadataProvider api.MetadataProvider
	if !cCtx.Bool("debug-local-provider") {
		provisioningClient := &provisioner.ProvisioningClient{
			ServerAddr:                cCtx.String("provisioning-server-addr"),
			SetAttestationType:        cCtx.String("debug-set-attestation-type-header"),
			SetAttestationMeasurement: cCtx.String("debug-set-attestation-measurement-header"),
		}
		registrationProvider = provisioningClient
		metadataProvider = provisioningClient
	} else {
		localKMS, err := kms.NewSimpleKMS(make([]byte, 32))
		if err != nil {
			return nil, fmt.Errorf("could not create a local kms: %w", err)
		}
		if cCtx.String("debug-local-kms-remote-attestaion-provider") != "" {
			localKMS = localKMS.WithAttestationProvider(&cryptoutils.RemoteAttestationProvider{Address: cCtx.String("debug-local-kms-remote-attestaion-provider")})
		}
		localProvider := &instanceutils.LocalKMSRegistrationProvider{KMS: localKMS}
		registrationProvider = localProvider
		metadataProvider = localProvider
	}

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
		TLSCACertPath:  tlsCACertFile,
		AppPrivkeyPath: appKeyFile,
		OperatorSignatureConfig: OperatorSignatureConfig{
			Enabled:    cCtx.Bool("await-operator-signature"),
			ListenAddr: cCtx.String("operator-signature-listen-addr"),
		},
		RegistrationProvider: registrationProvider,
		MetadataProvider:     metadataProvider,
	}, nil
}

type DiskLabel [8]byte

func (d DiskLabel) String() string {
	return hex.EncodeToString(d[:])
}

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

func RandomDiskLabel() (DiskLabel, error) {
	var diskLabel DiskLabel
	_, err := rand.Read(diskLabel[:])
	if err != nil {
		return DiskLabel{}, err
	}
	return diskLabel, nil
}

func (p *Provisioner) Do() error {
	if checkMounted(p.DiskConfig) {
		return errors.New("encrypted disk already mounted, refusing to continue")
	}

	CN := interfaces.NewAppCommonName(p.AppContract)
	tlskey, certificate_request, err := CreateCertificateRequest(CN.String())
	if err != nil {
		return fmt.Errorf("could not create instance certificate request: %w", err)
	}

	// TODO: fetch MROWNER, MROWNERCONFIG, MRCONFIGID if present.

	if p.OperatorSignatureConfig.Enabled {
		certificate_request, err = p.OperatorSignatureConfig.AwaitCRSignature(tlskey, certificate_request)
		if err != nil {
			return fmt.Errorf("error while waiting for operator signature: %w", err)
		}
	}

	tlskeyPem, csr, err := CreateCSR(tlskey, certificate_request)

	parsedResponse, err := p.RegistrationProvider.Register(p.AppContract, csr)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	if err = cryptoutils.VerifyCertificate(tlskeyPem, []byte(parsedResponse.TLSCert), CN.String()); err != nil {
		return fmt.Errorf("invalid certificate in registration response: %w", err)
	}

	// TODO: we should use MRCONFIGOWNER or equivalent for disk label
	// however, the actual guarantee with a random label is roughly
	// equivalent as both are enforced by the infrastructure operator

	if !isLuks(p.DiskConfig) {
		// Brand new disk!
		var err error
		diskLabel, err := RandomDiskLabel()
		if err != nil {
			return fmt.Errorf("could not generate a random disk id")
		}

		diskKey := cryptoutils.DeriveDiskKey(diskLabel[:], []byte(parsedResponse.AppPrivkey))

		err = setupNewDisk(p.DiskConfig, diskKey)
		if err != nil {
			return fmt.Errorf("disk setup failed: %w", err)
		}

		err = writeMetadataToLUKS(p.DiskConfig, LUKS_TOKEN_ID_DISK_LABEL, diskLabel.String())
		if err != nil {
			cleanupMount(p.DiskConfig)
			return fmt.Errorf("failed to write metadata to LUKS: %w", err)
		}
	} else {
		// Mounting already provisioned disk
		diskLabelString, err := readMetadataFromLUKS(p.DiskConfig, LUKS_TOKEN_ID_DISK_LABEL)
		if err != nil {
			return fmt.Errorf("failed to read metadata from LUKS: %w", err)
		}

		diskLabel, err := DiskLabelFromString(diskLabelString)
		if err != nil {
			return fmt.Errorf("failed to read disk label from LUKS: %w", err)
		}

		diskKey := cryptoutils.DeriveDiskKey(diskLabel[:], []byte(parsedResponse.AppPrivkey))

		if err = mountExistingDisk(p.DiskConfig, diskKey); err != nil {
			return fmt.Errorf("disk mounting failed: %w", err)
		}
	}

	pki, err := p.MetadataProvider.GetAppMetadata(p.AppContract)
	if err != nil {
		return fmt.Errorf("could not get app metadata: %w", err)
	}

	// Create directory structure with proper permissions
	provisioningDir := filepath.Dir(p.ConfigFilePath)
	if err := os.MkdirAll(provisioningDir, 0700); err != nil {
		return fmt.Errorf("failed to create provisioning directory: %w", err)
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
		{p.TLSKeyPath, tlskeyPem, 0600},
		{p.TLSCACertPath, pki.CACert, 0666},
	}

	for _, fw := range fileWrites {
		// TODO: we should force the perms as well as overwriting
		if err := os.WriteFile(fw.path, fw.content, fw.mode); err != nil {
			cleanupMount(p.DiskConfig)
			return fmt.Errorf("failed to write %s: %w", fw.path, err)
		}
	}

	return nil
}

func (c *OperatorSignatureConfig) AwaitCRSignature(privateKey *ecdsa.PrivateKey, cr *x509.CertificateRequest) (*x509.CertificateRequest, error) {
	pubkeyDer, err := x509.MarshalPKIXPublicKey(privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	crPubkeyHash := cryptoutils.DERPubkeyHash(pubkeyDer)

	sigCh := make(chan []byte, 1)

	mux := chi.NewRouter()
	mux.Get("/instance_pubkey", func(w http.ResponseWriter, r *http.Request) {
		w.Write(crPubkeyHash)
	})
	mux.Post("/pubkey_signature", func(w http.ResponseWriter, r *http.Request) {
		sig, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Errorf("could not read request body: %w", err).Error(), 500)
			return
		}
		_, err = crypto.Ecrecover(crPubkeyHash, sig)
		if err != nil {
			http.Error(w, fmt.Errorf("could not recover signature: %w", err).Error(), 400)
			return
		}
		sigCh <- sig
	})

	s := http.Server{
		Addr:    c.ListenAddr,
		Handler: mux,
	}

	cert, err := cryptoutils.RandomCert()
	if err != nil {
		log.Fatalf("could not generate random tls cert: %s", err.Error())
	}

	s.TLSConfig = &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	go s.ListenAndServeTLS("", "")

	sig := <-sigCh

	// Recreate and resign the CSR
	crCopy := *cr
	crCopy.ExtraExtensions = []pkix.Extension{{
		Id:    api.OIDOperatorSignature,
		Value: sig,
	}}
	return &crCopy, nil
}

func CreateCertificateRequest(cn string) (*ecdsa.PrivateKey, *x509.CertificateRequest, error) {
	// Generate a new ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Create a CSR template
	cr := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	return privateKey, cr, nil
}

func CreateCSR(privateKey *ecdsa.PrivateKey, cr *x509.CertificateRequest) ([]byte, interfaces.TLSCSR, error) {
	// Create a CSR using the private key and template
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, cr, privateKey)
	if err != nil {
		return nil, nil, err
	}

	// Encode the CSR in PEM format
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyBytes})
	return keyPEM, interfaces.TLSCSR(csrPEM), nil
}
