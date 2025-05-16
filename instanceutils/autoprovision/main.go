package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"slices"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/go-chi/chi/v5"
	"github.com/ruteri/tee-service-provisioning-backend/api/kmshandler"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/instanceutils/diskutil"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/ruteri/tee-service-provisioning-backend/kmsgovernance"
	"github.com/ruteri/tee-service-provisioning-backend/registry"
	"github.com/urfave/cli/v2"
)

var flagAppContract = &cli.StringFlag{
	Name:     "app-contract",
	Required: true,
	Usage:    "Application governance contract address to request provisioning for",
	EnvVars:  []string{"APP_CONTRACT"},
}
var flagKmsContract = &cli.StringFlag{
	Name:     "kms-contract",
	Required: true,
	Usage:    "KMS governance contract address to request provisioning for",
	EnvVars:  []string{"KMS_CONTRACT"},
}
var flagRpcAddr = &cli.StringFlag{
	Name:    "rpc-addr",
	Value:   "http://127.0.0.1:8085",
	Usage:   "RPC to connect to. Note that this should be a local node.",
	EnvVars: []string{"RPC_ADDR"},
}

var provisionerFlags []cli.Flag = []cli.Flag{
	flagAppContract, flagKmsContract, flagRpcAddr,
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
	&cli.StringFlag{
		Name:    "debug-set-attestation-type-header",
		Usage:   "If provided will set the attestation type header",
		EnvVars: []string{"DEBUG_SET_ATTESTATION_TYPE_HEADER"},
	},
	&cli.StringFlag{
		Name:    "debug-set-attestation-measurement-header",
		Usage:   "If provided will set the attestation measurement header",
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
	DiskConfig     diskutil.DiskConfig
	ConfigFilePath string
	TLSCertPath    string
	TLSKeyPath     string
	TLSCACertPath  string
	AppPrivkeyPath string

	OperatorSignatureConfig OperatorSignatureConfig

	KmsGovernance    interfaces.KMSGovernance
	SecretsProvider  *kmshandler.SecretsProvider
	RegistryContract interfaces.OnchainRegistry
}

type OperatorSignatureConfig struct {
	Enabled    bool
	ListenAddr string
}

func NewProvisioner(cCtx *cli.Context) (*Provisioner, error) {
	devicePath, err := diskutil.DevicePathForGlob(cCtx.String("device-glob"))
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

	appContract, err := interfaces.NewContractAddressFromHex(cCtx.String(flagAppContract.Name))
	if err != nil {
		return nil, err
	}

	rpcAddress := cCtx.String(flagRpcAddr.Name)
	ethClient, err := ethclient.Dial(rpcAddress)
	if err != nil {
		return nil, fmt.Errorf("failed to dial RPC: %w", err)
	}

	registryContract, err := registry.NewOnchainRegistryClient(ethClient, ethClient, common.Address(appContract))
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate registry client: %w", err)
	}

	secretsProvider := &*kmshandler.DefaultSecretsProvider
	secretsProvider.DebugAttestationTypeHeader = cCtx.String("debug-set-attestation-type-header")
	secretsProvider.DebugMeasurementsHeader = cCtx.String("debug-set-attestation-measurement-header")

	kmsContractAddr, err := interfaces.NewContractAddressFromHex(cCtx.String(flagKmsContract.Name))
	if err != nil {
		return nil, err
	}

	kmsGovernance, err := kmsgovernance.NewKmsGovernanceClient(ethClient, ethClient, common.Address(kmsContractAddr))
	if err != nil {
		return nil, fmt.Errorf("failed to instantiate kms governance contract: %w", err)
	}

	return &Provisioner{
		AppContract: appContract,
		DiskConfig: diskutil.DiskConfig{
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
		KmsGovernance:    kmsGovernance,
		SecretsProvider:  secretsProvider,
		RegistryContract: registryContract,
	}, nil
}

func (p *Provisioner) Do() error {
	if diskutil.IsMounted(p.DiskConfig) {
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

	kmsDomains, err := p.KmsGovernance.InstanceDomainNames()
	if err != nil {
		return fmt.Errorf("failed to resolve kms domains: %w", err)
	}

	if len(kmsDomains) == 0 {
		return fmt.Errorf("no kms domains, cannot bootstrap")
	}

	// TODO: try all of them
	kmsUrl := kmsDomains[0]

	tlskeyPem, csr, err := CreateCSR(tlskey, certificate_request)
	if err != nil {
		return fmt.Errorf("failed to create CSR: %w", err)
	}

	parsedResponse, err := p.SecretsProvider.AppSecrets(kmsUrl, p.AppContract, csr)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}

	// TODO: provide a utility function for verifying identity (reimplemented in a couple of places)
	secretsReportData := parsedResponse.ReportData(p.AppContract)
	measurements, err := cryptoutils.VerifyDCAPAttestation(secretsReportData, parsedResponse.Attestation)
	if err != nil {
		return fmt.Errorf("invalid kms attestation: %w", err)
	}

	kmsIdentity, err := interfaces.AttestationToIdentity(cryptoutils.DCAPAttestation, measurements, p.RegistryContract)
	if err != nil {
		return fmt.Errorf("could not fetch kms identity: %w", err)
	}

	kmsAllowed, err := p.RegistryContract.IdentityAllowed(kmsIdentity, parsedResponse.Operator)
	if err != nil {
		return fmt.Errorf("could not verify kms identity: %w", err)
	}
	if !kmsAllowed {
		return fmt.Errorf("kms identity not allowed")
	}

	if err = cryptoutils.VerifyCertificate(tlskeyPem, []byte(parsedResponse.TLSCert), CN.String()); err != nil {
		return fmt.Errorf("invalid certificate in registration response: %w", err)
	}

	// TODO: check app privkey against onchain pki

	// TODO: we should use MRCONFIGOWNER or equivalent for disk label
	// however, the actual guarantee with a random label is roughly
	// equivalent as both are enforced by the infrastructure operator

	_, _, err = diskutil.ProvisionOrMountDisk(p.DiskConfig, parsedResponse.AppPrivkey)
	if err != nil {
		return fmt.Errorf("could not provision disk: %w", err)
	}

	pki, err := p.RegistryContract.PKI()
	if err != nil {
		return fmt.Errorf("could not get app metadata: %w", err)
	}

	// TODO: verify pki attestation as well

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
		// {p.ConfigFilePath, []byte(""), 0600}, // TODO: resolve config as needed
		{p.TLSCertPath, []byte(parsedResponse.TLSCert), 0600},
		{p.AppPrivkeyPath, []byte(parsedResponse.AppPrivkey), 0600},
		{p.TLSKeyPath, tlskeyPem, 0600},
		{p.TLSCACertPath, pki.Ca, 0666},
	}

	for _, fw := range fileWrites {
		// TODO: we should force the perms as well as overwriting
		if err := os.WriteFile(fw.path, fw.content, fw.mode); err != nil {
			diskutil.CleanupMount(p.DiskConfig)
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
		Id:    cryptoutils.OIDOperatorSignature,
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
