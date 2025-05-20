package kms

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"math/big"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// SimpleKMS provides a deterministic key management implementation.
// It derives keys from a master key, suitable for development and testing.
type SimpleKMS struct {
	masterKey []byte
	mu        sync.RWMutex

	attestationProvider cryptoutils.AttestationProvider
	operator            interfaces.ContractAddress
}

// NewSimpleKMS creates a new instance with the provided master key.
// The master key must be at least 32 bytes long.
func NewSimpleKMS(masterKey []byte) (*SimpleKMS, error) {
	if len(masterKey) < 32 {
		return nil, errors.New("master key must be at least 32 bytes")
	}

	return &SimpleKMS{masterKey: masterKey, attestationProvider: &cryptoutils.DumyAttestationProvider{}}, nil
}

// OnboardRequestHash computes the hash of an onboard request.
// Used for request validation and identification.
func OnboardRequestHash(onboardRequest interfaces.OnboardRequest) ([32]byte, error) {
	intTy, _ := abi.NewType("int", "", nil)
	bytesTy, _ := abi.NewType("bytes", "", nil)
	addressTy, _ := abi.NewType("address", "", nil)

	arguments := abi.Arguments{
		{Type: bytesTy},
		{Type: intTy},
		{Type: addressTy},
		{Type: bytesTy},
	}

	packed, err := arguments.Pack(onboardRequest.Pubkey, onboardRequest.Nonce, onboardRequest.Operator, onboardRequest.Attestation)
	if err != nil {
		return [32]byte{}, err
	}
	return crypto.Keccak256Hash(packed), nil
}

// OnboardRequestReportData generates expected attestation report data
// for an onboard request verification.
func OnboardRequestReportData(kmsAddress interfaces.ContractAddress, onboardRequest interfaces.OnboardRequest) [64]byte {
	var onboardReportData [64]byte
	onboardRequestSerialized := onboardRequest.Pubkey
	onboardRequestSerialized = append(onboardRequestSerialized, onboardRequest.Nonce.Bytes()...)
	onboardRequestSerialized = append(onboardRequestSerialized, onboardRequest.Operator.Bytes()...)

	operatorRequestHash := sha256.Sum256(onboardRequestSerialized)
	copy(onboardReportData[:20], kmsAddress[:])
	copy(onboardReportData[20:], operatorRequestHash[:])

	return onboardReportData
}

// RequestOnboard creates a new onboard request for TEE registration.
// Includes nonce generation and attestation of the request.
func (k *SimpleKMS) RequestOnboard(kmsAddress interfaces.ContractAddress, operator interfaces.ContractAddress, pubkey interfaces.AppPubkey) (interfaces.OnboardRequest, error) {
	randomInt, err := rand.Int(rand.Reader, big.NewInt(math.MaxInt64))
	if err != nil {
		return interfaces.OnboardRequest{}, err
	}

	nonce := big.NewInt(randomInt.Int64())
	if err != nil {
		return interfaces.OnboardRequest{}, err
	}

	onboardRequest := interfaces.OnboardRequest{
		Pubkey:   pubkey,
		Nonce:    nonce,
		Operator: common.Address(operator),
	}

	reportData := OnboardRequestReportData(kmsAddress, onboardRequest)
	onboardRequest.Attestation, err = k.attestationProvider.Attest(reportData)
	if err != nil {
		return interfaces.OnboardRequest{}, err
	}

	return onboardRequest, nil
}

// OnboardRemote encrypts the master key for a new KMS instance.
// Used for secure master key distribution.
func (k *SimpleKMS) OnboardRemote(pubkey cryptoutils.AppPubkey) ([]byte, error) {
	// Note: vaidation done by the caller. Might be a good idea to consider moving it here to match RequestOnboard.
	return cryptoutils.EncryptWithPublicKey(pubkey, k.masterKey)
}

// WithSeed creates a new SimpleKMS with the provided seed.
// Useful for testing with deterministic keys.
func (k *SimpleKMS) WithSeed(seed []byte) *SimpleKMS {
	newkms := &SimpleKMS{
		masterKey:           make([]byte, len(k.masterKey)),
		attestationProvider: k.attestationProvider,
		operator:            k.operator,
	}
	copy(newkms.masterKey, seed)
	return newkms
}

// WithAttestationProvider creates a new SimpleKMS with the specified attestation provider.
// Used to customize attestation generation.
func (k *SimpleKMS) WithAttestationProvider(provider cryptoutils.AttestationProvider) *SimpleKMS {
	newkms := &SimpleKMS{
		masterKey:           make([]byte, len(k.masterKey)),
		attestationProvider: provider,
		operator:            k.operator,
	}
	copy(newkms.masterKey, k.masterKey)
	return newkms
}

// WithOperator creates a new SimpleKMS with the specified operator address.
// Sets the KMS operator for authorization purposes.
func (k *SimpleKMS) WithOperator(operator interfaces.ContractAddress) *SimpleKMS {
	newkms := &SimpleKMS{
		masterKey:           make([]byte, len(k.masterKey)),
		attestationProvider: k.attestationProvider,
		operator:            operator,
	}
	copy(newkms.masterKey, k.masterKey)
	return newkms
}

// getCA generates the app's CA key and certificate.
// Derives the CA key deterministically from the contract address.
func (k *SimpleKMS) getCA(contractAddr interfaces.ContractAddress) (*ecdsa.PrivateKey, interfaces.CACert, error) {
	// Derive CA key from contract address
	caKey, err := k.deriveCAKey(contractAddr)
	if err != nil {
		return nil, nil, err
	}

	// Create a self-signed CA certificate
	certPEM, err := createCACertificate(caKey, interfaces.NewAppCommonName(contractAddr))
	if err != nil {
		return nil, nil, err
	}

	return caKey, certPEM, nil
}

// GetPKI returns the CA certificate, app public key and attestation for a contract.
// Generates these materials deterministically from the contract address.
func (k *SimpleKMS) GetPKI(contractAddr interfaces.ContractAddress) (interfaces.AppPKI, error) {
	_, certPEM, err := k.getCA(contractAddr)
	if err != nil {
		return interfaces.AppPKI{}, fmt.Errorf("failed to generate app CA: %w", err)
	}

	// Derive app key from contract address
	appKey, err := k.GetAppPrivkey(contractAddr)
	if err != nil {
		return interfaces.AppPKI{}, err
	}

	appPubkey, err := appKey.GetPublicKey()
	if err != nil {
		return interfaces.AppPKI{}, err
	}

	// Extract and encode public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(appPubkey)
	if err != nil {
		return interfaces.AppPKI{}, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	pkiData := interfaces.AppPKI{Ca: certPEM, Pubkey: pubKeyPEM}
	reportData := pkiData.ReportData(contractAddr)

	pkiData.Attestation, err = k.attestationProvider.Attest(reportData)
	if err != nil {
		return interfaces.AppPKI{}, fmt.Errorf("failed to attest: %w", err)
	}

	return pkiData, nil
}

// GetAppPrivkey returns the application private key for a contract address.
// Derives the key deterministically from the master key and contract address.
func (k *SimpleKMS) GetAppPrivkey(contractAddr interfaces.ContractAddress) (interfaces.AppPrivkey, error) {
	appKey, err := k.deriveAppKey(contractAddr)
	if err != nil {
		return nil, err
	}

	privKeyBytes, err := x509.MarshalECPrivateKey(appKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	return pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privKeyBytes,
	}), nil
}

// SignCSR signs a certificate signing request for a specified contract.
// Verifies the CSR signature before creating a certificate valid for 1 year.
func (k *SimpleKMS) SignCSR(contractAddr interfaces.ContractAddress, csr interfaces.TLSCSR) (interfaces.TLSCert, error) {
	parsedCSR, err := csr.GetX509CSR()
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	// Verify CSR signature
	if err := parsedCSR.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	caKey, caCertPEM, err := k.getCA(contractAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to generate app CA: %w", err)
	}

	caCert, err := caCertPEM.GetX509Cert()
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               parsedCSR.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // 1 year validity
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              parsedCSR.DNSNames,
		IPAddresses:           parsedCSR.IPAddresses,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, caCert, parsedCSR.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode to PEM
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}), nil
}

// AppSecrets provides all cryptographic materials needed for a TEE instance.
// Returns private key, signed certificate, and attestation in one package.
func (k *SimpleKMS) AppSecrets(contractAddr interfaces.ContractAddress, csr interfaces.TLSCSR) (*interfaces.AppSecrets, error) {
	appPrivkey, err := k.GetAppPrivkey(contractAddr)
	if err != nil {
		return nil, err
	}

	cert, err := k.SignCSR(contractAddr, csr)
	if err != nil {
		return nil, err
	}

	appSecrets := &interfaces.AppSecrets{
		AppPrivkey: appPrivkey,
		TLSCert:    cert,
		Operator:   k.operator,
	}

	reportData := appSecrets.ReportData(contractAddr)
	appSecrets.Attestation, err = k.attestationProvider.Attest(reportData)
	return appSecrets, err
}

// deriveCAKey derives a CA key from a contract address.
// Creates deterministic ECDSA key using the P-256 curve.
func (k *SimpleKMS) deriveCAKey(contractAddr interfaces.ContractAddress) (*ecdsa.PrivateKey, error) {
	// Create deterministic seed
	h := sha256.New()
	h.Write(k.masterKey)
	h.Write(contractAddr[:])
	h.Write([]byte("ca"))
	seed := h.Sum(nil)

	// Create EC private key from seed
	curve := elliptic.P256() // Use P-256 for all keys
	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
		},
		D: new(big.Int).SetBytes(seed[:32]), // Use first 32 bytes as private key
	}

	// Generate public key
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(seed[:32])

	// TODO: sanity check that X and Y are on curve and priv does not need trimming

	return privateKey, nil
}

// deriveAppKey derives an application key from a contract address.
// Creates deterministic ECDSA key using the P-256 curve.
func (k *SimpleKMS) deriveAppKey(contractAddr interfaces.ContractAddress) (*ecdsa.PrivateKey, error) {
	// Create deterministic seed
	h := sha256.New()
	h.Write(k.masterKey)
	h.Write(contractAddr[:])
	h.Write([]byte("app"))
	seed := h.Sum(nil)

	// Create EC private key from seed
	curve := elliptic.P256() // Use P-256 for all keys
	privateKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
		},
		D: new(big.Int).SetBytes(seed[:32]), // Use first 32 bytes as private key
	}

	// Generate public key
	privateKey.PublicKey.X, privateKey.PublicKey.Y = curve.ScalarBaseMult(seed[:32])

	// TODO: sanity check that X and Y are on curve and priv does not need trimming

	return privateKey, nil
}

// createCACertificate creates a self-signed CA certificate.
// Creates a certificate valid for 10 years suitable for signing instance certificates.
func createCACertificate(caKey *ecdsa.PrivateKey, cn interfaces.AppCommonName) (interfaces.CACert, error) {
	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"SimpleKMS"},
			CommonName:   fmt.Sprintf("CA for %s", cn),
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years validity
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	// Create certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode to PEM
	return pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	}), nil
}
