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

// SimpleKMS provides a straightforward implementation of the KMS interface.
// It derives keys deterministically from a master key, making it suitable
// for development and testing environments.
type SimpleKMS struct {
	masterKey []byte
	mu        sync.RWMutex

	attestationProvider cryptoutils.AttestationProvider
	operator            interfaces.ContractAddress
}

// NewSimpleKMS creates a new instance of SimpleKMS with the provided master key.
// The master key must be at least 32 bytes long for adequate security.
// Returns an error if the master key is too short.
func NewSimpleKMS(masterKey []byte) (*SimpleKMS, error) {
	if len(masterKey) < 32 {
		return nil, errors.New("master key must be at least 32 bytes")
	}

	return &SimpleKMS{masterKey: masterKey, attestationProvider: &cryptoutils.DumyAttestationProvider{}}, nil
}

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

func (k *SimpleKMS) OnboardRemote(pubkey cryptoutils.AppPubkey) ([]byte, error) {
	// Note: vaidation done by the caller. Might be a good idea to consider moving it here to match RequestOnboard.
	return cryptoutils.EncryptWithPublicKey(pubkey, k.masterKey)
}

func (k *SimpleKMS) WithSeed(seed []byte) *SimpleKMS {
	newkms := &SimpleKMS{
		masterKey:           make([]byte, len(k.masterKey)),
		attestationProvider: k.attestationProvider,
		operator:            k.operator,
	}
	copy(newkms.masterKey, seed)
	return newkms
}

func (k *SimpleKMS) WithAttestationProvider(provider cryptoutils.AttestationProvider) *SimpleKMS {
	newkms := &SimpleKMS{
		masterKey:           make([]byte, len(k.masterKey)),
		attestationProvider: provider,
		operator:            k.operator,
	}
	copy(newkms.masterKey, k.masterKey)
	return newkms
}

func (k *SimpleKMS) WithOperator(operator interfaces.ContractAddress) *SimpleKMS {
	newkms := &SimpleKMS{
		masterKey:           make([]byte, len(k.masterKey)),
		attestationProvider: k.attestationProvider,
		operator:            operator,
	}
	copy(newkms.masterKey, k.masterKey)
	return newkms
}

// getCA generates the app's CA key and PEM-encoded certificate
// It derives the CA key from the contract address and creates a self-signed certificate.
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
// It derives these cryptographic materials deterministically from the contract address.
// The returned AppPKI contains:
//   - CA certificate in PEM format
//   - Application public key in PEM format
//   - Attestation data that can be verified by external parties
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

// GetAppPrivkey returns the application private key for the specified contract address.
// This key is derived deterministically from the master key and contract address.
// The private key is returned in PEM format (PKCS#8).
// This method assumes attestation and identity verification have already been performed.
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

// SignCSR signs a certificate signing request using the CA key for the specified contract.
// It verifies the CSR signature before creating a certificate valid for 1 year.
// The certificate includes:
//   - Subject from the CSR
//   - Key usage for digital signatures and key encipherment
//   - Extended key usage for server and client authentication
//   - DNS names and IP addresses from the CSR
//
// The returned certificate is in PEM format.
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

// deriveCAKey derives a CA key from a contract address
// The resulting key is an ECDSA key using the P-256 curve.
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

// deriveAppKey derives an application key from a contract address
// The resulting key is an ECDSA key using the P-256 curve.
// TODO: Use Ethereum's curve (requires a refactor of marshaling/unmarshaling since x509 does not support it)
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

// createCACertificate creates a self-signed CA certificate for the specified key and contract.
// The certificate is valid for 10 years and is suitable for signing instance certificates.
// It has key usage for certificate signing, CRL signing, and digital signatures.
// The certificate is returned in PEM format.
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
