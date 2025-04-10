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
	"math/big"
	"sync"
	"time"

	"github.com/ruteri/tee-service-provisioning-backend/api"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// SimpleKMS provides a straightforward implementation of the KMS interface.
// It derives keys deterministically from a master key, making it suitable
// for development and testing environments.
type SimpleKMS struct {
	masterKey []byte
	mu        sync.RWMutex

	attestationProvider AttestationProvider
}

type DumyAttestationProvider struct{}

func (DumyAttestationProvider) Attest(userData [64]byte) ([]byte, error) {
	return []byte(fmt.Sprintf("Attestation for CA %x", userData)), nil
}

// NewSimpleKMS creates a new instance of SimpleKMS with the provided master key.
// The master key must be at least 32 bytes long for adequate security.
// Returns an error if the master key is too short.
func NewSimpleKMS(masterKey []byte) (*SimpleKMS, error) {
	if len(masterKey) < 32 {
		return nil, errors.New("master key must be at least 32 bytes")
	}

	return &SimpleKMS{masterKey: masterKey, attestationProvider: DumyAttestationProvider{}}, nil
}

func (k *SimpleKMS) WithAttestationProvider(provider AttestationProvider) *SimpleKMS {
	newkms := &SimpleKMS{
		masterKey:           make([]byte, len(k.masterKey)),
		attestationProvider: provider,
	}
	copy(newkms.masterKey, k.masterKey)
	return newkms
}

// GetPKI returns the CA certificate, app public key and attestation for a contract.
// It derives these cryptographic materials deterministically from the contract address.
// The returned AppPKI contains:
//   - CA certificate in PEM format
//   - Application public key in PEM format
//   - Attestation data that can be verified by external parties
func (k *SimpleKMS) GetPKI(contractAddr interfaces.ContractAddress) (interfaces.AppPKI, error) {
	// Derive CA key from contract address
	caKey, err := k.deriveKey(contractAddr, "ca")
	if err != nil {
		return interfaces.AppPKI{}, err
	}

	// Create a self-signed CA certificate
	certPEM, err := createCACertificate(caKey, interfaces.NewAppCommonName(contractAddr))
	if err != nil {
		return interfaces.AppPKI{}, err
	}

	// Derive app key from contract address
	appKey, err := k.deriveKey(contractAddr, "app")
	if err != nil {
		return interfaces.AppPKI{}, err
	}

	// Extract and encode public key
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&appKey.PublicKey)
	if err != nil {
		return interfaces.AppPKI{}, fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	reportData := api.ReportData(contractAddr, certPEM, pubKeyPEM)
	attestation, err := k.attestationProvider.Attest(reportData)
	if err != nil {
		return interfaces.AppPKI{}, fmt.Errorf("failed to attest: %w", err)
	}

	return interfaces.AppPKI{certPEM, pubKeyPEM, attestation}, nil
}

// GetAppPrivkey returns the application private key for the specified contract address.
// This key is derived deterministically from the master key and contract address.
// The private key is returned in PEM format (PKCS#8).
// This method assumes attestation and identity verification have already been performed.
func (k *SimpleKMS) GetAppPrivkey(contractAddr interfaces.ContractAddress) (interfaces.AppPrivkey, error) {
	appKey, err := k.deriveKey(contractAddr, "app")
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
	// Parse CSR
	block, _ := pem.Decode(csr)
	if block == nil {
		return nil, errors.New("failed to decode CSR")
	}

	parsedCSR, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}

	// Verify CSR signature
	if err := parsedCSR.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	// Get CA key and certificate
	caKey, err := k.deriveKey(contractAddr, "ca")
	if err != nil {
		return nil, err
	}

	caCertPEM, err := createCACertificate(caKey, interfaces.NewAppCommonName(contractAddr))
	if err != nil {
		return nil, err
	}

	caBlock, _ := pem.Decode(caCertPEM)
	if caBlock == nil {
		return nil, errors.New("failed to decode CA certificate")
	}

	caCert, err := x509.ParseCertificate(caBlock.Bytes)
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

// deriveKey derives a key from a contract address and purpose (e.g., "ca" or "app").
// It creates a deterministic seed by hashing the master key, contract address, and purpose.
// The resulting key is an ECDSA key using the P-256 curve.
func (k *SimpleKMS) deriveKey(contractAddr interfaces.ContractAddress, purpose string) (*ecdsa.PrivateKey, error) {
	// Create deterministic seed
	h := sha256.New()
	h.Write(k.masterKey)
	h.Write(contractAddr[:])
	h.Write([]byte(purpose))
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
