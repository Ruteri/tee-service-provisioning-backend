package cryptoutils

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

// TLSCSR represents a TLS Certificate Signing Request in PEM format.
type TLSCSR []byte

// NewTLSCSR creates a new CSR object from PEM-encoded data with validation.
func NewTLSCSR(data []byte) (TLSCSR, error) {
	// Validate PEM format
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return TLSCSR{}, errors.New("invalid CSR: not in PEM format or not a certificate request")
	}

	// Validate CSR structure
	_, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return TLSCSR{}, fmt.Errorf("invalid CSR structure: %w", err)
	}

	return TLSCSR(data), nil
}

// Validate checks if the CSR is properly formed.
func (csr TLSCSR) Validate() error {
	_, err := NewTLSCSR(csr)
	return err
}

// GetX509CSR returns the parsed X.509 certificate request.
func (csr TLSCSR) GetX509CSR() (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csr)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return x509.ParseCertificateRequest(block.Bytes)
}

// TLSCert represents a TLS Certificate in PEM format.
type TLSCert []byte

// NewTLSCert creates a new certificate object from PEM-encoded data with validation.
func NewTLSCert(data []byte) (TLSCert, error) {
	// Validate PEM format
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return TLSCert{}, errors.New("invalid certificate: not in PEM format or not a certificate")
	}

	// Validate certificate structure
	_, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return TLSCert{}, fmt.Errorf("invalid certificate structure: %w", err)
	}

	return TLSCert(data), nil
}

// Validate checks if the certificate is properly formed.
func (cert TLSCert) Validate() error {
	_, err := NewTLSCert(cert)
	return err
}

// GetX509Cert returns the parsed X.509 certificate.
func (cert TLSCert) GetX509Cert() (*x509.Certificate, error) {
	block, _ := pem.Decode(cert)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// IsExpired checks if the certificate has expired.
func (cert TLSCert) IsExpired() (bool, error) {
	x509Cert, err := cert.GetX509Cert()
	if err != nil {
		return false, err
	}
	return x509Cert.NotAfter.Before(time.Now()), nil
}

// CACert represents a Certificate Authority Certificate in PEM format.
type CACert []byte

// NewCACert creates a new CA certificate object from PEM-encoded data with validation.
func NewCACert(data []byte) (CACert, error) {
	// Validate PEM format
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return CACert{}, errors.New("invalid CA certificate: not in PEM format or not a certificate")
	}

	// Validate certificate structure
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CACert{}, fmt.Errorf("invalid CA certificate structure: %w", err)
	}

	// Check if it's a CA certificate
	if !cert.IsCA {
		return CACert{}, errors.New("certificate is not a CA certificate (IsCA flag not set)")
	}

	return CACert(data), nil
}

// Validate checks if the CA certificate is properly formed.
func (ca CACert) Validate() error {
	_, err := NewCACert(ca)
	return err
}

// GetX509Cert returns the parsed X.509 certificate.
func (ca CACert) GetX509Cert() (*x509.Certificate, error) {
	block, _ := pem.Decode(ca)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// VerifyCertificate checks if a certificate was signed by this CA.
func (ca CACert) VerifyCertificate(cert TLSCert) error {
	caCert, err := ca.GetX509Cert()
	if err != nil {
		return err
	}

	leafCert, err := cert.GetX509Cert()
	if err != nil {
		return err
	}

	// Create a certificate pool containing the CA cert
	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)

	// Verify the leaf certificate against the CA
	_, err = leafCert.Verify(x509.VerifyOptions{
		Roots: caPool,
	})
	return err
}

// AppPubkey represents an application's public key in PEM format.
type AppPubkey []byte

// NewAppPubkey creates a new public key object from PEM-encoded data with validation.
func NewAppPubkey(data []byte) (AppPubkey, error) {
	// Validate PEM format
	block, _ := pem.Decode(data)
	if block == nil || (block.Type != "PUBLIC KEY" && block.Type != "RSA PUBLIC KEY") {
		return AppPubkey{}, errors.New("invalid public key: not in PEM format or not a public key")
	}

	// Validate public key structure
	_, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return AppPubkey{}, fmt.Errorf("invalid public key structure: %w", err)
	}

	return AppPubkey(data), nil
}

// Validate checks if the public key is properly formed.
func (pub AppPubkey) Validate() error {
	_, err := NewAppPubkey(pub)
	return err
}

// GetPublicKey returns the parsed public key interface.
func (pub AppPubkey) GetPublicKey() (interface{}, error) {
	block, _ := pem.Decode(pub)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return x509.ParsePKIXPublicKey(block.Bytes)
}

// AppPrivkey represents an application's private key in PEM format.
type AppPrivkey []byte

// NewAppPrivkey creates a new private key object from PEM-encoded data with validation.
func NewAppPrivkey(data []byte) (AppPrivkey, error) {
	// Validate PEM format
	block, _ := pem.Decode(data)
	if block == nil || (block.Type != "PRIVATE KEY" && block.Type != "EC PRIVATE KEY") {
		return AppPrivkey{}, errors.New("invalid private key: not in PEM format or not a private key")
	}

	// Try to parse it as a PKCS8 private key
	_, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Try to parse it as an EC private key
		_, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return AppPrivkey{}, fmt.Errorf("invalid private key structure: %w", err)
		}
	}

	return AppPrivkey(data), nil
}

// Validate checks if the private key is properly formed.
func (priv AppPrivkey) Validate() error {
	_, err := NewAppPrivkey(priv)
	return err
}

// GetPrivateKey returns the parsed private key interface.
func (priv AppPrivkey) GetPrivateKey() (interface{}, error) {
	block, _ := pem.Decode(priv)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	// Try to parse it as a PKCS8 private key
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	// Try to parse it as an EC private key
	key, err = x509.ParseECPrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	return nil, errors.New("failed to parse private key")
}

func (priv AppPrivkey) GetPublicKey() (interface{}, error) {
	parsedPriv, err := priv.GetPrivateKey()
	if err != nil {
		return nil, err
	}

	// Extract public key based on the private key type
	switch key := parsedPriv.(type) {
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	case ed25519.PrivateKey:
		return key.Public(), nil
	default:
		return nil, fmt.Errorf("unsupported private key type: %T", parsedPriv)
	}
}

func RandomP256Keypair() (AppPubkey, AppPrivkey, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, err
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

	pubkeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}

	pubkeyKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubkeyBytes,
	})

	return AppPubkey(pubkeyKeyPEM), AppPrivkey(privateKeyPEM), nil
}
