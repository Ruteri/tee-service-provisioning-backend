package cryptoutils

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
)

// VerifyCertificate validates that a certificate matches a given private key and has the expected common name.
// It performs the following checks:
//   - The certificate can be parsed correctly
//   - The common name matches the expected value
//   - The public key in the certificate corresponds to the provided private key
//
// This function is useful for ensuring that a certificate was issued for the correct entity
// and matches the private key that will be used with it.
func VerifyCertificate(keyPEM, certPEM []byte, expectedCN string) error {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return errors.New("failed to decode private key PEM block")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		// Try PKCS#1 format if PKCS#8 fails
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" {
		return errors.New("failed to decode certificate PEM block")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Compare CommonName
	if cert.Subject.CommonName != expectedCN {
		return fmt.Errorf("CommonName is %s, expected %s", cert.Subject.CommonName, expectedCN)
	}

	// Compare public keys
	certPublicKey := cert.PublicKey
	privatePublicKey := privateKey.(interface{ Public() crypto.PublicKey }).Public()

	// For ECDSA keys
	if ecdsaCertKey, ok := certPublicKey.(*ecdsa.PublicKey); ok {
		ecdsaPrivKey, ok := privatePublicKey.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("private key type doesn't match certificate")
		}

		if ecdsaCertKey.X.Cmp(ecdsaPrivKey.X) != 0 ||
			ecdsaCertKey.Y.Cmp(ecdsaPrivKey.Y) != 0 ||
			ecdsaCertKey.Curve != ecdsaPrivKey.Curve {
			return errors.New("private key doesn't match certificate")
		}
		return nil
	}
	// Add comparisons for other key types (RSA, etc.) as needed

	return errors.New("unsupported key type")
}

// CreateCSRWithRandomKey generates a new ECDSA key pair and creates a Certificate Signing Request (CSR)
// with the specified Common Name (CN). This is useful for generating new identities for TLS connections.
//
// Returns:
//   - Private key in PEM format
//   - CSR in PEM format
//   - Error if key generation or CSR creation fails
func CreateCSRWithRandomKey(cn string) ([]byte, TLSCSR, error) {
	// Generate a new ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Create a CSR template
	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: cn,
		},
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}

	// Create a CSR using the private key and template
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, privateKey)
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
	return keyPEM, TLSCSR(csrPEM), nil
}

// RandomCert generates a random self-signed certificate to use
// for https servers where chain of trust does not matter, for
// example when the server is running on localhost.
func RandomCert() (tls.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{},
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	certASN1, err := x509.CreateCertificate(rand.Reader, template, template,
		privateKey.Public(), privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certASN1})

	privkeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privkeyBytes,
	}))
}

func DERPubkeyHash(pubkeyDER []byte) []byte {
	shaHash := sha256.Sum256(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubkeyDER}))
	return shaHash[:]
}
