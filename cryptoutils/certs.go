package cryptoutils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"

	"github.com/ethereum/go-ethereum/crypto"
)

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
	return crypto.Keccak256(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubkeyDER}))
}
