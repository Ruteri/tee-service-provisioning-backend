package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"sync"

	"github.com/ruteri/tee-service-provisioning-backend/api/kmshandler"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/instanceutils/serviceresolver"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// AppCertificateManager is a concrete implementation of the CertificateManager interface
// using the AppResolver to fetch certificates and CAs for different applications.
// It manages TLS certificates for secure cross-application communication.
type AppCertificateManager struct {
	secretsProvider  kmshandler.SecretsProvider
	onchainDiscovery interfaces.OnchainDiscovery

	// TODO: fetch from KMS governance instead!
	kmsUrl string
	// ourAppAddress is our application's contract address for identity
	ourAppAddress interfaces.ContractAddress

	// ourCert is our certificate and private key for outgoing connections
	ourCert *tls.Certificate

	// Cache for CA certificates to avoid repeated fetching
	caCache     map[string]*x509.Certificate
	caCacheLock sync.RWMutex

	// Logger for operational insights
	log *slog.Logger
}

// NewAppCertificateManager creates a new certificate manager for application communication.
// Parameters:
//   - secretsProvider: fetches signed certificates
//   - onchainDiscovery: fetches PKI
//   - ourAppAddress: Our application's contract address
//   - log: Logger for operational insights
//
// Returns:
//   - Configured AppCertificateManager
//   - Error if certificate loading fails
func NewAppCertificateManager(
	secretsProvider kmshandler.SecretsProvider,
	onchainDiscovery interfaces.OnchainDiscovery,
	ourAppAddress interfaces.ContractAddress,
	log *slog.Logger,
) (*AppCertificateManager, error) {
	// Initialize manager
	manager := &AppCertificateManager{
		secretsProvider:  secretsProvider,
		onchainDiscovery: onchainDiscovery,
		ourAppAddress:    ourAppAddress,
		caCache:          make(map[string]*x509.Certificate),
		log:              log,
	}

	// Fetch our certificate for outgoing communications
	cert, err := manager.loadOurCertificate()
	if err != nil {
		return nil, fmt.Errorf("failed to load our certificate: %w", err)
	}
	manager.ourCert = cert

	return manager, nil
}

// loadOurCertificate loads our application's certificate and private key.
// This certificate is used for both outgoing connections and for verifying
// our identity to other instances.
func (m *AppCertificateManager) loadOurCertificate() (*tls.Certificate, error) {
	// Fetch our certificate and private key from the resolver
	// TODO: add a local provider that just reads it from file
	key, csr, err := cryptoutils.CreateCSRWithRandomKey(interfaces.NewAppCommonName(m.ourAppAddress).String())
	if err != nil {
		return nil, fmt.Errorf("failed to prepare CSR for registration: %w", err)
	}
	secrets, err := m.secretsProvider.AppSecrets(m.kmsUrl, m.ourAppAddress, csr)
	if err != nil {
		return nil, fmt.Errorf("failed to get signed certificate from registry: %w", err)
	}
	tlsCert, err := tls.X509KeyPair(secrets.TLSCert, key)
	if err != nil {
		return nil, fmt.Errorf("failed to get certificate: %w", err)
	}

	return &tlsCert, nil
}

// GetClientCertificate returns our application's certificate for outgoing connections.
// This implements the CertificateManager interface and is used by TLS clients
// to provide our identity when connecting to other instances.
func (m *AppCertificateManager) GetClientCertificate(_ *tls.CertificateRequestInfo) (*tls.Certificate, error) {
	return m.ourCert, nil
}

// GetConfigForClient returns a TLS config for incoming connections based on the client hello.
// This implements the CertificateManager interface and is used by TLS servers
// to validate the identity of connecting instances.
func (m *AppCertificateManager) GetConfigForClient(hello *tls.ClientHelloInfo) (*tls.Config, error) {
	// Create a server TLS config with client certificate verification
	config := &tls.Config{
		ClientAuth:         tls.RequireAndVerifyClientCert,
		Certificates:       []tls.Certificate{*m.ourCert},
		InsecureSkipVerify: true,
	}

	// If we have a ServerName indicating the source app, we can set up a specific CA pool
	if hello.ServerName != "" {
		// This would be a contract address in hex format
		var contractAddr interfaces.ContractAddress
		// Parse the contract address from ServerName
		if len(hello.ServerName) != 44 {
			m.log.Warn("Failed to get CA for client", "serverName", hello.ServerName, "err", errors.New("ServerName not 44 characters long"))
			return nil, errors.New("ServerName not 44 characters long")
		}

		srvNameBytes, err := hex.DecodeString(hello.ServerName[:40])
		if err != nil {
			m.log.Warn("Failed to get CA for client", "serverName", hello.ServerName, "err", errors.New("ServerName not hex"))
			return nil, errors.New("ServerName not hex")
		}

		copy(contractAddr[:], srvNameBytes[:20])

		// Get the CA certificate for this application
		cert, err := m.CACertFor(contractAddr)
		if err != nil {
			m.log.Warn("Failed to get CA for client", "serverName", hello.ServerName, "err", err)
			return nil, err
		} else {
			// Create a cert pool with just this application's CA
			config.ClientCAs = x509.NewCertPool()
			config.ClientCAs.AddCert(cert)

			m.log.Debug("Using specific CA for client", "serverName", hello.ServerName)
		}
	}

	return config, nil
}

// CACertFor returns the CA certificate for a specific application contract.
// This method is used to verify the identity of instances from other applications.
// It caches CA certificates to avoid repeated registry calls.
func (m *AppCertificateManager) CACertFor(contractAddr interfaces.ContractAddress) (*x509.Certificate, error) {
	// Create a key for cache lookup
	key := contractAddr.String()

	// Check cache first
	m.caCacheLock.RLock()
	cert, found := m.caCache[key]
	m.caCacheLock.RUnlock()

	if found {
		return cert, nil
	}

	// Fetch CA from resolver
	metadata, err := serviceresolver.ResolveServiceMetadata(m.onchainDiscovery)
	if err != nil {
		return nil, fmt.Errorf("failed to get CA certificate: %w", err)
	}

	// Parse the PEM encoded CA cert
	block, _ := pem.Decode(metadata.PKI.Ca)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	// Parse the CA certificate
	x509Cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Store in cache
	m.caCacheLock.Lock()
	m.caCache[key] = x509Cert
	m.caCacheLock.Unlock()

	return x509Cert, nil
}
