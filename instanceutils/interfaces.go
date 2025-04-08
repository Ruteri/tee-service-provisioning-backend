package instanceutils

import (
	"crypto/tls"

	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// AppResolver is an interface for managing cross-application TLS communication.
// It provides the cryptographic materials needed for secure communication
// between instances of the same or different applications.
type AppResolver interface {
	// GetAppMetadata retrieves CA certificate and instance addresses for a contract.
	// This enables verification of connections to instances of the target application.
	GetAppMetadata(contractAddr interfaces.ContractAddress) (interfaces.CACert, []string, error)

	// GetCert returns the TLS certificate for secure communication.
	// This certificate is used for outgoing connections to other instances.
	GetCert(contractAddr interfaces.ContractAddress) (*tls.Certificate, error)
}
