package kmsgovernance

import (
	"errors"
	"slices"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	kmsbindings "github.com/ruteri/tee-service-provisioning-backend/bindings/kms"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// KMSGovernanceImpl implements the KMSGovernance interface for testing
type KMSGovernanceImpl struct {
	contractAddr          interfaces.ContractAddress
	owner                 interfaces.ContractAddress
	operators             map[interfaces.ContractAddress]bool
	appPKI                interfaces.AppPKI
	allowlistedIdentities map[[32]byte]bool
	onboardRequests       map[[32]byte]kmsbindings.OnboardRequest
	domains               []string
	allowedApps           []interfaces.ContractAddress
}

// NewKMSGovernance creates a new KMSGovernance implementation
func NewKMSGovernance(contractAddr interfaces.ContractAddress, owner interfaces.ContractAddress) *KMSGovernanceImpl {
	g := &KMSGovernanceImpl{
		contractAddr:          contractAddr,
		owner:                 owner,
		operators:             map[interfaces.ContractAddress]bool{owner: true},
		allowlistedIdentities: make(map[[32]byte]bool),
		onboardRequests:       make(map[[32]byte]kmsbindings.OnboardRequest),
	}
	return g
}

// DCAPIdentity calculates identity hash for a DCAP report
func (g *KMSGovernanceImpl) DCAPIdentity(report interfaces.DCAPReport, _ []interfaces.DCAPEvent) ([32]byte, error) {
	data := []byte(g.contractAddr.Bytes())
	data = append(data, report.RTMRs[0][:]...)
	data = append(data, report.RTMRs[1][:]...)
	data = append(data, report.RTMRs[2][:]...)
	hash := crypto.Keccak256(data)

	var identity [32]byte
	copy(identity[:], hash)
	return identity, nil
}

// MAAIdentity calculates identity hash for an MAA report
func (g *KMSGovernanceImpl) MAAIdentity(report interfaces.MAAReport) ([32]byte, error) {
	data := append(g.contractAddr.Bytes(),
		append(report.PCRs[4][:], append(report.PCRs[9][:], report.PCRs[11][:]...)...)...)

	hash := crypto.Keccak256(data)

	var identity [32]byte
	copy(identity[:], hash)
	return identity, nil
}

// IdentityAllowed checks if an identity is authorized
func (g *KMSGovernanceImpl) IdentityAllowed(identity [32]byte, operator [20]byte) (bool, error) {
	if !g.operators[operator] {
		return false, errors.New("operator not authorized")
	}
	return g.allowlistedIdentities[identity], nil
}

// AllowlistDCAP adds a DCAP-attested identity to the allowlist
func (g *KMSGovernanceImpl) AllowlistDCAP(report interfaces.DCAPReport) (*types.Transaction, error) {
	identity, err := g.DCAPIdentity(report, nil)
	if err != nil {
		return nil, err
	}
	return g.AllowlistIdentity(identity)
}

// AllowlistMAA adds an MAA-attested identity to the allowlist
func (g *KMSGovernanceImpl) AllowlistMAA(report interfaces.MAAReport) (*types.Transaction, error) {
	identity, err := g.MAAIdentity(report)
	if err != nil {
		return nil, err
	}
	return g.AllowlistIdentity(identity)
}

// AllowlistIdentity adds an identity hash to the allowlist
func (g *KMSGovernanceImpl) AllowlistIdentity(identity [32]byte) (*types.Transaction, error) {
	g.allowlistedIdentities[identity] = true
	return &types.Transaction{}, nil
}

// RemoveAllowlistedIdentity removes an identity from the allowlist
func (g *KMSGovernanceImpl) RemoveAllowlistedIdentity(identity [32]byte) (*types.Transaction, error) {
	delete(g.allowlistedIdentities, identity)
	return &types.Transaction{}, nil
}

// ApplicationAllowed checks if an application is allowed
func (g *KMSGovernanceImpl) ApplicationAllowed(app [20]byte) (bool, error) {
	appAddr := interfaces.ContractAddress(app)
	return slices.Contains(g.allowedApps, appAddr), nil
}

// RequestOnboard submits an onboarding request for a new TEE instance
func (g *KMSGovernanceImpl) RequestOnboard(req kmsbindings.OnboardRequest) (*types.Transaction, error) {
	if !g.operators[interfaces.ContractAddress(req.Operator)] {
		return nil, errors.New("operator not authorized")
	}

	data := append(req.Pubkey, append(req.Nonce.Bytes(),
		append(req.Operator[:], req.Attestation...)...)...)

	hash := crypto.Keccak256(data)
	var reqHash [32]byte
	copy(reqHash[:], hash)

	g.onboardRequests[reqHash] = req
	return &types.Transaction{}, nil
}

// FetchOnboardRequest retrieves an onboarding request
func (g *KMSGovernanceImpl) FetchOnboardRequest(reqHash [32]byte) (kmsbindings.OnboardRequest, error) {
	req, exists := g.onboardRequests[reqHash]
	if !exists {
		return kmsbindings.OnboardRequest{}, errors.New("request not found")
	}
	return req, nil
}

// PKI retrieves application PKI information
func (g *KMSGovernanceImpl) PKI() (interfaces.AppPKI, error) {
	return g.appPKI, nil
}

// InstanceDomainNames returns registered instance domain names
func (g *KMSGovernanceImpl) InstanceDomainNames() ([]string, error) {
	return g.domains, nil
}

// Additional methods for testing

// SetPKI sets the PKI information
func (g *KMSGovernanceImpl) SetPKI(pki interfaces.AppPKI) error {
	g.appPKI = pki
	return nil
}

// RegisterDomain adds a domain name
func (g *KMSGovernanceImpl) RegisterDomain(domain string) error {
	g.domains = append(g.domains, domain)
	return nil
}

// AllowApp adds an application to the allowlist
func (g *KMSGovernanceImpl) AllowApp(app interfaces.ContractAddress) error {
	g.allowedApps = append(g.allowedApps, app)
	return nil
}

// RemoveApp removes an application from the allowlist
func (g *KMSGovernanceImpl) RemoveApp(app interfaces.ContractAddress) error {
	for i, a := range g.allowedApps {
		if a == app {
			g.allowedApps[i] = g.allowedApps[len(g.allowedApps)-1]
			g.allowedApps = g.allowedApps[:len(g.allowedApps)-1]
			break
		}
	}
	return nil
}
