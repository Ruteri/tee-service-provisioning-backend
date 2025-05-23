package kmsgovernance

import (
	"context"
	"errors"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	kmsbindings "github.com/ruteri/tee-service-provisioning-backend/bindings/kms"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

var ErrNoTransactOpts = errors.New("no authorized transactor available")

type KmsGovernanceClient struct {
	contract *kmsbindings.Kms
	client   bind.ContractBackend
	backend  bind.DeployBackend
	address  common.Address
	auth     *bind.TransactOpts
}

func NewKmsGovernanceClient(client bind.ContractBackend, backend bind.DeployBackend, address common.Address) (*KmsGovernanceClient, error) {
	contract, err := kmsbindings.NewKms(address, client)
	if err != nil {
		return nil, err
	}

	return &KmsGovernanceClient{
		contract: contract,
		client:   client,
		backend:  backend,
		address:  address,
	}, nil
}

func (c *KmsGovernanceClient) SetTransactOpts(auth *bind.TransactOpts) {
	c.auth = auth
}

func (c *KmsGovernanceClient) PKI() (interfaces.AppPKI, error) {
	pki, err := c.contract.PKI(&bind.CallOpts{Context: context.Background()})
	if err != nil {
		return interfaces.AppPKI{}, err
	}

	return interfaces.AppPKI{
		Ca:          pki.Ca,
		Pubkey:      pki.Pubkey,
		Attestation: pki.Attestation,
	}, nil
}

func (c *KmsGovernanceClient) DCAPIdentity(report interfaces.DCAPReport, events []interfaces.DCAPEvent) ([32]byte, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	// Convert report to contract report format
	contractReport := kmsbindings.DCAPReport{
		MrTd:          report.MrTd[:],
		RTMRs:         [4][]byte{report.RTMRs[0][:], report.RTMRs[1][:], report.RTMRs[2][:], report.RTMRs[3][:]},
		MrOwner:       report.MrOwner[:],
		MrConfigId:    report.MrConfigId[:],
		MrConfigOwner: report.MrConfigOwner[:],
	}

	// Convert events to contract event format
	contractEvents := make([]kmsbindings.DCAPEvent, len(events))
	for i, event := range events {
		contractEvents[i] = kmsbindings.DCAPEvent{
			Index:        event.Index,
			EventType:    event.EventType,
			EventPayload: event.EventPayload,
			Digest:       event.Digest,
		}
	}

	return c.contract.DCAPIdentity(opts, contractReport, contractEvents)
}

func (c *KmsGovernanceClient) MAAIdentity(report interfaces.MAAReport) ([32]byte, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	// Convert PCRs to contract format
	var pcrs [24][32]byte
	for i, pcr := range report.PCRs {
		copy(pcrs[i][:], pcr[:])
	}

	contractReport := kmsbindings.MAAReport{
		PCRs: pcrs,
	}

	return c.contract.MAAIdentity(opts, contractReport)
}

func (c *KmsGovernanceClient) IdentityAllowed(identity [32]byte, operator [20]byte) (bool, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	return c.contract.IdentityAllowed(opts, identity, operator)
}

func (c *KmsGovernanceClient) AllowlistDCAP(report interfaces.DCAPReport) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	// Convert report to contract report format
	contractReport := kmsbindings.DCAPReport{
		MrTd:          report.MrTd[:],
		RTMRs:         [4][]byte{report.RTMRs[0][:], report.RTMRs[1][:], report.RTMRs[2][:], report.RTMRs[3][:]},
		MrOwner:       report.MrOwner[:],
		MrConfigId:    report.MrConfigId[:],
		MrConfigOwner: report.MrConfigOwner[:],
	}

	return c.contract.AllowlistDCAP(c.auth, contractReport)
}

func (c *KmsGovernanceClient) AllowlistMAA(report interfaces.MAAReport) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	// Convert PCRs to contract format
	var pcrs [24][32]byte
	for i, pcr := range report.PCRs {
		copy(pcrs[i][:], pcr[:])
	}

	contractReport := kmsbindings.MAAReport{
		PCRs: pcrs,
	}

	return c.contract.AllowlistMAA(c.auth, contractReport)
}

func (c *KmsGovernanceClient) AllowlistIdentity(identity [32]byte) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	return c.contract.AllowlistIdentity(c.auth, identity)
}

func (c *KmsGovernanceClient) RemoveAllowlistedIdentity(identity [32]byte) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	return c.contract.RemoveAllowlistedIdentity(c.auth, identity)
}

func (c *KmsGovernanceClient) RequestOnboard(request interfaces.OnboardRequest) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	// Convert request to contract format
	contractRequest := kmsbindings.OnboardRequest{
		Pubkey:      request.Pubkey,
		Nonce:       request.Nonce,
		Operator:    request.Operator,
		Attestation: request.Attestation,
	}

	return c.contract.RequestOnboard(c.auth, contractRequest)
}

func (c *KmsGovernanceClient) FetchOnboardRequest(requestId [32]byte) (interfaces.OnboardRequest, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	contractRequest, err := c.contract.FetchOnboardRequest(opts, requestId)
	if err != nil {
		return interfaces.OnboardRequest{}, err
	}

	// Convert contract request to interface format
	request := interfaces.OnboardRequest{
		Pubkey:      contractRequest.Pubkey,
		Nonce:       contractRequest.Nonce,
		Operator:    contractRequest.Operator,
		Attestation: contractRequest.Attestation,
	}

	return request, nil
}

func (c *KmsGovernanceClient) InstanceDomainNames() ([]string, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	return c.contract.InstanceDomainNames(opts)
}

func (c *KmsGovernanceClient) RegisterInstanceDomainName(domain string) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	return c.contract.RegisterInstanceDomainName(c.auth, domain)
}

func (c *KmsGovernanceClient) ApplicationAllowed(app [20]byte) (bool, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	return c.contract.ApplicationAllowed(opts, app)
}
