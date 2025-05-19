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

	identity, err := c.contract.DCAPIdentity(opts, contractReport, contractEvents)
	if err != nil {
		return [32]byte{}, err
	}

	return identity, nil
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

	identity, err := c.contract.MAAIdentity(opts, contractReport)
	if err != nil {
		return [32]byte{}, err
	}

	return identity, nil
}

func (c *KmsGovernanceClient) IdentityAllowed(identity [32]byte, operator [20]byte) (bool, error) {
	opts := &bind.CallOpts{Context: context.Background()}

	allowed, err := c.contract.IdentityAllowed(opts, identity, operator)
	if err != nil {
		return false, err
	}

	return allowed, nil
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

	tx, err := c.contract.AllowlistDCAP(c.auth, contractReport)
	if err != nil {
		return nil, err
	}

	return tx, nil
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

	tx, err := c.contract.AllowlistMAA(c.auth, contractReport)
	if err != nil {
		return nil, err
	}

	return tx, nil
}

func (c *KmsGovernanceClient) AllowlistIdentity(identity [32]byte) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	tx, err := c.contract.AllowlistIdentity(c.auth, identity)
	if err != nil {
		return nil, err
	}

	return tx, nil
}

func (c *KmsGovernanceClient) RemoveAllowlistedIdentity(identity [32]byte) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	tx, err := c.contract.RemoveAllowlistedIdentity(c.auth, identity)
	if err != nil {
		return nil, err
	}

	return tx, nil
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

	tx, err := c.contract.RequestOnboard(c.auth, contractRequest)
	if err != nil {
		return nil, err
	}

	return tx, nil
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

	domains, err := c.contract.InstanceDomainNames(opts)
	if err != nil {
		return nil, err
	}

	return domains, nil
}

func (c *KmsGovernanceClient) RegisterInstanceDomainName(domain string) (*types.Transaction, error) {
	if c.auth == nil {
		return nil, ErrNoTransactOpts
	}

	tx, err := c.contract.RegisterInstanceDomainName(c.auth, domain)
	if err != nil {
		return nil, err
	}

	return tx, nil
}
