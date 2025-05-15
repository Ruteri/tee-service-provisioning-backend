// Package interfaces defines the core interfaces and types for the TEE registry system.
// It provides the contract between different components without implementation details.
package interfaces

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
)

type TLSCSR = cryptoutils.TLSCSR
type TLSCert = cryptoutils.TLSCert
type CACert = cryptoutils.CACert
type AppPubkey = cryptoutils.AppPubkey
type AppPrivkey = cryptoutils.AppPrivkey

// Attestation represents a cryptographic attestation of identity.
type Attestation []byte

// ContractAddress represents an Ethereum contract address.
type ContractAddress [20]byte

// NewContractAddress creates a new contract address from a byte array or hex string.
func NewContractAddressFromBytes(addr []byte) (ContractAddress, error) {
	if len(addr) != 20 {
		return ContractAddress{}, errors.New("invalid address length: must be 20 bytes")
	}

	var res ContractAddress
	copy(res[:], addr)
	return res, nil
}

func NewContractAddressFromHex(addr string) (ContractAddress, error) {
	// Remove 0x prefix if present
	clean := strings.TrimPrefix(addr, "0x")
	if len(clean) != 40 {
		return ContractAddress{}, errors.New("invalid address length: hex string must be 40 characters")
	}

	// Validate hex format
	addrBytes, err := hex.DecodeString(clean)
	if err != nil {
		return ContractAddress{}, fmt.Errorf("invalid hex format: %w", err)
	}

	return NewContractAddressFromBytes(addrBytes)
}

// String returns the hex string representation of the contract address.
func (addr ContractAddress) String() string {
	return hex.EncodeToString(addr[:])
}

// Bytes returns the raw 20-byte address.
func (addr ContractAddress) Bytes() []byte {
	return addr[:]
}

// Equal compares two contract addresses for equality.
func (addr ContractAddress) Equal(other ContractAddress) bool {
	return addr == other
}

// AppCommonName represents a common name for an application certificates.
type AppCommonName string

// NewAppCommonName creates a new common name with validation.
func NewAppCommonName(addr ContractAddress) AppCommonName {
	return AppCommonName(addr.String() + ".app")
}

// String returns the domain name as a string.
func (name AppCommonName) String() string {
	return string(name)
}

// String returns the domain name as a string.
func (name AppCommonName) Address() (ContractAddress, error) {
	if len(name) != 44 {
		return ContractAddress{}, errors.New("invalid app cn")
	}
	return NewContractAddressFromHex(string(name[:40]))
}

// AppDomainName represents a domain name for an application instance.
type AppDomainName string

// NewAppDomainName creates a new domain name with validation.
func NewAppDomainName(domain string) (AppDomainName, error) {
	// Basic domain name validation (simplified version)
	domainRegex := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+([a-zA-Z]{2,}|$|:[0-9]{2,6}$)?`)
	if !domainRegex.MatchString(domain) {
		return AppDomainName(""), errors.New("invalid domain name format")
	}

	return AppDomainName(domain), nil
}

// String returns the domain name as a string.
func (name AppDomainName) String() string {
	return string(name)
}

// Validate checks if the domain name has a valid format.
func (name AppDomainName) Validate() error {
	_, err := NewAppDomainName(string(name))
	return err
}

// Validate checks if the domain name has a valid format.
func (name AppCommonName) Validate() error {
	_, err := name.Address()
	return err
}

// DCAPReport represents a Direct Capability Attestation Protocol report.
// It contains measurement registers that uniquely identify a TEE instance.
type DCAPReport struct {
	MrTd          [48]byte
	RTMRs         [4][48]byte
	MrOwner       [48]byte
	MrConfigId    [48]byte
	MrConfigOwner [48]byte
}

func DCAPReportFromMeasurement(measurements map[int]string) (*DCAPReport, error) {
	dcapReport := &DCAPReport{}

	mrtdHex, ok := measurements[0]
	if !ok {
		return nil, fmt.Errorf("mrtd missing")
	}
	mrtd, err := hex.DecodeString(mrtdHex)
	if err != nil {
		return nil, fmt.Errorf("could not decode mrtd measurement value %x: %w", mrtdHex, err)
	}
	if len(mrtd) != 48 {
		return nil, fmt.Errorf("invalid mrtd measurement value %x", mrtd)
	}

	copy(dcapReport.MrTd[:], mrtd)

	for rtmr := 0; rtmr < 3; rtmr += 1 {
		rtmrHex, ok := measurements[1+rtmr]
		if !ok {
			return nil, fmt.Errorf("rtmr %d missing", rtmr)
		}
		rtmrBytes, err := hex.DecodeString(rtmrHex)
		if err != nil {
			return nil, fmt.Errorf("could not decode rtmr %d measurement value %x: %w", rtmr, rtmrHex, err)
		}
		if len(rtmrBytes) != 48 {
			return nil, fmt.Errorf("invalid rtmr %d value %x", rtmr, rtmrBytes)
		}
		copy(dcapReport.RTMRs[rtmr][:], rtmrBytes)
	}
	return dcapReport, nil
}

type AppSecrets struct {
	AppPrivkey  AppPrivkey      `json:"app_privkey"`
	TLSCert     TLSCert         `json:"tls_cert"`
	Operator    ContractAddress `json:"operator"`
	Attestation Attestation     `json:"attestation"`
}

func (s *AppSecrets) ReportData(appAddr ContractAddress) [64]byte {
	var reportData [64]byte
	secretsHash := sha256.Sum256(append(s.Operator[:], append(s.TLSCert, s.AppPrivkey...)...))
	copy(reportData[:20], appAddr[:])
	copy(reportData[20:], secretsHash[:])
	return reportData
}
