package cryptoutils

import (
	"bytes"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"

	tdx_abi "github.com/google/go-tdx-guest/abi"
	tdx_client "github.com/google/go-tdx-guest/client"
	tdx_pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
)

var OIDOperatorSignature asn1.ObjectIdentifier = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66704, 98670, 17}

var (
	DCAPAttestation = AttestationType{
		OID:      asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66704, 98645, 1},
		StringID: "qemu-tdx",
	}

	MAAAttestation = AttestationType{
		OID:      asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66704, 98645, 2},
		StringID: "azure-tdx",
	}

	DummyAttestation = AttestationType{
		OID:      asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 66704, 98645, 404},
		StringID: "dummy",
	}
)

type AttestationType struct {
	OID      asn1.ObjectIdentifier
	StringID string
}

func AttestationTypeFromString(str string) (AttestationType, error) {
	switch str {
	case DCAPAttestation.StringID:
		return DCAPAttestation, nil
	case MAAAttestation.StringID:
		return MAAAttestation, nil
	default:
		return AttestationType{}, errors.ErrUnsupported
	}
}

func AttestationTypeFromOID(oid asn1.ObjectIdentifier) (AttestationType, error) {
	if oid.Equal(DCAPAttestation.OID) {
		return DCAPAttestation, nil
	}
	if oid.Equal(MAAAttestation.OID) {
		return MAAAttestation, nil
	}

	return AttestationType{}, errors.ErrUnsupported
}

type AttestationProvider interface {
	AttestationType() AttestationType
	Attest(reportData [64]byte) ([]byte, error)
}

func AttestationProviderForOID(id asn1.ObjectIdentifier) (AttestationProvider, error) {
	if id.Equal(DCAPAttestation.OID) {
		return &DCAPAttestationProvider{}, nil
	}

	return nil, errors.ErrUnsupported
}

type RemoteAttestationProvider struct {
	Address string
}

func (*RemoteAttestationProvider) AttestationType() AttestationType { return DCAPAttestation }

func (p *RemoteAttestationProvider) Attest(reportData [64]byte) ([]byte, error) {
	extraDataHex := hex.EncodeToString(reportData[:])

	url := fmt.Sprintf("%s/attest/%s", p.Address, extraDataHex)
	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("calling remote quote provider: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("remote quote provider returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read the quote
	rawQuote, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading quote from response: %w", err)
	}
	return rawQuote, nil
}

type DCAPAttestationProvider struct{}

func (DCAPAttestationProvider) AttestationType() AttestationType { return DCAPAttestation }

func (DCAPAttestationProvider) Attest(reportData [64]byte) ([]byte, error) {
	qp := &tdx_client.LinuxConfigFsQuoteProvider{}
	if qp.IsSupported() == nil {
		return qp.GetRawQuote(reportData)
	}

	qd, err := tdx_client.OpenDevice()
	if err != nil {
		return nil, err
	}
	defer qd.Close()

	return tdx_client.GetRawQuote(qd, reportData)
}

type DumyAttestationProvider struct{}

func (DumyAttestationProvider) AttestationType() AttestationType {
	return DummyAttestation
}

func (DumyAttestationProvider) Attest(userData [64]byte) ([]byte, error) {
	return []byte(fmt.Sprintf("Attestation for CA %x", userData)), nil
}

func VerifyDCAPAttestation(reportData [64]byte, report []byte) (map[int]string, error) {
	protoQuote, err := tdx_abi.QuoteToProto(report)
	if err != nil {
		return nil, fmt.Errorf("could not parse quote: %w", err)
	}

	v4Quote, err := func() (*tdx_pb.QuoteV4, error) {
		switch q := protoQuote.(type) {
		case *tdx_pb.QuoteV4:
			return q, nil
		default:
			return nil, fmt.Errorf("unsupported quote type: %T", q)
		}
	}()
	if err != nil {
		return nil, err
	}

	options := verify.DefaultOptions()
	// TODO: fetch collateral before verifying to distinguish the error better
	err = verify.TdxQuote(protoQuote, options)
	if err != nil {
		return nil, fmt.Errorf("quote verification failed: %w", err)
	}

	if !bytes.Equal(v4Quote.TdQuoteBody.ReportData, reportData[:]) {
		return nil, fmt.Errorf("invalid report data %x, expected %x", v4Quote.TdQuoteBody.ReportData, reportData[:])
	}

	fmt.Println("attestation validation successful")

	measurements := map[int]string{
		0: hex.EncodeToString(v4Quote.TdQuoteBody.MrTd),
		1: hex.EncodeToString(v4Quote.TdQuoteBody.Rtmrs[0]),
		2: hex.EncodeToString(v4Quote.TdQuoteBody.Rtmrs[1]),
		3: hex.EncodeToString(v4Quote.TdQuoteBody.Rtmrs[2]),
		4: hex.EncodeToString(v4Quote.TdQuoteBody.Rtmrs[3]),
		5: hex.EncodeToString(v4Quote.TdQuoteBody.MrConfigId),
		6: hex.EncodeToString(v4Quote.TdQuoteBody.MrOwner),
		7: hex.EncodeToString(v4Quote.TdQuoteBody.MrOwnerConfig),
	}

	return measurements, nil
}
