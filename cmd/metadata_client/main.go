package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/ruteri/tee-service-provisioning-backend/api"
	"github.com/ruteri/tee-service-provisioning-backend/api/clients"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/urfave/cli/v2"

	tdx_abi "github.com/google/go-tdx-guest/abi"
	tdx_pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
)

var flags []cli.Flag = []cli.Flag{
	&cli.StringFlag{
		Name:  "provisioning-server-addr",
		Value: "http://127.0.0.1:8080",
		Usage: "Provisioning server address to request",
	},
	&cli.StringFlag{
		Name:     "app-contract",
		Required: true,
		Usage:    "Application governance contract address to request provisioning for. 40-char hex string with no 0x prefix",
	},
}

const usage string = ``

func main() {
	app := &cli.App{
		Name:  "metadata client",
		Usage: usage,
		Flags: flags,
		Action: func(cCtx *cli.Context) error {
			provisioner, err := NewProvisioner(cCtx)
			if err != nil {
				return err
			}

			return provisioner.Do()
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

type Provisioner struct {
	AppContract      interfaces.ContractAddress
	MetadataProvider api.MetadataProvider
}

func NewProvisioner(cCtx *cli.Context) (*Provisioner, error) {
	appContract, err := interfaces.NewContractAddressFromHex(cCtx.String("app-contract"))
	if err != nil {
		return nil, fmt.Errorf("could not parse app contract address: %w", err)
	}

	registrationProvider := &clients.ProvisioningClient{
		ServerAddr:                cCtx.String("provisioning-server-addr"),
		SetAttestationType:        cCtx.String("debug-set-attestation-type-header"),
		SetAttestationMeasurement: cCtx.String("debug-set-attestation-measurement-header"),
	}

	return &Provisioner{
		AppContract:      appContract,
		MetadataProvider: registrationProvider,
	}, nil
}

func (p *Provisioner) Do() error {
	parsedResponse, err := p.MetadataProvider.GetAppMetadata(p.AppContract)
	if err != nil {
		return fmt.Errorf("metadata request failed: %w", err)
	}
	encodedResp, _ := json.Marshal(parsedResponse)
	fmt.Println(string(encodedResp))

	err = VerifyDCAPAttestation(p.AppContract, parsedResponse)
	if err != nil {
		return fmt.Errorf("metadata attestation verification failed: %w", err)
	}

	return nil
}

func VerifyDCAPAttestation(contractAddr interfaces.ContractAddress, resp *api.MetadataResponse) error {
	protoQuote, err := tdx_abi.QuoteToProto(resp.Attestation)
	if err != nil {
		return fmt.Errorf("could not parse quote: %w", err)
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
		return err
	}

	options := verify.DefaultOptions()
	// TODO: fetch collateral before verifying to distinguish the error better
	err = verify.TdxQuote(protoQuote, options)
	if err != nil {
		return fmt.Errorf("quote verification failed: %w", err)
	}

	expectedReportData := api.ReportData(contractAddr, resp.CACert, resp.AppPubkey)
	if !bytes.Equal(v4Quote.TdQuoteBody.ReportData, expectedReportData[:]) {
		return fmt.Errorf("invalid report data %x, expected %x", v4Quote.TdQuoteBody.ReportData, expectedReportData[:])
	}

	fmt.Println("attestation validation successful")

	return nil
}
