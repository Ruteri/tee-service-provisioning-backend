package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/ruteri/tee-service-provisioning-backend/api"
	"github.com/ruteri/tee-service-provisioning-backend/api/clients"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/urfave/cli/v2"

	tdx_abi "github.com/google/go-tdx-guest/abi"
	tdx_pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
)

var flagServerAddr *cli.StringFlag = &cli.StringFlag{
	Name:  "provisioning-server-addr",
	Value: "http://127.0.0.1:8080",
	Usage: "Provisioning server address to request",
}
var flagAppAddr *cli.StringFlag = &cli.StringFlag{
	Name:     "app-contract",
	Required: true,
	Usage:    "Application governance contract address to request provisioning for. 40-char hex string with no 0x prefix",
}
var flagAttsetationType *cli.StringFlag = &cli.StringFlag{
	Name:  "debug-set-attestation-type-header",
	Usage: "If provided the provisioner will set the attestation type header",
}
var flagAttsetationMeasurement *cli.StringFlag = &cli.StringFlag{
	Name:  "debug-set-attestation-measurement-header",
	Usage: "If provided the provisioner will set the attestation measurement header",
}

const usage string = ``

func main() {
	app := &cli.App{
		Name:  "registry client",
		Usage: usage,
		Flags: []cli.Flag{
			flagAppAddr,
			flagServerAddr,
		},
		Commands: []*cli.Command{
			&cli.Command{
				Name:        "register",
				Usage:       "",
				Description: "",
				Flags: []cli.Flag{
					flagAttsetationType,
					flagAttsetationMeasurement,
				},
				Action: func(cCtx *cli.Context) error {
					c, err := NewClientConfig(cCtx)
					if err != nil {
						return err
					}
					return c.Register()
				},
			},
			&cli.Command{
				Name:        "metadata",
				Usage:       "",
				Description: "",
				Flags: []cli.Flag{
					flagAttsetationType,
					flagAttsetationMeasurement,
				},
				Action: func(cCtx *cli.Context) error {
					c, err := NewClientConfig(cCtx)
					if err != nil {
						return err
					}
					return c.GetAppMetadata()
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

type Client struct {
	AppContract interfaces.ContractAddress
	Provider    interface {
		api.MetadataProvider
		api.RegistrationProvider
	}
}

func NewClientConfig(cCtx *cli.Context) (*Client, error) {
	appContract, err := interfaces.NewContractAddressFromHex(cCtx.String(flagAppAddr.Name))
	if err != nil {
		return nil, fmt.Errorf("could not parse app contract address: %w", err)
	}

	registrationProvider := &clients.ProvisioningClient{
		ServerAddr:                cCtx.String(flagServerAddr.Name),
		SetAttestationType:        cCtx.String(flagAttsetationType.Name),
		SetAttestationMeasurement: cCtx.String(flagAttsetationType.Name),
	}

	return &Client{
		AppContract: appContract,
		Provider:    registrationProvider,
	}, nil
}

func (c *Client) Register() error {
	_, csr, err := cryptoutils.CreateCSRWithRandomKey(string(interfaces.NewAppCommonName(c.AppContract)))
	if err != nil {
		return fmt.Errorf("could not create instance CSR: %w", err)
	}

	parsedResponse, err := c.Provider.Register(c.AppContract, csr)
	if err != nil {
		return fmt.Errorf("registration failed: %w", err)
	}
	encodedRegistrationResp, _ := json.Marshal(parsedResponse)
	fmt.Println(string(encodedRegistrationResp))
	return nil
}

func (c *Client) GetAppMetadata() error {
	parsedResponse, err := c.Provider.GetAppMetadata(c.AppContract)
	if err != nil {
		return fmt.Errorf("metadata request failed: %w", err)
	}
	encodedResp, _ := json.Marshal(parsedResponse)
	fmt.Println(string(encodedResp))

	err = VerifyDCAPAttestation(c.AppContract, parsedResponse)
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
