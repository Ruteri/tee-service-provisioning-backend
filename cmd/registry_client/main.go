package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/ruteri/tee-service-provisioning-backend/api"
	"github.com/ruteri/tee-service-provisioning-backend/api/provisioner"
	"github.com/ruteri/tee-service-provisioning-backend/cmd/flags"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/urfave/cli/v2"
)

var flagServerAddr *cli.StringFlag = &cli.StringFlag{
	Name:  "provisioning-server-addr",
	Value: "http://127.0.0.1:8080",
	Usage: "Provisioning server address to request",
}

const usage string = ``

func main() {
	app := &cli.App{
		Name:  "registry client",
		Usage: usage,
		Flags: []cli.Flag{
			flags.FlagAppAddr,
			flagServerAddr,
		},
		Commands: []*cli.Command{
			&cli.Command{
				Name:        "register",
				Usage:       "",
				Description: "",
				Flags: []cli.Flag{
					flags.FlagAttsetationType,
					flags.FlagAttsetationMeasurement,
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
					flags.FlagAttsetationType,
					flags.FlagAttsetationMeasurement,
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
	appContract, err := interfaces.NewContractAddressFromHex(cCtx.String(flags.FlagAppAddr.Name))
	if err != nil {
		return nil, fmt.Errorf("could not parse app contract address: %w", err)
	}

	registrationProvider := &provisioner.ProvisioningClient{
		ServerAddr:                cCtx.String(flagServerAddr.Name),
		SetAttestationType:        cCtx.String(flags.FlagAttsetationType.Name),
		SetAttestationMeasurement: cCtx.String(flags.FlagAttsetationMeasurement.Name),
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

	expectedReportData := api.ReportData(c.AppContract, parsedResponse.CACert, parsedResponse.AppPubkey)
	_, err = cryptoutils.VerifyDCAPAttestation(expectedReportData, parsedResponse.Attestation)
	if err != nil {
		return fmt.Errorf("metadata attestation verification failed: %w", err)
	}

	return nil
}
