package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/ruteri/tee-service-provisioning-backend/api"
	"github.com/ruteri/tee-service-provisioning-backend/api/clients"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/urfave/cli/v2"
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
	&cli.StringFlag{
		Name:  "debug-set-attestation-type-header",
		Usage: "If provided the provisioner will set the attestation type header",
	},
	&cli.StringFlag{
		Name:  "debug-set-attestation-measurement-header",
		Usage: "If provided the provisioner will set the attestation measurement header",
	},
}

const usage string = ``

func main() {
	app := &cli.App{
		Name:  "registry client",
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
	AppContract    interfaces.ContractAddress
	RegistrationProvider api.RegistrationProvider
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
		AppContract: appContract,
		RegistrationProvider: registrationProvider,
	}, nil
}

func (p *Provisioner) Do() error {
		_, csr, err := cryptoutils.CreateCSRWithRandomKey(string(interfaces.NewAppCommonName(p.AppContract)))
		if err != nil {
			return fmt.Errorf("could not create instance CSR: %w", err)
		}

		parsedResponse, err := p.RegistrationProvider.Register(p.AppContract, csr)
		if err != nil {
			return fmt.Errorf("registration failed: %w", err)
		}
		encodedRegistrationResp, _ := json.Marshal(parsedResponse)
		fmt.Println(string(encodedRegistrationResp))
		return nil
}
