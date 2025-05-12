package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/ruteri/tee-service-provisioning-backend/api/kmshandler"
	"github.com/ruteri/tee-service-provisioning-backend/api/pkihandler"
	"github.com/ruteri/tee-service-provisioning-backend/cmd/flags"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/urfave/cli/v2"
)

var flagSecretsServer *cli.StringFlag = &cli.StringFlag{
	Name:  "kms-server-addr",
	Value: "http://127.0.0.1:8081",
	Usage: "KMS secrets server address to request",
}

var flagPKIServer *cli.StringFlag = &cli.StringFlag{
	Name:  "pki-server-addr",
	Value: "http://127.0.0.1:8081",
	Usage: "KMS PKI server address to request",
}

var flagCSR *cli.StringFlag = &cli.StringFlag{
	Name:  "csr",
	Usage: "Path to CSR file. If empty a random one will be sent.",
}

func main() {
	app := &cli.App{
		Name:           "kms client",
		Usage:          "",
		DefaultCommand: "pki",
		Flags: []cli.Flag{
			flags.FlagAppAddr,
		},
		Commands: []*cli.Command{
			&cli.Command{
				Name:        "pki",
				Usage:       "",
				Description: "",
				Flags: []cli.Flag{
					flagPKIServer,
				},
				Action: func(cCtx *cli.Context) error {
					contractAddr, err := interfaces.NewContractAddressFromHex(cCtx.String(flags.FlagAppAddr.Name))
					if err != nil {
						return err
					}

					pki, err := pkihandler.PKI(cCtx.String(flagPKIServer.Name), contractAddr)
					if err != nil {
						return err
					}

					encodedPki, err := json.Marshal(pki)
					if err != nil {
						return err
					}
					fmt.Println(string(encodedPki))
					return nil
				},
			},
			&cli.Command{
				Name:        "secrets",
				Usage:       "",
				Description: "",
				Flags: []cli.Flag{
					flagSecretsServer,
					flagCSR,
					flags.FlagAttsetationType,
					flags.FlagAttsetationMeasurement,
				},
				Action: func(cCtx *cli.Context) error {
					contractAddr, err := interfaces.NewContractAddressFromHex(cCtx.String(flags.FlagAppAddr.Name))
					if err != nil {
						return err
					}

					sp := *kmshandler.DefaultSecretsProvider
					sp.DebugAttestationTypeHeader = cCtx.String(flags.FlagAttsetationType.Name)
					sp.DebugMeasurementsHeader = cCtx.String(flags.FlagAttsetationMeasurement.Name)

					var csr interfaces.TLSCSR
					csrPath := cCtx.String(flagCSR.Name)
					if csrPath == "" {
						_, csr, err = cryptoutils.CreateCSRWithRandomKey(interfaces.NewAppCommonName(contractAddr).String())
					} else {
						csr, err = os.ReadFile(csrPath)
					}

					if err != nil {
						return err
					}

					secrets, err := sp.AppSecrets(cCtx.String(flagSecretsServer.Name), contractAddr, csr)
					if err != nil {
						return err
					}

					encodedSecrets, err := json.Marshal(secrets)
					if err != nil {
						return err
					}
					fmt.Println(string(encodedSecrets))
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
