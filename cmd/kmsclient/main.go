package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/ethereum/go-ethereum/accounts/abi/bind/v2"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ruteri/tee-service-provisioning-backend/api/kmshandler"
	"github.com/ruteri/tee-service-provisioning-backend/api/pkihandler"
	"github.com/ruteri/tee-service-provisioning-backend/cmd/flags"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/ruteri/tee-service-provisioning-backend/kms"
	"github.com/ruteri/tee-service-provisioning-backend/kmsgovernance"
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

var flagOnboardedServer *cli.StringFlag = &cli.StringFlag{
	Name:  "kms-onboarded-addr",
	Value: "http://127.0.0.1:8081",
	Usage: "Bootstraping KMS server address to onboard",
}
var flagOnboardingServer *cli.StringFlag = &cli.StringFlag{
	Name:  "kms-onboarding-addr",
	Value: "http://127.0.0.1:8081",
	Usage: "Already bootstrapped KMS server address to onboard with",
}

var flagCSR *cli.StringFlag = &cli.StringFlag{
	Name:  "csr",
	Usage: "Path to CSR file. If empty a random one will be sent.",
}

var flagOperatorPrivkey *cli.StringFlag = &cli.StringFlag{
	Name:    "operator-key",
	EnvVars: []string{"OPERATOR_KEY"},
	Usage:   "Operator ethereum signing key to use for onboarding",
}

func main() {
	app := &cli.App{
		Name:           "kms client",
		Usage:          "",
		DefaultCommand: "pki",
		Flags:          []cli.Flag{},
		Commands: []*cli.Command{
			&cli.Command{
				Name:        "pki",
				Usage:       "",
				Description: "",
				Flags: []cli.Flag{
					flags.FlagAppAddr,
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
					flags.FlagAppAddr,
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
			&cli.Command{
				Name:        "generate",
				Usage:       "",
				Description: "Requests non-bootstrapped KMS to generate a random seed (simplekms only, for shamir see cmd/admin)",
				Flags: []cli.Flag{
					flagOnboardingServer,
				},
				Action: func(cCtx *cli.Context) error {
					onboardingUrl := cCtx.String(flagOnboardingServer.Name)
					resp, err := http.DefaultClient.Post(fmt.Sprintf("%s/api/operator/generate", onboardingUrl), "application/octet-stream", nil)
					if err != nil {
						return fmt.Errorf("could not request generating seed: %w", err)
					}
					if resp.StatusCode != http.StatusOK {
						body, _ := io.ReadAll(resp.Body)
						return fmt.Errorf("kms returned %d: %s", resp.StatusCode, string(body))
					}
					log.Println("OK")
					return nil
				},
			},
			&cli.Command{
				Name:        "authorize",
				Usage:       "",
				Description: "",
				Flags: []cli.Flag{
					flagOnboardingServer,
					flagOperatorPrivkey,
				},
				Action: func(cCtx *cli.Context) error {
					operatorPrivkey, err := crypto.HexToECDSA(cCtx.String(flagOperatorPrivkey.Name))
					if err != nil {
						return fmt.Errorf("could not parse operator privkey: %w", err)
					}

					onboardingUrl := cCtx.String(flagOnboardingServer.Name)
					nonceResp, err := http.DefaultClient.Get(fmt.Sprintf("%s/api/operator/auth", onboardingUrl))
					if err != nil {
						return fmt.Errorf("could not request nonce: %w", err)
					}

					nonce, err := io.ReadAll(nonceResp.Body)
					nonceResp.Body.Close()
					if err != nil {
						return fmt.Errorf("could not read nonce response: %w", err)
					}

					signedNonce, err := crypto.Sign(nonce, operatorPrivkey)
					if err != nil {
						return fmt.Errorf("could not sign nonce: %w", err)
					}

					authResp, err := http.DefaultClient.Post(fmt.Sprintf("%s/api/operator/auth", onboardingUrl), "application/octet-stream", bytes.NewBuffer(signedNonce))
					if err != nil {
						return fmt.Errorf("could not request authorization: %w", err)
					}

					authRespBody, _ := io.ReadAll(authResp.Body)
					authResp.Body.Close()

					if authResp.StatusCode != http.StatusOK {
						return fmt.Errorf("authorization returned %d: %s", authResp.StatusCode, string(authRespBody))
					}

					fmt.Println("OK")
					return nil
				},
			},
			&cli.Command{
				Name:        "onboard",
				Usage:       "",
				Description: "",
				Flags: []cli.Flag{
					flags.FlagAppAddr,
					flagOnboardedServer,
					flagOnboardingServer,
					flagOperatorPrivkey,
					flags.RpcAddrFlag,
				},
				Action: func(cCtx *cli.Context) error {
					contractAddr, err := interfaces.NewContractAddressFromHex(cCtx.String(flags.FlagAppAddr.Name))
					if err != nil {
						return fmt.Errorf("could not parse kms governance contract address: %w", err)
					}

					operatorPrivkey, err := crypto.HexToECDSA(cCtx.String(flagOperatorPrivkey.Name))
					if err != nil {
						return fmt.Errorf("could not parse operator privkey: %w", err)
					}

					opreatorAddress := crypto.PubkeyToAddress(operatorPrivkey.PublicKey)

					onboardingUrl := cCtx.String(flagOnboardingServer.Name)
					onboardRequestResp, err := http.DefaultClient.Get(fmt.Sprintf("%s/api/operator/onboard_request/%s", onboardingUrl, hex.EncodeToString(opreatorAddress.Bytes())))
					if err != nil {
						return fmt.Errorf("could not request onboarding message: %w", err)
					}

					onboardRequestBody, err := io.ReadAll(onboardRequestResp.Body)
					if err != nil {
						return fmt.Errorf("could not read onboard request response: %w", err)
					}
					if onboardRequestResp.StatusCode != http.StatusOK {
						return fmt.Errorf("could not prepare onboard request: onboarding kms returned %d: %s", onboardRequestResp.StatusCode, string(onboardRequestBody))
					}

					var onboardRequest interfaces.OnboardRequest
					err = json.Unmarshal(onboardRequestBody, &onboardRequest)
					if err != nil {
						return fmt.Errorf("could not unmarshal onboarding request: %w", err)
					}

					rpcUrl := cCtx.String(flags.RpcAddrFlag.Name)
					ethClient, err := ethclient.Dial(rpcUrl)
					chainId, err := ethClient.ChainID(context.Background())
					if err != nil {
						return fmt.Errorf("could not fetch chain id from ethclient: %w", err)
					}

					onboardRequestHash, err := kms.OnboardRequestHash(onboardRequest)
					if err != nil {
						return fmt.Errorf("could not hash onboard request: %w", err)
					}

					kmsGovernance, err := kmsgovernance.NewKmsGovernanceClient(ethClient, ethClient, common.Address(contractAddr))
					if err != nil {
						return fmt.Errorf("could not initialize kms governance client: %w", err)
					}

					onchainRequest, err := kmsGovernance.FetchOnboardRequest(onboardRequestHash)
					if err != nil || onchainRequest.Nonce.Cmp(onboardRequest.Nonce) != 0 {
						kmsGovernance.SetTransactOpts(bind.NewKeyedTransactor(operatorPrivkey, chainId))
						tx, err := kmsGovernance.RequestOnboard(onboardRequest)
						if err != nil {
							return fmt.Errorf("could not request onboard message: %w", err)
						}

						_, err = bind.WaitMined(context.Background(), ethClient, tx.Hash())
						if err != nil {
							return fmt.Errorf("could not mine onboard request: %w", err)
						}
					}

					bootstrappedUrl := cCtx.String(flagOnboardedServer.Name)
					onboardResp, err := http.DefaultClient.Post(fmt.Sprintf("%s/api/operator/onboard", onboardingUrl), "application/octet-stream", bytes.NewBufferString(bootstrappedUrl))
					if err != nil {
						return fmt.Errorf("could not request to onboard: %w", err)
					}

					if onboardResp.StatusCode != http.StatusOK {
						body, _ := io.ReadAll(onboardResp.Body)
						return fmt.Errorf("could not onboard: onboarding kms returned %d: %s", onboardResp.StatusCode, string(body))
					}
					return nil
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
