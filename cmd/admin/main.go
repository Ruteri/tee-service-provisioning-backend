package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"os"

	"github.com/ruteri/tee-service-provisioning-backend/api/clients"
	"github.com/ruteri/tee-service-provisioning-backend/api/handlers"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/urfave/cli/v2"
)

var flagProvisioningServer *cli.StringFlag = &cli.StringFlag{
	Name:  "provisioning-server-addr",
	Value: "http://127.0.0.1:8080/admin",
	Usage: "Provisioning server address to request",
}
var flagAdminPrivkey *cli.StringFlag = &cli.StringFlag{
	Name:  "admin-privkey-file",
	Value: "admin-private.pem",
	Usage: "Path to admin private key",
}
var flagAdminPubkey *cli.StringFlag = &cli.StringFlag{
	Name:  "admin-pubkey-file",
	Value: "admin-public.pem",
	Usage: "Path to admin public key",
}
var flagShamirAdmins *cli.StringFlag = &cli.StringFlag{
	Name:  "shamir-admins-file",
	Value: "shamir-admins.json",
	Usage: "Path to file to use for shamir KMS configuration",
}
var flagShamirShare *cli.StringFlag = &cli.StringFlag{
	Name:  "shamir-share-file",
	Value: "shamir-share.json",
	Usage: "Path to file to use for shamir share",
}

var flagShamirThreshold *cli.IntFlag = &cli.IntFlag{
	Name:  "shamir-threshold",
	Value: 2,
}

var flagShamirTotal *cli.IntFlag = &cli.IntFlag{
	Name:  "shamir-total-shares",
	Value: 2,
}

func main() {
	app := &cli.App{
		Name:           "admin client",
		Usage:          "",
		DefaultCommand: "status",
		Commands: []*cli.Command{
			&cli.Command{
				Name:        "status",
				Usage:       "",
				Description: "",
				Flags: []cli.Flag{
					flagProvisioningServer,
				},
				Action: func(cCtx *cli.Context) error {
					baseURL := cCtx.String(flagProvisioningServer.Name)
					adminClient := clients.NewAdminClient(baseURL, "", nil)
					status, err := adminClient.GetStatus()
					if err != nil {
						return err
					}

					fmt.Println(status)
					return nil
				},
			},
			&cli.Command{
				Name:        "generate-admin",
				Usage:       "",
				Description: "",
				Flags: []cli.Flag{
					flagAdminPrivkey,
					flagAdminPubkey,
				},
				Action: func(cCtx *cli.Context) error {
					privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
					if err != nil {
						return fmt.Errorf("failed to generate ECDSA key: %w", err)
					}

					// Convert private key to PEM
					privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
					if err != nil {
						return fmt.Errorf("failed to marshal private key: %w", err)
					}

					privateKeyPEM := pem.EncodeToMemory(&pem.Block{
						Type:  "EC PRIVATE KEY",
						Bytes: privateKeyBytes,
					})

					// Convert public key to PEM
					publicKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
					if err != nil {
						return fmt.Errorf("failed to marshal public key: %w", err)
					}

					publicKeyPEM := pem.EncodeToMemory(&pem.Block{
						Type:  "PUBLIC KEY",
						Bytes: publicKeyBytes,
					})

					if err := os.WriteFile(cCtx.String(flagAdminPrivkey.Name), privateKeyPEM, 0600); err != nil {
						return err
					}

					if err := os.WriteFile(cCtx.String(flagAdminPubkey.Name), publicKeyPEM, 0600); err != nil {
						return err
					}

					return nil
				},
			},
			&cli.Command{
				Name:        "generate-shamir-config",
				Usage:       "",
				Description: "",
				Flags: []cli.Flag{
					flagShamirAdmins,
					&cli.StringSliceFlag{
						Name: "admin-pubkey-files",
					},
				},
				Action: func(cCtx *cli.Context) error {
					config := handlers.ShamirAdminsConfig{}

					for _, pubkey := range cCtx.StringSlice("admin-pubkey-files") {
						publicKeyPEM, err := os.ReadFile(pubkey)
						if err != nil {
							return err
						}

						pubkeyHash := sha256.Sum256(publicKeyPEM)
						config.Admins = append(config.Admins, handlers.ShamirAdminMetadata{
							ID:     hex.EncodeToString(pubkeyHash[:]),
							PubKey: string(publicKeyPEM),
						})
					}

					configBytes, err := json.Marshal(config)
					if err != nil {
						return err
					}

					if err := os.WriteFile(cCtx.String(flagShamirAdmins.Name), configBytes, 0600); err != nil {
						return err
					}

					return nil
				},
			},
			&cli.Command{
				Name:        "init-generate-shares",
				Usage:       "",
				Description: "",
				Flags: []cli.Flag{
					flagProvisioningServer,
					flagAdminPrivkey,
					flagAdminPubkey,
					flagShamirShare,
					flagShamirTotal,
					flagShamirThreshold,
				},
				Action: func(cCtx *cli.Context) error {
					baseURL := cCtx.String(flagProvisioningServer.Name)
					publicKeyPEM, err := os.ReadFile(cCtx.String(flagAdminPubkey.Name))
					if err != nil {
						return err
					}

					pubkeyHash := sha256.Sum256(publicKeyPEM)
					adminID := hex.EncodeToString(pubkeyHash[:])

					privateKeyPEM, err := os.ReadFile(cCtx.String(flagAdminPrivkey.Name))
					if err != nil {
						return err
					}

					pkBlock, _ := pem.Decode(privateKeyPEM)
					privateKey, err := x509.ParseECPrivateKey(pkBlock.Bytes)
					if err != nil {
						return err
					}

					sharesTotal := cCtx.Int(flagShamirTotal.Name)
					sharesThreshold := cCtx.Int(flagShamirThreshold.Name)

					adminClient := clients.NewAdminClient(baseURL, adminID, privateKey)
					_, err = adminClient.InitGenerate(sharesThreshold, sharesTotal)
					return err
				},
			},
			&cli.Command{
				Name:        "init-recovery",
				Usage:       "",
				Description: "",
				Flags: []cli.Flag{
					flagProvisioningServer,
					flagAdminPrivkey,
					flagAdminPubkey,
					flagShamirShare,
					flagShamirThreshold,
				},
				Action: func(cCtx *cli.Context) error {
					baseURL := cCtx.String(flagProvisioningServer.Name)
					publicKeyPEM, err := os.ReadFile(cCtx.String(flagAdminPubkey.Name))
					if err != nil {
						return err
					}

					pubkeyHash := sha256.Sum256(publicKeyPEM)
					adminID := hex.EncodeToString(pubkeyHash[:])

					privateKeyPEM, err := os.ReadFile(cCtx.String(flagAdminPrivkey.Name))
					if err != nil {
						return err
					}

					pkBlock, _ := pem.Decode(privateKeyPEM)
					privateKey, err := x509.ParseECPrivateKey(pkBlock.Bytes)
					if err != nil {
						return err
					}

					sharesThreshold := cCtx.Int(flagShamirThreshold.Name)

					adminClient := clients.NewAdminClient(baseURL, adminID, privateKey)
					return adminClient.InitRecover(sharesThreshold)
				},
			},
			&cli.Command{
				Name:        "fetch-admin-share",
				Usage:       "",
				Description: "",
				Flags: []cli.Flag{
					flagProvisioningServer,
					flagAdminPrivkey,
					flagAdminPubkey,
					flagShamirShare,
				},
				Action: func(cCtx *cli.Context) error {
					baseURL := cCtx.String(flagProvisioningServer.Name)
					publicKeyPEM, err := os.ReadFile(cCtx.String(flagAdminPubkey.Name))
					if err != nil {
						return err
					}

					pubkeyHash := sha256.Sum256(publicKeyPEM)
					adminID := hex.EncodeToString(pubkeyHash[:])

					privateKeyPEM, err := os.ReadFile(cCtx.String(flagAdminPrivkey.Name))
					if err != nil {
						return err
					}

					pkBlock, _ := pem.Decode(privateKeyPEM)
					privateKey, err := x509.ParseECPrivateKey(pkBlock.Bytes)
					if err != nil {
						return err
					}

					adminClient := clients.NewAdminClient(baseURL, adminID, privateKey)
					shareResponse, err := adminClient.FetchShare()
					if err != nil {
						return err
					}

					shareResponseJSON, err := json.Marshal(shareResponse)
					if err != nil {
						return err
					}

					return os.WriteFile(cCtx.String(flagShamirShare.Name), shareResponseJSON, 0600)
				},
			},
			&cli.Command{
				Name:        "submit-admin-share",
				Usage:       "",
				Description: "",
				Flags: []cli.Flag{
					flagProvisioningServer,
					flagAdminPrivkey,
					flagAdminPubkey,
					flagShamirShare,
				},
				Action: func(cCtx *cli.Context) error {
					baseURL := cCtx.String(flagProvisioningServer.Name)
					publicKeyPEM, err := os.ReadFile(cCtx.String(flagAdminPubkey.Name))
					if err != nil {
						return err
					}

					pubkeyHash := sha256.Sum256(publicKeyPEM)
					adminID := hex.EncodeToString(pubkeyHash[:])

					privateKeyPEM, err := os.ReadFile(cCtx.String(flagAdminPrivkey.Name))
					if err != nil {
						return err
					}

					pkBlock, _ := pem.Decode(privateKeyPEM)
					privateKey, err := x509.ParseECPrivateKey(pkBlock.Bytes)
					if err != nil {
						return err
					}

					shareResponseJSON, err := os.ReadFile(cCtx.String(flagShamirShare.Name))
					if err != nil {
						return err
					}

					var shareData handlers.AdminGetShareResponse 
					err = json.Unmarshal(shareResponseJSON, &shareData)
					if err != nil {
						return err
					}

					rawEncryptedShare, err := base64.StdEncoding.DecodeString(shareData.EncryptedShare)
					if err != nil {
						return err
					}

					rawShare, err := cryptoutils.DecryptWithPrivateKey(privateKeyPEM, rawEncryptedShare)
					if err != nil {
						return err
					}

					adminClient := clients.NewAdminClient(baseURL, adminID, privateKey)
					err = adminClient.SubmitShare(shareData.ShareIndex, base64.StdEncoding.EncodeToString(rawShare), nil)
					if err != nil {
						return err
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
