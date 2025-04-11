package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/urfave/cli/v2"
)

var flagInstanceAddr *cli.StringFlag = &cli.StringFlag{
	Name:  "instance-addr",
	Value: "https://127.0.0.1:8082",
	Usage: "Instance to connect to",
}
var flagPrivateKey *cli.StringFlag = &cli.StringFlag{
	Name:     "privkey",
	Required: true,
	EnvVars:  []string{"OPERATOR_PRIVKEY"},
	Usage:    "Private key to use for signing",
}
var flagInsecureTLS *cli.BoolFlag = &cli.BoolFlag{
	Name:  "insecure-tls",
	Value: true,
	Usage: "Skip TLS verification (not recommended for production, use cvm proxy instead)",
}

func main() {
	app := &cli.App{
		Name:  "operator client",
		Usage: "",
		Flags: []cli.Flag{
			flagInstanceAddr,
			flagInsecureTLS,
			flagPrivateKey,
		},
		Commands: []*cli.Command{
			&cli.Command{
				Name:        "sign-pubkey",
				Usage:       "",
				Description: "",
				Action: func(cCtx *cli.Context) error {
					privateKey, err := crypto.HexToECDSA(cCtx.String(flagPrivateKey.Name))
					if err != nil {
						return fmt.Errorf("failed to parse private key: %w", err)
					}

					// Create HTTP client with optional TLS verification skip
					client := &http.Client{}
					if cCtx.Bool(flagInsecureTLS.Name) {
						client.Transport = &http.Transport{
							TLSClientConfig: &tls.Config{
								InsecureSkipVerify: true,
							},
						}
					}

					return SubmitOperatorSignature(privateKey, client, cCtx.String(flagInstanceAddr.Name))
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func SubmitOperatorSignature(privateKey *ecdsa.PrivateKey, client *http.Client, serverAddr string) error {
	// Get the instance public key hash
	resp, err := client.Get(fmt.Sprintf("%s/instance_pubkey", serverAddr))
	if err != nil {
		return fmt.Errorf("failed to get instance public key: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned error: %s", string(msg))
	}

	pubkeyHash, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response: %w", err)
	}

	// Show address that will sign
	address := crypto.PubkeyToAddress(privateKey.PublicKey)
	fmt.Printf("Signing with address: %s\n", address.Hex())
	fmt.Printf("Message to sign: %s\n", hexutil.Encode(pubkeyHash))

	// Sign the public key hash
	signature, err := crypto.Sign(pubkeyHash, privateKey)
	if err != nil {
		return fmt.Errorf("failed to sign message: %w", err)
	}

	fmt.Printf("Signature: %s\n", hexutil.Encode(signature))

	// Submit the signature to the server
	resp, err = client.Post(
		fmt.Sprintf("%s/pubkey_signature", serverAddr),
		"application/octet-stream",
		bytes.NewReader(signature),
	)
	if err != nil {
		return fmt.Errorf("failed to submit signature: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		msg, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned error: %s", string(msg))
	}

	fmt.Println("Signature submitted successfully. Instance provisioning should continue.")
	return nil
}
