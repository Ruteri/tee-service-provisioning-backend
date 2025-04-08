package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/urfave/cli/v2"
)

var flags []cli.Flag = []cli.Flag{
	&cli.StringFlag{
		Name:  "listen-addr",
		Value: "0.0.0.0:8072",
		Usage: "address to listen on for API",
	},
	&cli.BoolFlag{
		Name:  "listen-tls",
		Value: true,
		Usage: "use a random self-signed TLS certificate",
	},
	&cli.StringFlag{
		Name:     "config-file",
		Required: true,
		Usage:    "config file path to check or write to",
	},
}

const usage string = `This script makes sure an operator-provided configuration file exists before exiting
If the configuration file already exists the script simply exits (0).
If the configuration file does not exist, the script:
* starts a http server listening on /config for a POST request.
* writes the post request's body as the configuration file and exits (0).

This script is only intended for non-transparent configuration as it does not modify the measurements.`

func main() {
	app := &cli.App{
		Name:  "operator-config-api",
		Usage: usage,
		Flags: flags,
		Action: func(cCtx *cli.Context) error {
			laddr := cCtx.String("listen-addr")
			configFilePath := cCtx.String("config-file")
			listenTLS := cCtx.Bool("listen-tls")

			// Check if config file already exists
			_, err := os.Stat(configFilePath)
			if err == nil {
				log.Printf("config file %s already exists, exiting\n", configFilePath)
				os.Exit(0)
			}

			mux := chi.NewRouter()
			mux.Post("/config", func(w http.ResponseWriter, r *http.Request) {
				configFile, err := os.OpenFile(configFilePath, os.O_CREATE|os.O_WRONLY, 0600)
				if err != nil {
					log.Printf("could not create config file %s for writing: %s\n", configFilePath, err.Error())
					http.Error(w, fmt.Errorf("could not create config file %s for writing: %w", configFilePath, err).Error(), http.StatusInternalServerError)
					return // do not exit!
				}

				io.Copy(configFile, r.Body)
				w.WriteHeader(http.StatusOK)
				log.Printf("successfully wrote config file %s, exiting\n", configFilePath)
				os.Exit(0)
			})

			s := http.Server{
				Addr:    laddr,
				Handler: mux,
			}

			if listenTLS {
				cert, err := randomCert()
				if err != nil {
					log.Fatalf("could not generate random tls cert: %s", err.Error())
				}

				s.TLSConfig = &tls.Config{
					Certificates: []tls.Certificate{cert},
				}

				return s.ListenAndServeTLS("", "")
			} else {
				return s.ListenAndServe()
			}
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}

}

func randomCert() (tls.Certificate, error) {
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{},
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	certASN1, err := x509.CreateCertificate(rand.Reader, template, template,
		privateKey.Public(), privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certASN1})

	privkeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.X509KeyPair(certPEM, pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privkeyBytes,
	}))
}
