package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/google/uuid"
	"github.com/ruteri/poc-tee-registry/common"
	"github.com/ruteri/poc-tee-registry/httpserver"
	"github.com/ruteri/poc-tee-registry/kms"
	"github.com/ruteri/poc-tee-registry/registry"
	"github.com/ruteri/poc-tee-registry/storage"
	"github.com/urfave/cli/v2" // imports as package "cli"
)

var flags []cli.Flag = []cli.Flag{
	&cli.StringFlag{
		Name:  "rpc-addr",
		Value: "http://127.0.0.1:8545",
		Usage: "address to connect to RPC",
	},
	&cli.StringFlag{
		Name:  "listen-addr",
		Value: "127.0.0.1:8080",
		Usage: "address to listen on for API",
	},
	&cli.StringFlag{
		Name:  "metrics-addr",
		Value: "127.0.0.1:8090",
		Usage: "address to listen on for Prometheus metrics",
	},
	&cli.BoolFlag{
		Name:  "log-json",
		Value: false,
		Usage: "log in JSON format",
	},
	&cli.BoolFlag{
		Name:  "log-debug",
		Value: false,
		Usage: "log debug messages",
	},
	&cli.BoolFlag{
		Name:  "log-uid",
		Value: false,
		Usage: "generate a uuid and add to all log messages",
	},
	&cli.StringFlag{
		Name:  "log-service",
		Value: "your-project",
		Usage: "add 'service' tag to logs",
	},
	&cli.BoolFlag{
		Name:  "pprof",
		Value: false,
		Usage: "enable pprof debug endpoint",
	},
	&cli.Int64Flag{
		Name:  "drain-seconds",
		Value: 45,
		Usage: "seconds to wait in drain HTTP request",
	},
}

func main() {
	app := &cli.App{
		Name:  "httpserver",
		Usage: "Serve API, and metrics",
		Flags: flags,
		Action: func(cCtx *cli.Context) error {
			rpcAddress := cCtx.String("rpc-addr")
			listenAddr := cCtx.String("listen-addr")
			metricsAddr := cCtx.String("metrics-addr")
			logJSON := cCtx.Bool("log-json")
			logDebug := cCtx.Bool("log-debug")
			logUID := cCtx.Bool("log-uid")
			logService := cCtx.String("log-service")
			enablePprof := cCtx.Bool("pprof")
			drainDuration := time.Duration(cCtx.Int64("drain-seconds")) * time.Second

			log := common.SetupLogger(&common.LoggingOpts{
				Debug:   logDebug,
				JSON:    logJSON,
				Service: logService,
				Version: common.Version,
			})

			if logUID {
				id := uuid.Must(uuid.NewRandom())
				log = log.With("uid", id.String())
			}

			cfg := &httpserver.HTTPServerConfig{
				ListenAddr:  listenAddr,
				MetricsAddr: metricsAddr,
				Log:         log,
				EnablePprof: enablePprof,

				DrainDuration:            drainDuration,
				GracefulShutdownDuration: 30 * time.Second,
				ReadTimeout:              60 * time.Second,
				WriteTimeout:             30 * time.Second,
			}

			ethClient, err := ethclient.Dial(rpcAddress)
			if err != nil {
				cfg.Log.Error("failed to dial rpc", "err", err)
				return err
			}

			seed := [32]byte{}
			kmsImpl, err := kms.NewSimpleKMS(seed[:])
			if err != nil {
				cfg.Log.Error("failed to create kms", "err", err)
				return err
			}

			registryFactory := registry.NewRegistryFactory(ethClient)
			handler := httpserver.NewHandler(kmsImpl, storage.NewStorageBackendFactory(log), registryFactory, log)
			srv, err := httpserver.New(cfg, handler)
			if err != nil {
				cfg.Log.Error("failed to create server", "err", err)
				return err
			}

			exit := make(chan os.Signal, 1)
			signal.Notify(exit, os.Interrupt, syscall.SIGTERM)
			srv.RunInBackground()
			<-exit

			// Shutdown server once termination signal is received
			srv.Shutdown()
			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
