package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/google/uuid"
	"github.com/ruteri/tee-service-provisioning-backend/api"
	"github.com/ruteri/tee-service-provisioning-backend/api/provisioner"
	"github.com/ruteri/tee-service-provisioning-backend/api/server"
	shamirkms "github.com/ruteri/tee-service-provisioning-backend/api/shamir-kms"
	"github.com/ruteri/tee-service-provisioning-backend/common"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/ruteri/tee-service-provisioning-backend/kms"
	"github.com/ruteri/tee-service-provisioning-backend/registry"
	"github.com/ruteri/tee-service-provisioning-backend/storage"
	"github.com/urfave/cli/v2"
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
	&cli.StringFlag{
		Name:  "kms-type",
		Value: "simple",
		Usage: "type of KMS to use: 'simple' or 'shamir'",
	},
	&cli.StringFlag{
		Name:  "simple-kms-seed",
		Value: "",
		Usage: "hex-encoded 32-byte seed for SimpleKMS (required if kms-type is 'simple')",
	},
	&cli.StringFlag{
		Name:  "shamirkms-admin-keys-file",
		Value: "",
		Usage: "JSON file with admin public keys for ShamirKMS (required if kms-type is 'shamir')",
	},
	&cli.IntFlag{
		Name:  "shamirkms-threshold",
		Usage: "Threshold to use for shamir kms generation and recovery",
	},
	&cli.StringFlag{
		Name:  "shamirkms-listen-addr",
		Value: "127.0.0.1:8081",
		Usage: "address to listen on for API",
	},
	&cli.IntFlag{
		Name:  "shamirkms-bootstrap-timeout",
		Value: 86400,
		Usage: "timeout in seconds for bootstrap process when using ShamirKMS",
	},
	&cli.StringFlag{
		Name:  "remote-attestation-provider",
		Usage: "remote attestation provider (dummy dcap) address to use for attestations in KMS",
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
		Name:  "registry-server",
		Usage: "Serve TEE registry API with secure KMS bootstrapping",
		Flags: flags,
		Action: func(cCtx *cli.Context) error {
			// Parse basic configuration
			rpcAddress := cCtx.String("rpc-addr")
			listenAddr := cCtx.String("listen-addr")
			shamirkmsListenAddr := cCtx.String("shamirkms-listen-addr")
			metricsAddr := cCtx.String("metrics-addr")
			kmsType := cCtx.String("kms-type")
			kmsRemoteAttestationProvider := cCtx.String("remote-attestation-provider")
			adminKeysFile := cCtx.String("shamirkms-admin-keys-file")
			shamirkmsThreshold := cCtx.Int("shamirkms-threshold")
			bootstrapTimeout := cCtx.Int("shamirkms-bootstrap-timeout")
			simpleKMSSeed := cCtx.String("simple-kms-seed")
			logJSON := cCtx.Bool("log-json")
			logDebug := cCtx.Bool("log-debug")
			logUID := cCtx.Bool("log-uid")
			logService := cCtx.String("log-service")
			enablePprof := cCtx.Bool("pprof")
			drainDuration := time.Duration(cCtx.Int64("drain-seconds")) * time.Second

			// Setup logger
			logger := common.SetupLogger(&common.LoggingOpts{
				Debug:   logDebug,
				JSON:    logJSON,
				Service: logService,
				Version: common.Version,
			})

			if logUID {
				id := uuid.Must(uuid.NewRandom())
				logger = logger.With("uid", id.String())
			}

			// Connect to Ethereum
			logger.Info("Connecting to Ethereum RPC", "address", rpcAddress)
			ethClient, err := ethclient.Dial(rpcAddress)
			if err != nil {
				logger.Error("Failed to dial RPC", "err", err)
				return err
			}

			// Create registry factory and storage factory (don't depend on KMS)
			registryFactory := registry.NewRegistryFactory(ethClient, ethClient)
			storageFactory := storage.NewStorageBackendFactory(logger, registryFactory)

			// Set up the base HTTP server config
			cfg := &api.HTTPServerConfig{
				ListenAddr:               listenAddr,
				MetricsAddr:              metricsAddr,
				Log:                      logger,
				EnablePprof:              enablePprof,
				DrainDuration:            drainDuration,
				GracefulShutdownDuration: 30 * time.Second,
				ReadTimeout:              60 * time.Second,
				WriteTimeout:             30 * time.Second,
			}

			// Handle KMS initialization based on type
			var kmsImpl interfaces.KMS

			switch kmsType {
			case "simple":
				logger.Info("Using SimpleKMS")

				// Validate the seed parameter
				if simpleKMSSeed == "" {
					logger.Error("simple-kms-seed is required when using simple KMS")
					return errors.New("simple-kms-seed is required for simple KMS")
				}

				// Parse the seed
				seed, err := hex.DecodeString(simpleKMSSeed)
				if err != nil || len(seed) != 32 {
					logger.Error("Invalid simple-kms-seed - must be 64 hex chars (32 bytes)", "err", err)
					return fmt.Errorf("invalid simple-kms-seed: %v", err)
				}

				// Create SimpleKMS
				simpleKms, err := kms.NewSimpleKMS(seed)
				if err != nil {
					logger.Error("Failed to create SimpleKMS", "err", err)
					return err
				}
				if kmsRemoteAttestationProvider != "" {
					simpleKms = simpleKms.WithAttestationProvider(&cryptoutils.RemoteAttestationProvider{Address: kmsRemoteAttestationProvider})
				}
				kmsImpl = simpleKms
			case "shamir":
				logger.Info("Using ShamirKMS with admin bootstrap")

				// Validate the admin keys file parameter
				if adminKeysFile == "" {
					logger.Error("admin-keys-file is required when using shamir KMS")
					return errors.New("admin-keys-file is required for shamir KMS")
				}

				// Load admin keys
				logger.Info("Loading admin keys", "file", adminKeysFile)
				adminKeysData, err := os.Open(adminKeysFile)
				if err != nil {
					logger.Error("Failed to open admin keys file", "err", err)
					return err
				}
				defer adminKeysData.Close()

				adminKeys, err := shamirkms.LoadAdminKeys(adminKeysData)
				if err != nil {
					logger.Error("Failed to load admin keys", "err", err)
					return err
				}

				logger.Info("Admin keys loaded successfully", "count", len(adminKeys))

				skmsServerCfg := *cfg
				skmsServerCfg.ListenAddr = shamirkmsListenAddr
				adminHandler, err := shamirkms.NewAdminHandler(skmsServerCfg.Log, shamirkmsThreshold, adminKeys)
				if err != nil {
					return fmt.Errorf("could not initialize kms admin handler: %w", err)
				}

				// Create base server with the admin handler as a route registrar
				baseServer, err := server.New(&skmsServerCfg, adminHandler)
				if err != nil {
					return fmt.Errorf("could not create base server for kms admin: %w", err)
				}

				// Start server in bootstrap mode (only admin API will be available)
				logger.Info("Starting server in bootstrap mode")
				baseServer.RunInBackground()

				// Wait for bootstrap to complete
				logger.Info("Waiting for KMS bootstrap to complete...",
					"timeout", bootstrapTimeout)

				ctx, cancel := context.WithTimeout(context.Background(),
					time.Duration(bootstrapTimeout)*time.Second)
				defer cancel()

				// This blocks until bootstrap is complete or timeout occurs
				shamirKMS, err := adminHandler.WaitForBootstrap(ctx)
				if err != nil {
					logger.Error("KMS bootstrap failed", "err", err)
					return err
				}
				baseServer.Shutdown()
				kmsImpl = shamirKMS.SimpleKMS()

				// Now that KMS is bootstrapped, create the registry handler
				logger.Info("KMS bootstrap completed successfully, creating registry handler")

			default:
				logger.Error("Invalid kms-type", "type", kmsType)
				return fmt.Errorf("invalid kms-type: %s", kmsType)
			}

			logger.Info("SimpleKMS initialized successfully")

			// Create handler with the initialized KMS
			handler := provisioner.NewHandler(kmsImpl, storageFactory, registryFactory, logger)

			// Create server with registry handler
			server, err := server.New(cfg, handler)
			if err != nil {
				logger.Error("Failed to create server", "err", err)
				return err
			}

			server.RunInBackground()

			// Wait for termination signal
			exit := make(chan os.Signal, 1)
			signal.Notify(exit, os.Interrupt, syscall.SIGTERM)

			logger.Info("Server is running, press Ctrl+C to stop")
			<-exit
			logger.Info("Shutdown signal received")

			// Shutdown server gracefully
			server.Shutdown()
			logger.Info("Server shutdown complete")

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
