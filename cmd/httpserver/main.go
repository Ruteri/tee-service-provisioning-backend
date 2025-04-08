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
	"github.com/ruteri/tee-service-provisioning-backend/api/handlers"
	"github.com/ruteri/tee-service-provisioning-backend/api/servers"
	"github.com/ruteri/tee-service-provisioning-backend/common"
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
		Name:  "admin-keys-file",
		Value: "",
		Usage: "JSON file with admin public keys for ShamirKMS (required if kms-type is 'shamir')",
	},
	&cli.IntFlag{
		Name:  "bootstrap-timeout",
		Value: 300,
		Usage: "timeout in seconds for bootstrap process when using ShamirKMS",
	},
	&cli.StringFlag{
		Name:  "simple-kms-seed",
		Value: "",
		Usage: "hex-encoded 32-byte seed for SimpleKMS (required if kms-type is 'simple')",
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
			metricsAddr := cCtx.String("metrics-addr")
			kmsType := cCtx.String("kms-type")
			adminKeysFile := cCtx.String("admin-keys-file")
			bootstrapTimeout := cCtx.Int("bootstrap-timeout")
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
			cfg := &servers.HTTPServerConfig{
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
			var server *servers.Server

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
				kmsImpl, err = kms.NewSimpleKMS(seed)
				if err != nil {
					logger.Error("Failed to create SimpleKMS", "err", err)
					return err
				}

				logger.Info("SimpleKMS initialized successfully")

				// Create handler with the initialized KMS
				handler := handlers.NewHandler(kmsImpl, storageFactory, registryFactory, logger)

				// Create server with registry handler
				server, err = servers.New(cfg, handler, kmsImpl)
				if err != nil {
					logger.Error("Failed to create server", "err", err)
					return err
				}

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

				adminKeys, err := handlers.LoadAdminKeys(adminKeysData)
				if err != nil {
					logger.Error("Failed to load admin keys", "err", err)
					return err
				}

				logger.Info("Admin keys loaded successfully", "count", len(adminKeys))

				// Configure server for bootstrap mode
				cfg.EnableAdmin = true
				cfg.AdminKeys = adminKeys
				cfg.BootstrapMode = true

				// Create server in bootstrap mode (registry handler will be added later)
				// We pass nil for both handler and KMS since they'll be set after bootstrap
				server, err = servers.New(cfg, nil, nil)
				if err != nil {
					logger.Error("Failed to create server", "err", err)
					return err
				}

				// Start server in bootstrap mode (only admin API will be available)
				logger.Info("Starting server in bootstrap mode")
				server.RunInBackground()

				// Wait for bootstrap to complete
				logger.Info("Waiting for KMS bootstrap to complete...",
					"timeout", bootstrapTimeout)

				ctx, cancel := context.WithTimeout(context.Background(),
					time.Duration(bootstrapTimeout)*time.Second)
				defer cancel()

				// This blocks until bootstrap is complete or timeout occurs
				shamirKMS, err := server.WaitForBootstrap(ctx)
				if err != nil {
					logger.Error("KMS bootstrap failed", "err", err)
					return err
				}

				// Now that KMS is bootstrapped, create the registry handler
				logger.Info("KMS bootstrap completed successfully, creating registry handler")
				handler := handlers.NewHandler(shamirKMS, storageFactory, registryFactory, logger)

				// Update the server with the new handler
				server.SetRegistryHandler(handler)

				// Set the KMS implementation for the rest of the code
				kmsImpl = shamirKMS

				logger.Info("Registry handler enabled, server is now fully operational")

				// Note: We don't need to call RunInBackground here because it was already
				// started during the bootstrap phase

			default:
				logger.Error("Invalid kms-type", "type", kmsType)
				return fmt.Errorf("invalid kms-type: %s", kmsType)
			}

			// If we're using SimpleKMS, start the server now
			// (For ShamirKMS, the server is already running from the bootstrap phase)
			if kmsType == "simple" {
				logger.Info("Starting server")
				server.RunInBackground()
			}

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
