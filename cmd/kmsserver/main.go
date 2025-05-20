package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ruteri/tee-service-provisioning-backend/api/kmshandler"
	"github.com/ruteri/tee-service-provisioning-backend/api/pkihandler"
	"github.com/ruteri/tee-service-provisioning-backend/api/server"
	"github.com/ruteri/tee-service-provisioning-backend/cmd/flags"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/ruteri/tee-service-provisioning-backend/kmsgovernance"
	"github.com/ruteri/tee-service-provisioning-backend/registry"
	"github.com/urfave/cli/v2"
)

var KmsServiceLogFlag = flags.LogServiceFlagFn("kms")

var KmsPKIListenAddrFlag = &cli.StringFlag{
	Name:  "pki-listen-addr",
	Value: "127.0.0.1:8081",
	Usage: "address to listen on for API",
}
var KmsAttestedListenAddrFlag = &cli.StringFlag{
	Name:  "kms-listen-addr",
	Value: "127.0.0.1:8082",
	Usage: "address to listen on for API",
}
var KmsGovernanceAddrFlag = &cli.StringFlag{
	Name:  "kms-contract",
	Usage: "KMS governace contract address",
}

func main() {
	app := &cli.App{
		Name:  "kms-server",
		Usage: "Serve TEE KMS",
		Flags: append(append(KmsFlags, []cli.Flag{KmsPKIListenAddrFlag, KmsAttestedListenAddrFlag, KmsGovernanceAddrFlag, flags.RpcAddrFlag, KmsServiceLogFlag}...), flags.CommonFlags...),
		Action: func(cCtx *cli.Context) error {
			// Parse basic configuration
			pkiListenAddr := cCtx.String(KmsPKIListenAddrFlag.Name)
			attestedListenAddr := cCtx.String(KmsAttestedListenAddrFlag.Name)
			rpcAddress := cCtx.String(flags.RpcAddrFlag.Name)
			kmsGovernanceContractAdress, _ := interfaces.NewContractAddressFromHex(cCtx.String(KmsGovernanceAddrFlag.Name))

			// Setup logger
			logger := flags.SetupLogger(cCtx)

			// Connect to Ethereum
			logger.Info("Connecting to Ethereum RPC", "address", rpcAddress)
			ethClient, err := ethclient.Dial(rpcAddress)
			if err != nil {
				logger.Error("Failed to dial RPC", "err", err)
				return err
			}

			kmsGovernance, err := kmsgovernance.NewKmsGovernanceClient(ethClient, ethClient, common.Address(kmsGovernanceContractAdress))
			if err != nil {
				logger.Error("Failed to instantiate kms", "err", err)
				return err
			}

			// Create registry factory
			registryFactory := registry.NewRegistryFactory(ethClient, ethClient)

			// Handle KMS initialization based on type
			kmsImpl, err := SetupKMS(cCtx, logger, kmsGovernanceContractAdress, kmsGovernance)
			if err != nil {
				logger.Error("Failed to initialize KMS", "err", err)
				return err
			}

			logger.Info("KMS initialized successfully")

			pkiServer, err := server.New(flags.ConfigureServer(cCtx, logger, pkiListenAddr), pkihandler.NewHandler(kmsImpl, logger))
			if err != nil {
				logger.Error("Failed to create server", "err", err)
				return err
			}

			kmsServer, err := server.New(flags.ConfigureServer(cCtx, logger, attestedListenAddr), kmshandler.NewHandler(kmshandler.NewSimpleHandlerKMS(kmsImpl, kmsGovernanceContractAdress), kmsGovernance, registryFactory, logger))
			if err != nil {
				logger.Error("Failed to create server", "err", err)
				return err
			}

			pkiServer.RunInBackground()
			kmsServer.RunInBackground()

			// Wait for termination signal
			exit := make(chan os.Signal, 1)
			signal.Notify(exit, os.Interrupt, syscall.SIGTERM)

			logger.Info("Server is running, press Ctrl+C to stop")
			<-exit
			logger.Info("Shutdown signal received")

			// Shutdown server gracefully
			pkiServer.Shutdown()
			kmsServer.Shutdown()
			logger.Info("Server shutdown complete")

			return nil
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}
