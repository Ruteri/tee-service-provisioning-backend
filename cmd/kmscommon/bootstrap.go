package kmscommon

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/ruteri/tee-service-provisioning-backend/api/server"
	shamirkms "github.com/ruteri/tee-service-provisioning-backend/api/shamir-kms"
	"github.com/ruteri/tee-service-provisioning-backend/cmd/flags"
	"github.com/ruteri/tee-service-provisioning-backend/cryptoutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
	"github.com/ruteri/tee-service-provisioning-backend/kms"
	"github.com/urfave/cli/v2"
)

var KmsTypeFlag = &cli.StringFlag{
	Name:  "kms-type",
	Value: "simple",
	Usage: "type of KMS to use: 'simple' or 'shamir'",
}

var KmsSeedFlag = &cli.StringFlag{
	Name:  "simple-kms-seed",
	Value: "",
	Usage: "hex-encoded 32-byte seed for SimpleKMS (required if kms-type is 'simple')",
}

var KmsAdminKeysFlag = &cli.StringFlag{
	Name:  "shamirkms-admin-keys-file",
	Value: "",
	Usage: "JSON file with admin public keys for ShamirKMS (required if kms-type is 'shamir')",
}
var KmsThresholdFlag = &cli.IntFlag{
	Name:  "shamirkms-threshold",
	Usage: "Threshold to use for shamir kms generation and recovery",
}
var KmsBootstrapListenAddrFlag = &cli.StringFlag{
	Name:  "shamir-bootstrap-listen-addr",
	Value: "127.0.0.1:8080",
	Usage: "address to listen on for API",
}
var KmsTimeoutFlag = &cli.IntFlag{
	Name:  "shamirkms-bootstrap-timeout",
	Value: 86400,
	Usage: "timeout in seconds for bootstrap process when using ShamirKMS",
}
var RemoteAttestationFlag = &cli.StringFlag{
	Name:  "remote-attestation-provider",
	Usage: "remote attestation provider (dummy dcap) address to use for attestations in KMS",
}

var KmsFlags = []cli.Flag{
	KmsTypeFlag,
	KmsSeedFlag,
	KmsAdminKeysFlag,
	KmsThresholdFlag,
	KmsBootstrapListenAddrFlag,
	KmsTimeoutFlag,
	RemoteAttestationFlag,
}

// SetupKMS initalizes and bootstraps KMS. Note that for shamir this call will
// wait until shamir kms is bootstrapped (which requires admins to fetch or submit
// their shares).
func SetupKMS(cCtx *cli.Context, logger *slog.Logger) (interfaces.KMS, error) {
	kmsType := cCtx.String(KmsTypeFlag.Name)
	kmsRemoteAttestationProvider := cCtx.String(RemoteAttestationFlag.Name)
	adminKeysFile := cCtx.String(KmsAdminKeysFlag.Name)
	shamirkmsThreshold := cCtx.Int(KmsThresholdFlag.Name)
	shamirkmsListenAddr := cCtx.String(KmsBootstrapListenAddrFlag.Name)
	bootstrapTimeout := cCtx.Int(KmsTimeoutFlag.Name)
	simpleKMSSeed := cCtx.String(KmsSeedFlag.Name)

	switch kmsType {
	case "simple":
		logger.Info("Using SimpleKMS")

		// Validate the seed parameter
		if simpleKMSSeed == "" {
			return nil, errors.New("simple-kms-seed is required for simple KMS")
		}

		// Parse the seed
		seed, err := hex.DecodeString(simpleKMSSeed)
		if err != nil || len(seed) != 32 {
			return nil, fmt.Errorf("invalid simple-kms-seed: %v", err)
		}

		// Create SimpleKMS
		simpleKms, err := kms.NewSimpleKMS(seed)
		if err != nil {
			return nil, err
		}
		if kmsRemoteAttestationProvider != "" {
			simpleKms = simpleKms.WithAttestationProvider(&cryptoutils.RemoteAttestationProvider{Address: kmsRemoteAttestationProvider})
		}
		return simpleKms, nil
	case "shamir":
		logger.Info("Using ShamirKMS with admin bootstrap")

		// Validate the admin keys file parameter
		if adminKeysFile == "" {
			return nil, errors.New("admin-keys-file is required for shamir KMS")
		}

		// Load admin keys
		logger.Info("Loading admin keys", "file", adminKeysFile)
		adminKeysData, err := os.Open(adminKeysFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open admin keys file: %w", err)
		}
		defer adminKeysData.Close()

		adminKeys, err := shamirkms.LoadAdminKeys(adminKeysData)
		if err != nil {
			return nil, fmt.Errorf("failed to load admin keys: %w", err)
		}

		logger.Info("Admin keys loaded successfully", "count", len(adminKeys))

		skmsServerCfg := flags.ConfigureServer(cCtx, logger, shamirkmsListenAddr)
		adminHandler, err := shamirkms.NewAdminHandler(skmsServerCfg.Log, shamirkmsThreshold, adminKeys)
		if err != nil {
			return nil, fmt.Errorf("could not initialize kms admin handler: %w", err)
		}

		// Create base server with the admin handler as a route registrar
		baseServer, err := server.New(skmsServerCfg, adminHandler)
		if err != nil {
			return nil, fmt.Errorf("could not create base server for kms admin: %w", err)
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
			return nil, err
		}
		baseServer.Shutdown()

		return shamirKMS.SimpleKMS(), nil

	default:
		return nil, fmt.Errorf("invalid kms-type: %s", kmsType)
	}
}
