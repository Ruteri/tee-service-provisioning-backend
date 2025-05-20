package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/go-chi/chi/v5"
	"github.com/ruteri/tee-service-provisioning-backend/api/kmshandler"
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

var KmsBootstrapListenAddrFlag = &cli.StringFlag{
	Name:  "bootstrap-listen-addr",
	Value: "127.0.0.1:8080",
	Usage: "KMS bootstrap listen address.",
}

var KmsSeedFlag = &cli.StringFlag{
	Name:  "simple-kms-seed",
	Value: "",
	Usage: "hex-encoded 32-byte seed for SimpleKMS. One of simple-kms-seed and bootstrap-kms should be set.",
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

type Onboarder struct {
	SimpleKMS     *kms.SimpleKMS
	KmsAddr       interfaces.ContractAddress
	Pubkey        interfaces.AppPubkey
	Privkey       interfaces.AppPrivkey
	AllowGenerate bool
	OnboardCh     chan *kms.SimpleKMS

	mu         sync.Mutex
	onboardReq *interfaces.OnboardRequest
}

func NewOnboarder(KmsAddr interfaces.ContractAddress, attestationProvider cryptoutils.AttestationProvider, allowGenerate bool, onboardCh chan *kms.SimpleKMS) (*Onboarder, error) {
	masterKey := make([]byte, 32)
	_, err := rand.Read(masterKey)
	if err != nil {
		return nil, err
	}

	simpleKms, err := kms.NewSimpleKMS(masterKey)
	if err != nil {
		return nil, err
	}
	simpleKms = simpleKms.WithAttestationProvider(attestationProvider)

	pub, priv, err := cryptoutils.RandomP256Keypair()
	if err != nil {
		return nil, err
	}

	return &Onboarder{
		SimpleKMS:     simpleKms,
		KmsAddr:       KmsAddr,
		Pubkey:        pub,
		Privkey:       priv,
		AllowGenerate: allowGenerate,
		OnboardCh:     onboardCh,
	}, nil
}

func (o *Onboarder) RegisterRoutes(r chi.Router) {
	r.Get("/api/operator/onboard_request/{operator}", o.HandleGetOnboardRequest)
	r.Post("/api/operator/onboard", o.HandleDoOnboard)

	// Temporary workaround
	if o.AllowGenerate {
		r.Post("/api/operator/generate", o.HandleGenerate)
	}
}

func (o *Onboarder) HandleGetOnboardRequest(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()

	if o.onboardReq != nil {
		json.NewEncoder(w).Encode(o.onboardReq)
		return
	}

	operatorAddr, err := interfaces.NewContractAddressFromHex(r.PathValue("operator"))
	if err != nil {
		http.Error(w, fmt.Errorf("invalid contract address: %w", err).Error(), http.StatusBadRequest)
		return
	}

	onboardReq, err := o.SimpleKMS.RequestOnboard(o.KmsAddr, operatorAddr, o.Pubkey)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	o.onboardReq = &onboardReq
	json.NewEncoder(w).Encode(onboardReq)
}

func (o *Onboarder) HandleDoOnboard(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()

	// Note: this can be taken from DNS listed onchain as well
	onboarderUrl, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, fmt.Errorf("could not read onboarded kms url from body: %w", err).Error(), http.StatusInternalServerError)
		return
	}

	onboardHash, err := kms.OnboardRequestHash(*o.onboardReq)
	if err != nil {
		http.Error(w, fmt.Errorf("could not hash onboard request: %w", err).Error(), http.StatusInternalServerError)
		return
	}

	encryptedSeed, err := kmshandler.DefaultSecretsProvider.OnboardKMS(string(onboarderUrl), onboardHash, o.SimpleKMS, o.Privkey)
	if err != nil {
		http.Error(w, fmt.Errorf("could not get kms seed: %w", err).Error(), http.StatusInternalServerError)
		return
	}

	rawSeed, err := cryptoutils.DecryptWithPrivateKey(o.Privkey, encryptedSeed)
	if err != nil {
		http.Error(w, fmt.Errorf("could not decrypt kms seed: %w", err).Error(), http.StatusInternalServerError)
		return
	}

	o.OnboardCh <- o.SimpleKMS.WithSeed(rawSeed)
	w.WriteHeader(http.StatusOK)
}

func (o *Onboarder) HandleGenerate(w http.ResponseWriter, r *http.Request) {
	masterSeed := make([]byte, 32)
	_, err := rand.Read(masterSeed)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	o.OnboardCh <- o.SimpleKMS.WithSeed(masterSeed)
}

type OperatorAuth struct {
	Nonce  [32]byte
	AuthCh chan interfaces.ContractAddress
}

func NewOperatorAuth(authCh chan interfaces.ContractAddress) *OperatorAuth {
	nonce := make([]byte, 32)
	rand.Read(nonce)
	a := &OperatorAuth{
		AuthCh: authCh,
	}
	copy(a.Nonce[:], nonce)
	return a
}

func (a *OperatorAuth) RegisterRoutes(r chi.Router) {
	r.Get("/api/operator/auth", func(w http.ResponseWriter, r *http.Request) { w.Write(a.Nonce[:]) })
	r.Post("/api/operator/auth", func(w http.ResponseWriter, r *http.Request) {
		signedNonce, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, fmt.Errorf("could not read body: %w", err).Error(), http.StatusInternalServerError)
			return
		}

		pubkey, err := crypto.SigToPub(a.Nonce[:], signedNonce)
		if err != nil {
			http.Error(w, fmt.Errorf("signature not valid: %w", err).Error(), http.StatusBadRequest)
			return
		}

		a.AuthCh <- interfaces.ContractAddress(crypto.PubkeyToAddress(*pubkey))
		w.WriteHeader(http.StatusOK)
	})
}

// SetupKMS initalizes and bootstraps KMS. Note that for shamir this call will
// wait until shamir kms is bootstrapped (which requires admins to fetch or submit
// their shares).
func SetupKMS(cCtx *cli.Context, logger *slog.Logger, kmsContract interfaces.ContractAddress, kmsGovernance interfaces.KMSGovernance) (*kms.SimpleKMS, error) {
	kmsType := cCtx.String(KmsTypeFlag.Name)
	bootstrapListenAddr := cCtx.String(KmsBootstrapListenAddrFlag.Name)
	kmsRemoteAttestationProvider := cCtx.String(RemoteAttestationFlag.Name)
	adminKeysFile := cCtx.String(KmsAdminKeysFlag.Name)
	shamirkmsThreshold := cCtx.Int(KmsThresholdFlag.Name)
	bootstrapTimeout := cCtx.Int(KmsTimeoutFlag.Name)
	simpleKMSSeed := cCtx.String(KmsSeedFlag.Name)

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(bootstrapTimeout)*time.Second)
	defer cancel()

	authCh := make(chan interfaces.ContractAddress, 1)
	onboardedKmsCh := make(chan *kms.SimpleKMS, 2)
	handlers := []server.RouteRegistrar{NewOperatorAuth(authCh)}

	var attestationProvider cryptoutils.AttestationProvider = cryptoutils.DumyAttestationProvider{}
	if kmsRemoteAttestationProvider != "" {
		attestationProvider = &cryptoutils.RemoteAttestationProvider{Address: kmsRemoteAttestationProvider}
	}

	doBootstrap := bootstrapListenAddr != ""
	if doBootstrap {
		allowGenerate := kmsType == "simple"
		onboarder, err := NewOnboarder(kmsContract, attestationProvider, allowGenerate, onboardedKmsCh)
		if err != nil {
			return nil, fmt.Errorf("could not initialize onboarder: %w", err)
		}

		handlers = append(handlers, onboarder)
	}

	switch kmsType {
	case "simple":
		logger.Info("Using SimpleKMS")

		// Validate the seed parameter
		if simpleKMSSeed == "" && !doBootstrap {
			return nil, errors.New("simple-kms-seed is required for simple KMS")
		} else if simpleKMSSeed == "" {
			break
		}

		// Parse the seed
		seed, err := hex.DecodeString(simpleKMSSeed)
		if err != nil || len(seed) != 32 {
			return nil, fmt.Errorf("invalid simple-kms-seed: %v", err)
		}

		// Create SimpleKMS
		simpleKms, err := kms.NewSimpleKMS(seed)
		if err != nil {
			return nil, fmt.Errorf("could not initialize simple kms from seed: %w", err)
		}
		simpleKms = simpleKms.WithAttestationProvider(attestationProvider)
		return simpleKms, nil
	case "shamir":
		logger.Info("Using ShamirKMS with admin bootstrap")

		// Validate the admin keys file parameter
		if adminKeysFile == "" {
			return nil, errors.New("admin-keys-file is required for shamir KMS")
		}

		// Load admin keys
		adminKeysData, err := os.Open(adminKeysFile)
		if err != nil {
			return nil, fmt.Errorf("failed to open admin keys file: %w", err)
		}
		defer adminKeysData.Close()

		adminKeys, err := shamirkms.LoadAdminKeys(adminKeysData)
		if err != nil {
			return nil, fmt.Errorf("failed to load admin keys: %w", err)
		}

		adminHandler, err := shamirkms.NewAdminHandler(logger, shamirkmsThreshold, adminKeys)
		if err != nil {
			return nil, fmt.Errorf("could not initialize kms admin handler: %w", err)
		}

		handlers = append(handlers, adminHandler)

		go func() {
			shamirKMS, err := adminHandler.WaitForBootstrap(ctx)
			if err != nil {
				logger.Debug("admin botstrap failed", "err", err)
				return
			}
			onboardedKmsCh <- shamirKMS.SimpleKMS()
		}()
	default:
		return nil, fmt.Errorf("invalid kms-type: %s", kmsType)
	}

	bootstrapServerCfg := flags.ConfigureServer(cCtx, logger, bootstrapListenAddr)
	bootstrapServer, err := server.New(bootstrapServerCfg, handlers...)
	if err != nil {
		return nil, fmt.Errorf("could not create base server for kms admin: %w", err)
	}

	bootstrapServer.RunInBackground()
	defer bootstrapServer.Shutdown()

	var preparedKms *kms.SimpleKMS
	select {
	case <-ctx.Done():
		return nil, errors.New("kms bootstrap context timeout")
	case preparedKms = <-onboardedKmsCh:
	}

	select {
	case <-ctx.Done():
		return nil, errors.New("kms bootstrap context timeout")
	case operatorAddr := <-authCh:
		return preparedKms.WithOperator(operatorAddr), nil
	}
}
