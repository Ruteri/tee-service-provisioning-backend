package flags

import (
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/ruteri/tee-service-provisioning-backend/api"
	"github.com/ruteri/tee-service-provisioning-backend/common"
	"github.com/urfave/cli/v2"
)

func SetupLogger(cCtx *cli.Context) (log *slog.Logger) {
	logJSON := cCtx.Bool(LogJsonFlag.Name)
	logDebug := cCtx.Bool(LogDebugFlag.Name)
	logUID := cCtx.Bool(LogUidFlag.Name)
	logService := cCtx.String("log-service")

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
	return logger
}

func ConfigureServer(cCtx *cli.Context, logger *slog.Logger, listenAddr string) *api.HTTPServerConfig {
	metricsAddr := cCtx.String("metrics-addr")
	enablePprof := cCtx.Bool("pprof")
	drainDuration := time.Duration(cCtx.Int64("drain-seconds")) * time.Second

	return &api.HTTPServerConfig{
		ListenAddr:               listenAddr,
		MetricsAddr:              metricsAddr,
		Log:                      logger,
		EnablePprof:              enablePprof,
		DrainDuration:            drainDuration,
		GracefulShutdownDuration: 30 * time.Second,
		ReadTimeout:              60 * time.Second,
		WriteTimeout:             30 * time.Second,
	}
}

var FlagAppAddr *cli.StringFlag = &cli.StringFlag{
	Name:     "app-contract",
	Required: true,
	Usage:    "Application governance contract address to request provisioning for. 40-char hex string with no 0x prefix",
}

var RpcAddrFlag = &cli.StringFlag{
	Name:  "rpc-addr",
	Value: "http://127.0.0.1:8545",
	Usage: "address to connect to RPC",
}

var FlagAttsetationType *cli.StringFlag = &cli.StringFlag{
	Name:  "debug-set-attestation-type-header",
	Usage: "If provided the provisioner will set the attestation type header",
}
var FlagAttsetationMeasurement *cli.StringFlag = &cli.StringFlag{
	Name:  "debug-set-attestation-measurement-header",
	Usage: "If provided the provisioner will set the attestation measurement header",
}

var LogJsonFlag = &cli.BoolFlag{
	Name:  "log-json",
	Value: false,
	Usage: "log in JSON format",
}
var LogDebugFlag = &cli.BoolFlag{
	Name:  "log-debug",
	Value: false,
	Usage: "log debug messages",
}
var LogUidFlag = &cli.BoolFlag{
	Name:  "log-uid",
	Value: false,
	Usage: "generate a uuid and add to all log messages",
}

var LogServiceFlagFn = func(service string) *cli.StringFlag {
	return &cli.StringFlag{
		Name:  "log-service",
		Value: "your-project",
		Usage: "add 'service' tag to logs",
	}
}

var PprofFlag = &cli.BoolFlag{
	Name:  "pprof",
	Value: false,
	Usage: "enable pprof debug endpoint",
}
var DrainSecondsFlag = &cli.Int64Flag{
	Name:  "drain-seconds",
	Value: 45,
	Usage: "seconds to wait in drain HTTP request",
}
var MetricsAddrFlag = &cli.StringFlag{
	Name:  "metrics-addr",
	Value: "127.0.0.1:8090",
	Usage: "address to listen on for Prometheus metrics",
}

var CommonFlags = []cli.Flag{
	LogJsonFlag,
	LogDebugFlag,
	LogUidFlag,
	PprofFlag,
	DrainSecondsFlag,
	MetricsAddrFlag,
}
