package api

import (
	"log/slog"
	"time"
)

// HTTPServerConfig contains all configuration parameters for the HTTP server.
type HTTPServerConfig struct {
	// ListenAddr is the address and port the HTTP server will listen on.
	ListenAddr string

	// MetricsAddr is the address and port for the metrics server.
	// If empty, metrics server will not be started.
	MetricsAddr string

	// EnablePprof enables the pprof debugging API when true.
	EnablePprof bool

	// Log is the structured logger for server operations.
	Log *slog.Logger

	// DrainDuration is the time to wait after marking server not ready
	// before shutting down, allowing load balancers to detect the change.
	DrainDuration time.Duration

	// GracefulShutdownDuration is the maximum time to wait for in-flight
	// requests to complete during shutdown.
	GracefulShutdownDuration time.Duration

	// ReadTimeout is the maximum duration for reading the entire request,
	// including the body.
	ReadTimeout time.Duration

	// WriteTimeout is the maximum duration before timing out writes of
	// the response.
	WriteTimeout time.Duration
}
