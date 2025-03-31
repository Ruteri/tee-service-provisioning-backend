package httpserver

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/flashbots/go-utils/httplogger"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/ruteri/poc-tee-registry/common"
	"github.com/ruteri/poc-tee-registry/interfaces"
	"github.com/ruteri/poc-tee-registry/kms"
	"github.com/ruteri/poc-tee-registry/metrics"
	"go.uber.org/atomic"
	"go.uber.org/zap"
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

	// ZapLogger supports legacy logging integration.
	ZapLogger *zap.Logger

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

	// EnableAdmin determines whether to enable the admin API for KMS bootstrapping.
	EnableAdmin bool

	// AdminKeys is a map of admin IDs to their public keys for KMS bootstrapping.
	// Required if EnableAdmin is true.
	AdminKeys map[string][]byte

	// BootstrapMode determines if the server is starting in bootstrap mode.
	// In bootstrap mode, only admin endpoints are enabled until bootstrap completes.
	BootstrapMode bool
}

// Server represents the HTTP server for the TEE registry system.
// It can handle both registry API and admin API endpoints, depending on configuration.
type Server struct {
	cfg     *HTTPServerConfig
	isReady atomic.Bool
	mu      sync.RWMutex
	log     *slog.Logger
	zapLog  *zap.Logger

	srv        *http.Server
	metricsSrv *metrics.MetricsServer

	// Handlers
	registryHandler *Handler
	adminHandler    *AdminHandler
	kmsImpl         interfaces.KMS

	// Bootstrap completed channel
	bootstrapComplete chan struct{}
}

// New creates a new HTTP server with the specified configuration and handlers.
//
// Parameters:
//   - cfg: Server configuration
//   - registryHandler: Handler for registry API endpoints (can be nil in bootstrap mode)
//   - kmsImpl: Key Management System implementation (can be nil in bootstrap mode)
//
// Returns:
//   - Configured server instance
//   - Error if server creation fails
func New(cfg *HTTPServerConfig, registryHandler *Handler, kmsImpl interfaces.KMS) (*Server, error) {
	metricsSrv, err := metrics.New(common.PackageName, cfg.MetricsAddr)
	if err != nil {
		return nil, err
	}

	srv := &Server{
		cfg:               cfg,
		log:               cfg.Log,
		zapLog:            cfg.ZapLogger,
		registryHandler:   registryHandler,
		kmsImpl:           kmsImpl,
		metricsSrv:        metricsSrv,
		bootstrapComplete: make(chan struct{}),
	}

	// Create admin handler if admin API is enabled
	if cfg.EnableAdmin {
		if len(cfg.AdminKeys) == 0 {
			return nil, errors.New("admin keys are required when admin API is enabled")
		}

		srv.adminHandler = NewAdminHandler(cfg.Log, cfg.AdminKeys)
	}

	// Set initial ready state
	if !cfg.BootstrapMode {
		srv.isReady.Store(true)
	} else {
		srv.isReady.Store(false)
	}

	// Create HTTP server
	srv.srv = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      srv.getRouter(),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	return srv, nil
}

// getRouter creates and configures the HTTP router with appropriate endpoints.
// The router's configuration depends on the server's mode (bootstrap vs. normal).
func (srv *Server) getRouter() http.Handler {
	mux := chi.NewRouter()

	// Always add middleware
	mux.Use(middleware.RequestID)
	mux.Use(middleware.RealIP)
	mux.Use(middleware.Recoverer)

	// Add admin routes if enabled
	if srv.cfg.EnableAdmin && srv.adminHandler != nil {
		mux.Group(func(r chi.Router) {
			r.Use(srv.httpLogger)
			mux.Mount("/admin", srv.adminHandler.AdminRouter())
		})
	}

	// Add registry API routes if not in bootstrap mode or if registry handler is available
	if !srv.cfg.BootstrapMode || srv.registryHandler != nil {
		// API endpoints with contract address in URL path
		mux.With(srv.httpLogger).Post("/api/attested/register/{contract_address}", srv.handleRegister)
		mux.With(srv.httpLogger).Get("/api/public/app_metadata/{contract_address}", srv.handleAppMetadata)
	}

	// Health and diagnostic endpoints
	mux.With(srv.httpLogger).Get("/livez", srv.handleLivenessCheck)
	mux.With(srv.httpLogger).Get("/readyz", srv.handleReadinessCheck)
	mux.With(srv.httpLogger).Get("/drain", srv.handleDrain)
	mux.With(srv.httpLogger).Get("/undrain", srv.handleUndrain)

	if srv.cfg.EnablePprof {
		srv.log.Info("pprof API enabled")
		mux.Mount("/debug", middleware.Profiler())
	}

	return mux
}

// httpLogger is a middleware that logs HTTP requests using structured logging.
// It captures request method, path, status code, and timing information.
func (srv *Server) httpLogger(next http.Handler) http.Handler {
	return httplogger.LoggingMiddlewareSlog(srv.log, next)
}

// handleRegister delegates TEE instance registration requests to the registry handler.
func (srv *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	// In bootstrap mode, reject requests until bootstrap is complete
	if srv.cfg.BootstrapMode && !srv.isReady.Load() {
		http.Error(w, "Server is bootstrapping, please wait", http.StatusServiceUnavailable)
		return
	}

	srv.mu.RLock()
	handler := srv.registryHandler
	srv.mu.RUnlock()

	if handler == nil {
		http.Error(w, "Registry handler not available", http.StatusServiceUnavailable)
		return
	}

	handler.HandleRegister(w, r)
}

// handleAppMetadata delegates application metadata requests to the registry handler.
func (srv *Server) handleAppMetadata(w http.ResponseWriter, r *http.Request) {
	// In bootstrap mode, reject requests until bootstrap is complete
	if srv.cfg.BootstrapMode && !srv.isReady.Load() {
		http.Error(w, "Server is bootstrapping, please wait", http.StatusServiceUnavailable)
		return
	}

	srv.mu.RLock()
	handler := srv.registryHandler
	srv.mu.RUnlock()

	if handler == nil {
		http.Error(w, "Registry handler not available", http.StatusServiceUnavailable)
		return
	}

	handler.HandleAppMetadata(w, r)
}

// handleLivenessCheck provides a simple health check to verify the server is running.
// It always returns HTTP 200 with a JSON response indicating the server is alive.
func (srv *Server) handleLivenessCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"alive"}`))
}

// handleReadinessCheck verifies if the server is ready to accept requests.
// It returns HTTP 200 if ready or HTTP 503 if draining or shutting down.
func (srv *Server) handleReadinessCheck(w http.ResponseWriter, r *http.Request) {
	if !srv.isReady.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"not ready"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ready"}`))
}

// handleDrain marks the server as not ready and initiates graceful shutdown.
// This allows load balancers to stop sending new requests before shutdown.
func (srv *Server) handleDrain(w http.ResponseWriter, r *http.Request) {
	if !srv.isReady.Swap(false) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"already draining"}`))
		return
	}

	srv.log.Info("Server marked as not ready")

	// Use a goroutine to avoid blocking the request handler
	go func() {
		// Wait for the drain duration to allow load balancers to detect the change
		time.Sleep(srv.cfg.DrainDuration)
		srv.log.Info("Drain period completed")
	}()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"draining"}`))
}

// handleUndrain marks the server as ready to accept new requests.
// This can be used to cancel a drain operation before shutdown.
func (srv *Server) handleUndrain(w http.ResponseWriter, r *http.Request) {
	if srv.isReady.Swap(true) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"already ready"}`))
		return
	}

	srv.log.Info("Server marked as ready")

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ready"}`))
}

// WaitForBootstrap waits for the KMS bootstrap process to complete.
// This should only be called when the server is in bootstrap mode.
//
// Parameters:
//   - ctx: Context for cancellation and timeout
//
// Returns:
//   - The bootstrapped ShamirKMS if successful
//   - Error if bootstrap fails or times out
func (srv *Server) WaitForBootstrap(ctx context.Context) (*kms.ShamirKMS, error) {
	if !srv.cfg.BootstrapMode || srv.adminHandler == nil {
		return nil, errors.New("server not in bootstrap mode or admin handler not available")
	}

	// Wait for admin bootstrap to complete
	if err := srv.adminHandler.WaitForBootstrap(ctx); err != nil {
		return nil, fmt.Errorf("bootstrap timeout: %w", err)
	}

	// Get the bootstrapped KMS
	shamirKMS := srv.adminHandler.GetKMS()
	if shamirKMS == nil {
		return nil, errors.New("failed to get initialized KMS")
	}

	// Update server state
	srv.mu.Lock()
	srv.kmsImpl = shamirKMS
	srv.mu.Unlock()

	// Mark server as ready
	srv.isReady.Store(true)

	// Signal bootstrap completion
	close(srv.bootstrapComplete)

	srv.log.Info("KMS bootstrap completed successfully")
	return shamirKMS, nil
}

// SetRegistryHandler updates the registry handler with a new instance.
// This is used after bootstrap to configure the registry handler with the bootstrapped KMS.
//
// Parameters:
//   - handler: The new registry handler
func (srv *Server) SetRegistryHandler(handler *Handler) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	srv.registryHandler = handler
}

// GetKMS returns the current KMS implementation.
//
// Returns:
//   - The current KMS implementation
func (srv *Server) GetKMS() interfaces.KMS {
	srv.mu.RLock()
	defer srv.mu.RUnlock()
	return srv.kmsImpl
}

// RunInBackground starts the HTTP and metrics servers in separate goroutines.
// It doesn't block the calling goroutine, allowing concurrent operations.
func (srv *Server) RunInBackground() {
	// Start metrics server if configured
	if srv.cfg.MetricsAddr != "" {
		go func() {
			srv.log.With("metricsAddress", srv.cfg.MetricsAddr).Info("Starting metrics server")
			err := srv.metricsSrv.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				srv.log.Error("Metrics server failed", "err", err)
			}
		}()
	}

	// Start HTTP server
	go func() {
		srv.log.Info("Starting HTTP server", "listenAddress", srv.cfg.ListenAddr)
		if err := srv.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srv.log.Error("HTTP server failed", "err", err)
		}
	}()
}

// Shutdown gracefully stops the HTTP and metrics servers.
// It waits for in-flight requests to complete up to the configured timeout.
func (srv *Server) Shutdown() {
	// Shutdown API server
	ctx, cancel := context.WithTimeout(context.Background(), srv.cfg.GracefulShutdownDuration)
	defer cancel()
	if err := srv.srv.Shutdown(ctx); err != nil {
		srv.log.Error("Graceful HTTP server shutdown failed", "err", err)
	} else {
		srv.log.Info("HTTP server gracefully stopped")
	}

	// Shutdown metrics server if started
	if len(srv.cfg.MetricsAddr) != 0 {
		ctx, cancel := context.WithTimeout(context.Background(), srv.cfg.GracefulShutdownDuration)
		defer cancel()

		if err := srv.metricsSrv.Shutdown(ctx); err != nil {
			srv.log.Error("Graceful metrics server shutdown failed", "err", err)
		} else {
			srv.log.Info("Metrics server gracefully stopped")
		}
	}
}
