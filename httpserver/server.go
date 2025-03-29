package httpserver

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/ruteri/poc-tee-registry/common"
	"github.com/ruteri/poc-tee-registry/metrics"
	"github.com/flashbots/go-utils/httplogger"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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
}

// Server represents the HTTP server for the TEE registry service.
// It handles routing, request dispatch, and server lifecycle management.
type Server struct {
	cfg     *HTTPServerConfig
	isReady atomic.Bool
	log     *slog.Logger
	zapLog  *zap.Logger

	srv        *http.Server
	metricsSrv *metrics.MetricsServer
	handler    *Handler
}

// New creates a new HTTP server with the specified configuration and handler.
//
// Parameters:
//   - cfg: Server configuration
//   - handler: Request handler that processes application logic
//
// Returns:
//   - Configured server instance
//   - Error if server creation fails
func New(cfg *HTTPServerConfig, handler *Handler) (srv *Server, err error) {
	metricsSrv, err := metrics.New(common.PackageName, cfg.MetricsAddr)
	if err != nil {
		return nil, err
	}

	srv = &Server{
		cfg:        cfg,
		log:        cfg.Log,
		zapLog:     cfg.ZapLogger,
		srv:        nil,
		metricsSrv: metricsSrv,
		handler:    handler,
	}
	srv.isReady.Store(true)

	srv.srv = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      srv.getRouter(),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	return srv, nil
}

// getRouter creates and configures the HTTP router with all endpoints.
// It sets up routes for registration, app metadata, and health checks.
func (srv *Server) getRouter() http.Handler {
	mux := chi.NewRouter()

	// API endpoints with contract address in URL path
	mux.With(srv.httpLogger).Post("/api/attested/register/{contract_address}", srv.handleRegister)
	mux.With(srv.httpLogger).Get("/api/public/app_metadata/{contract_address}", srv.handleAppMetadata)

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

// handleRegister delegates TEE instance registration requests to the Handler.
func (srv *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	srv.handler.HandleRegister(w, r)
}

// handleAppMetadata delegates application metadata requests to the Handler.
func (srv *Server) handleAppMetadata(w http.ResponseWriter, r *http.Request) {
	srv.handler.HandleAppMetadata(w, r)
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

	// Start API server
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
