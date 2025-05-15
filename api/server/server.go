// Package server provides a base HTTP server implementation with common functionality
// for TEE registry system components.
package server

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/flashbots/go-utils/httplogger"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"go.uber.org/atomic"
)

// RouteRegistrar defines the interface for components that register routes
// with the server's router.
type RouteRegistrar interface {
	// RegisterRoutes registers routes with the provided router
	RegisterRoutes(r chi.Router)
}

// HTTPServerConfig contains all configuration parameters for the HTTP server.
type HTTPServerConfig struct {
	// ListenAddr is the address and port the HTTP server will listen on.
	ListenAddr string

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

// BaseServer provides common HTTP server functionality for different components
// of the TEE registry system.
type BaseServer struct {
	cfg     *HTTPServerConfig
	isReady atomic.Bool
	mu      sync.RWMutex
	log     *slog.Logger

	srv *http.Server
}

// New creates a new BaseServer with the specified configuration.
//
// Parameters:
//   - cfg: Server configuration
//   - routeRegistrars: Components that will register routes with the server
//
// Returns:
//   - Configured server instance
//   - Error if server creation fails
func New(cfg *HTTPServerConfig, routeRegistrars ...RouteRegistrar) (*BaseServer, error) {
	srv := &BaseServer{
		cfg: cfg,
		log: cfg.Log,
	}

	// Create HTTP server with router
	router := srv.CreateRoutes(routeRegistrars)
	srv.srv = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      router,
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	// Server is ready by default
	srv.isReady.Store(true)

	return srv, nil
}

// CreateRoutes configures the HTTP router with middleware and standard endpoints.
func (srv *BaseServer) CreateRoutes(routeRegistrars []RouteRegistrar) http.Handler {
	mux := chi.NewRouter()

	// Add standard middleware
	mux.Use(middleware.RequestID)
	mux.Use(middleware.RealIP)
	mux.Use(middleware.Recoverer)

	// Register component-specific routes
	for _, registrar := range routeRegistrars {
		registrar.RegisterRoutes(mux)
	}

	// Health and diagnostic endpoints
	mux.With(srv.httpLogger).Get("/livez", srv.handleLivenessCheck)
	mux.With(srv.httpLogger).Get("/readyz", srv.handleReadinessCheck)
	mux.With(srv.httpLogger).Get("/drain", srv.handleDrain)
	mux.With(srv.httpLogger).Get("/undrain", srv.handleUndrain)

	return mux
}

// httpLogger is a middleware that logs HTTP requests using structured logging.
func (srv *BaseServer) httpLogger(next http.Handler) http.Handler {
	return httplogger.LoggingMiddlewareSlog(srv.log, next)
}

// handleLivenessCheck provides a simple health check to verify the server is running.
func (srv *BaseServer) handleLivenessCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"alive"}`))
}

// handleReadinessCheck verifies if the server is ready to accept requests.
func (srv *BaseServer) handleReadinessCheck(w http.ResponseWriter, r *http.Request) {
	if !srv.isReady.Load() {
		w.WriteHeader(http.StatusServiceUnavailable)
		w.Write([]byte(`{"status":"not ready"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"ready"}`))
}

// handleDrain marks the server as not ready and initiates graceful shutdown preparation.
func (srv *BaseServer) handleDrain(w http.ResponseWriter, r *http.Request) {
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
func (srv *BaseServer) handleUndrain(w http.ResponseWriter, r *http.Request) {
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

// RunInBackground starts the HTTP in a goroutine.
func (srv *BaseServer) RunInBackground() {
	// Start HTTP server
	go func() {
		srv.log.Info("Starting HTTP server", "listenAddress", srv.cfg.ListenAddr)
		if err := srv.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srv.log.Error("HTTP server failed", "err", err)
		}
	}()
}

// Shutdown gracefully stops the HTTP server
func (srv *BaseServer) Shutdown() {
	// Shutdown API server
	ctx, cancel := context.WithTimeout(context.Background(), srv.cfg.GracefulShutdownDuration)
	defer cancel()
	if err := srv.srv.Shutdown(ctx); err != nil {
		srv.log.Error("Graceful HTTP server shutdown failed", "err", err)
	} else {
		srv.log.Info("HTTP server gracefully stopped")
	}
}
