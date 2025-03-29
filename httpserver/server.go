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

type HTTPServerConfig struct {
	ListenAddr  string
	MetricsAddr string
	EnablePprof bool
	Log         *slog.Logger
	ZapLogger   *zap.Logger // Added to support our handler

	DrainDuration            time.Duration
	GracefulShutdownDuration time.Duration
	ReadTimeout              time.Duration
	WriteTimeout             time.Duration
}

type Server struct {
	cfg     *HTTPServerConfig
	isReady atomic.Bool
	log     *slog.Logger
	zapLog  *zap.Logger

	srv        *http.Server
	metricsSrv *metrics.MetricsServer
	handler    *Handler // Added to store our handler
}

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

// Update to getRouter() method in server.go
func (srv *Server) getRouter() http.Handler {
	mux := chi.NewRouter()

	// Updated routes with contract address in URL path
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

func (srv *Server) httpLogger(next http.Handler) http.Handler {
	return httplogger.LoggingMiddlewareSlog(srv.log, next)
}

// Handlers that delegate to the improved Handler implementation
func (srv *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	srv.handler.HandleRegister(w, r)
}

func (srv *Server) handleAppMetadata(w http.ResponseWriter, r *http.Request) {
	srv.handler.HandleAppMetadata(w, r)
}

func (srv *Server) handleLivenessCheck(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"alive"}`))
}

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

func (srv *Server) handleDrain(w http.ResponseWriter, r *http.Request) {
	if !srv.isReady.Swap(false) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"already draining"}`))
		return
	}
	
	srv.log.Info("Server marked as not ready")
	
	// UPDATED: Use a goroutine to avoid blocking the request handler
	go func() {
		// Wait for the drain duration to allow load balancers to detect the change
		time.Sleep(srv.cfg.DrainDuration)
		srv.log.Info("Drain period completed")
	}()
	
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"status":"draining"}`))
}

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

func (srv *Server) RunInBackground() {
	// metrics
	if srv.cfg.MetricsAddr != "" {
		go func() {
			srv.log.With("metricsAddress", srv.cfg.MetricsAddr).Info("Starting metrics server")
			err := srv.metricsSrv.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				srv.log.Error("HTTP server failed", "err", err)
			}
		}()
	}

	// api
	go func() {
		srv.log.Info("Starting HTTP server", "listenAddress", srv.cfg.ListenAddr)
		if err := srv.srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			srv.log.Error("HTTP server failed", "err", err)
		}
	}()
}

func (srv *Server) Shutdown() {
	// api
	ctx, cancel := context.WithTimeout(context.Background(), srv.cfg.GracefulShutdownDuration)
	defer cancel()
	if err := srv.srv.Shutdown(ctx); err != nil {
		srv.log.Error("Graceful HTTP server shutdown failed", "err", err)
	} else {
		srv.log.Info("HTTP server gracefully stopped")
	}

	// metrics
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
