package proxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/ruteri/tee-service-provisioning-backend/instanceutils"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

type AppResolver = instanceutils.AppResolver

// CertificateManager handles TLS certificate operations for secure communication between TEE instances.
// It provides methods for certificate verification and validation.
type CertificateManager interface {
	// GetClientCertificate returns our application's certificate for outgoing connections.
	// The certificate identifies our instance to other TEE instances.
	GetClientCertificate(*tls.CertificateRequestInfo) (*tls.Certificate, error)

	// GetConfigForClient returns a TLS config for incoming connections based on the client hello.
	// This configures server-side TLS for verifying client certificates.
	GetConfigForClient(*tls.ClientHelloInfo) (*tls.Config, error)

	// CACertFor returns the CA certificate for a specific application contract.
	// This is used to verify the identity of instances from other applications.
	CACertFor(interfaces.ContractAddress) (*x509.Certificate, error)
}

// RouterConfig contains configuration for the router.
// It defines parameters for routing requests between TEE instances.
type RouterConfig struct {
	// The application's contract address
	DefaultAppContractAddress interfaces.ContractAddress

	// Certificate manager for TLS handling
	CertManager CertificateManager

	// Application resolver
	Resolver AppResolver

	// Address for incoming requests from other instances
	IngressListenAddr string

	// Address for outgoing requests to other instances
	EgressListenAddr string

	// Routing: app addr -> local endpoint
	Routes map[interfaces.ContractAddress]string

	// Public endpoint for end-user (non-TEE) requests
	PublicEndpoint string

	// Default request timeout
	RequestTimeout time.Duration

	// Logger for operational insights
	Log *slog.Logger
}

// HTTPRouter handles routing requests between TEE instances.
// It provides secure communication channels between instances.
type HTTPRouter struct {
	config        RouterConfig
	egressServer  *http.Server
	ingressServer *http.Server

	// Cache of HTTP transports per target application
	transportCache     map[string]*http.Transport
	transportCacheLock sync.RWMutex

	// Random source for load balancing
	rand *rand.Rand
	mu   sync.RWMutex
}

// NewHTTPRouter creates a new HTTP router/proxy for TEE instance communication.
// Parameters:
//   - config: Router configuration including addresses, TLS settings, and routes
func NewHTTPRouter(config RouterConfig) (*HTTPRouter, error) {
	// Set default request timeout if not provided
	if config.RequestTimeout == 0 {
		config.RequestTimeout = 30 * time.Second
	}

	router := &HTTPRouter{
		config:         config,
		transportCache: make(map[string]*http.Transport),
		rand:           rand.New(rand.NewSource(time.Now().UnixNano())),
	}

	// Configure egress (outgoing) router
	emux := chi.NewRouter()
	emux.Use(middleware.Logger)
	emux.Use(middleware.Recoverer)
	emux.HandleFunc("/*", router.handleEgressRequest)

	router.egressServer = &http.Server{
		Addr:    config.EgressListenAddr,
		Handler: emux,
	}

	// Configure ingress (incoming) router
	imux := chi.NewRouter()
	imux.Use(middleware.Logger)
	imux.Use(middleware.Recoverer)
	imux.HandleFunc("/*", router.handleIngressRequest)

	router.ingressServer = &http.Server{
		Addr:    config.IngressListenAddr,
		Handler: imux,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
			GetConfigForClient: config.CertManager.GetConfigForClient,
		},
	}

	return router, nil
}

// RunInBackground starts the HTTP router in separate goroutines
func (r *HTTPRouter) RunInBackground() {
	// Start egress server
	go func() {
		r.config.Log.Info("Starting HTTP egress server", "addr", r.egressServer.Addr)
		if err := r.egressServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			r.config.Log.Error("HTTP egress server stopped", "err", err)
		}
	}()

	// Start ingress server
	go func() {
		r.config.Log.Info("Starting HTTP ingress server with TLS", "addr", r.ingressServer.Addr)
		if err := r.ingressServer.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			r.config.Log.Error("HTTP ingress server stopped", "err", err)
		}
	}()
}

// Shutdown gracefully stops the HTTP router servers
func (r *HTTPRouter) Shutdown(ctx context.Context) error {
	var egressErr, ingressErr error

	// Shutdown egress server
	egressCtx, egressCancel := context.WithTimeout(ctx, 5*time.Second)
	defer egressCancel()

	egressErr = r.egressServer.Shutdown(egressCtx)
	if egressErr != nil {
		r.config.Log.Error("Failed to gracefully shutdown egress server", "err", egressErr)
	}

	// Shutdown ingress server
	ingressCtx, ingressCancel := context.WithTimeout(ctx, 5*time.Second)
	defer ingressCancel()

	ingressErr = r.ingressServer.Shutdown(ingressCtx)
	if ingressErr != nil {
		r.config.Log.Error("Failed to gracefully shutdown ingress server", "err", ingressErr)
	}

	// Return an error if either shutdown failed
	if egressErr != nil {
		return egressErr
	}
	return ingressErr
}

// handleIngressRequest processes incoming requests from other TEE instances or users.
// It validates the TLS connection, verifies the client's certificate against the
// appropriate CA, and routes the request to the configured local endpoint.
//
// For non-TLS connections (typically end-user requests), it routes to the public
// endpoint if configured. For TLS connections from authenticated TEE instances,
// it verifies the requesting application's identity and routes to the appropriate
// internal service based on the Routes configuration.
//
// Parameters:
//   - w: HTTP response writer for sending the response
//   - req: The incoming HTTP request with TLS information
func (r *HTTPRouter) handleIngressRequest(w http.ResponseWriter, req *http.Request) {
	// Handle requests without TLS (non-authenticated requests)
	if req.TLS == nil || len(req.TLS.VerifiedChains) == 0 {
		// This is an end user request - route to the public endpoint if configured
		if r.config.PublicEndpoint == "" {
			r.config.Log.Warn("Received non-TLS request but no public endpoint configured")
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Proxy to the public endpoint
		target, err := url.Parse(r.config.PublicEndpoint)
		if err != nil {
			r.config.Log.Error("Failed to parse public endpoint URL", "endpoint", r.config.PublicEndpoint, "err", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(target)
		proxy.ServeHTTP(w, req)
		return
	}

	// TLS verified request from another TEE instance
	// Extract the requesting app address from ServerName
	var requestingApp interfaces.ContractAddress

	peerCertCNBytes, err := hex.DecodeString(strings.Split(req.TLS.VerifiedChains[0][0].Subject.CommonName, ".")[0])
	if err != nil || len(peerCertCNBytes) != 20 {
		r.config.Log.Error("Bad peer cert CN")
		http.Error(w, "Bad peer cert CN", http.StatusBadRequest)
		return
	}
	copy(requestingApp[:], peerCertCNBytes)

	// Verify the CA certificate matches what we expect for this app
	caCert := req.TLS.VerifiedChains[0][len(req.TLS.VerifiedChains[0])-1] // Root CA
	expectedCA, err := r.config.CertManager.CACertFor(requestingApp)
	if err != nil {
		r.config.Log.Error("Failed to get CA certificate for requesting app",
			"app", hex.EncodeToString(requestingApp[:]), "err", err)
		http.Error(w, "Failed to verify application identity", http.StatusInternalServerError)
		return
	}

	if !caCert.Equal(expectedCA) {
		r.config.Log.Warn("CA certificate mismatch",
			"app", hex.EncodeToString(requestingApp[:]),
			"expected", expectedCA.Subject.String(),
			"actual", caCert.Subject.String())
		http.Error(w, "CA certificate mismatch", http.StatusForbidden)
		return
	}

	// Find the route for this application
	targetRoute, exists := r.config.Routes[requestingApp]
	if !exists {
		r.config.Log.Warn("No route configured for application", "app", hex.EncodeToString(requestingApp[:]))
		http.Error(w, "Application not routable", http.StatusNotFound)
		return
	}

	// Proxy the request to the target route
	target, err := url.Parse(targetRoute)
	if err != nil {
		r.config.Log.Error("Invalid target route", "route", targetRoute, "err", err)
		http.Error(w, "Internal routing error", http.StatusInternalServerError)
		return
	}

	// Create and configure the reverse proxy
	proxy := httputil.NewSingleHostReverseProxy(target)

	// Update request for the backend service
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Header.Add("X-Forwarded-App", hex.EncodeToString(requestingApp[:]))
		req.Header.Add("X-Forwarded-Proto", "https")
	}

	// Proxy the request
	proxy.ServeHTTP(w, req)
}

// getOrCreateTransport gets a cached HTTP transport for a target application or creates a new one.
// The transport is configured with TLS settings appropriate for secure communication
// with the target application, including client certificates and CA verification.
//
// This method ensures that:
//   - Each target application has a dedicated transport with the correct TLS configuration
//   - Transports are cached for performance
//   - Client certificates are properly presented for mutual TLS authentication
//
// Parameters:
//   - sourceAppAddr: The source application's contract address (for SNI routing)
//   - targetAppAddr: The target application's contract address
//   - targetAppCAPEM: The target application's CA certificate in PEM format
//
// Returns:
//   - Configured HTTP transport for the target application
//   - Error if transport creation fails
func (r *HTTPRouter) getOrCreateTransport(sourceAppAddr interfaces.ContractAddress, targetAppAddr interfaces.ContractAddress, targetAppCAPEM interfaces.CACert) (*http.Transport, error) {
	// Create cache key from app address
	cacheKey := hex.EncodeToString(targetAppAddr[:])

	// Check cache first (read lock)
	r.transportCacheLock.RLock()
	transport, exists := r.transportCache[cacheKey]
	r.transportCacheLock.RUnlock()

	if exists {
		return transport, nil
	}

	targetAppCABlock, _ := pem.Decode(targetAppCAPEM)
	if targetAppCABlock.Bytes == nil || targetAppCABlock.Type != "CERTIFICATE" {
		r.config.Log.Warn("could not decode target app CA certificate", "app", cacheKey, "ca cert", string(targetAppCAPEM))
		return nil, errors.New("could not decode target app CA certificate")
	}

	targetAppCA, err := x509.ParseCertificate(targetAppCABlock.Bytes)
	if err != nil {
	}

	// Not in cache, create new transport (write lock)
	r.transportCacheLock.Lock()
	defer r.transportCacheLock.Unlock()

	// Check again in case another goroutine created it while we were waiting
	transport, exists = r.transportCache[cacheKey]
	if exists {
		return transport, nil
	}

	// Create cert pool with the app's CA
	appCertPool := x509.NewCertPool()
	appCertPool.AddCert(targetAppCA)

	// TODO: rework to use cert for the source app

	// Create a new transport with proper TLS configuration
	transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			GetClientCertificate: r.config.CertManager.GetClientCertificate,
			RootCAs:              appCertPool,
			InsecureSkipVerify:   true,
			ServerName:           hex.EncodeToString(sourceAppAddr[:]) + ".app",
		},
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	// Store in cache
	r.transportCache[cacheKey] = transport

	return transport, nil
}

// pickRandomInstance selects a random instance from the available instances
func (r *HTTPRouter) pickRandomInstance(instances []string) string {
	if len(instances) == 0 {
		return ""
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	idx := r.rand.Intn(len(instances))
	return instances[idx]
}

// handleEgressRequest processes outgoing requests to other TEE instances.
// It routes requests based on special headers:
//   - X-Source-App: The source application address (defaults to DefaultAppContractAddress)
//   - X-Target-App: The target application address (defaults to source app - self-call)
//   - X-Request-Type: The routing pattern ("any" for single instance, "all" for broadcast)
//
// For "any" requests, it selects a random instance for load balancing.
// For "all" requests, it broadcasts to all instances and aggregates responses.
//
// Parameters:
//   - w: HTTP response writer for sending the response
//   - req: The outgoing HTTP request with routing headers
func (r *HTTPRouter) handleEgressRequest(w http.ResponseWriter, req *http.Request) {
	// Extract routing information from headers
	sourceApp := req.Header.Get("X-Source-App")
	targetApp := req.Header.Get("X-Target-App")
	requestType := req.Header.Get("X-Request-Type")

	// Remove routing headers before forwarding
	req.Header.Del("X-Target-App")
	req.Header.Del("X-Request-Type")

	// Use default app if source not specified
	if sourceApp == "" {
		sourceApp = hex.EncodeToString(r.config.DefaultAppContractAddress[:])
	}

	// Parse source app address
	var sourceAppAddr interfaces.ContractAddress
	sourceAppAddrBytes, err := hex.DecodeString(sourceApp)
	if err != nil || len(sourceAppAddrBytes) < 20 {
		r.config.Log.Error("Invalid source app address", "sourceApp", sourceApp, "err", err)
		http.Error(w, "Invalid source application address", http.StatusBadRequest)
		return
	}
	copy(sourceAppAddr[:], sourceAppAddrBytes[:20])

	// If no target app specified, use source (self-call)
	if targetApp == "" {
		targetApp = sourceApp
	}

	// Parse target app address
	var targetAppAddr interfaces.ContractAddress
	targetAppAddrBytes, err := hex.DecodeString(targetApp)
	if err != nil || len(targetAppAddrBytes) < 20 {
		r.config.Log.Error("Invalid target app address", "targetApp", targetApp, "err", err)
		http.Error(w, "Invalid target application address", http.StatusBadRequest)
		return
	}
	copy(targetAppAddr[:], targetAppAddrBytes[:20])

	// Resolve instances for the target app
	targetAppCAPEM, targetAppInstances, err := r.config.Resolver.GetAppMetadata(targetAppAddr)
	if err != nil {
		r.config.Log.Error("Failed to resolve instances for target app",
			"app", targetApp, "err", err)
		http.Error(w, "Failed to resolve target application instances", http.StatusBadGateway)
		return
	}

	// Check if we have any instances available
	if len(targetAppInstances) == 0 {
		r.config.Log.Warn("No instances available for target app", "app", targetApp)
		http.Error(w, "No instances available for target application", http.StatusServiceUnavailable)
		return
	}

	// Get or create transport for the target app
	transport, err := r.getOrCreateTransport(sourceAppAddr, targetAppAddr, targetAppCAPEM)
	if err != nil {
		r.config.Log.Error("Failed to create transport for target app",
			"app", targetApp, "err", err)
		http.Error(w, "Failed to create secure connection to target application", http.StatusInternalServerError)
		return
	}

	// Set ourselves as the host for routing on the server
	req.Host = fmt.Sprintf("%s.app", sourceApp)

	// Handle different request types
	if requestType == "" || requestType == "any" {
		// Single instance request - pick a random instance for load balancing
		instanceAddr := r.pickRandomInstance(targetAppInstances)
		targetURL, err := url.Parse(fmt.Sprintf("https://%s", instanceAddr))

		if err != nil {
			r.config.Log.Error("Failed to parse target instance URL",
				"instance", instanceAddr, "err", err)
			http.Error(w, "Invalid target instance address", http.StatusInternalServerError)
			return
		}

		// Set up the reverse proxy
		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		proxy.Transport = transport

		// Proxy the request
		proxy.ServeHTTP(w, req)
		return
	} else if requestType == "all" {
		// Broadcast request to all instances and collect responses
		r.handleBroadcastRequest(w, req, targetAppInstances, transport)
		return
	}

	// If we get here, the request type is invalid
	r.config.Log.Warn("Invalid request type", "type", requestType)
	http.Error(w, "Invalid request type", http.StatusBadRequest)
}

// handleBroadcastRequest sends a request to all instances of a target application
// and aggregates the responses. This implements the "all" routing pattern, useful
// for operations that need to query or update all instances simultaneously.
//
// The method:
//   - Sends requests to all instances in parallel
//   - Collects responses with timeouts
//   - Includes instance-specific information in the response
//   - Aggregates all responses into a single JSON response
//
// Parameters:
//   - w: HTTP response writer for sending the aggregated response
//   - req: The original HTTP request to broadcast
//   - targetInstances: List of instance addresses to send the request to
//   - transport: HTTP transpo
func (r *HTTPRouter) handleBroadcastRequest(
	w http.ResponseWriter,
	req *http.Request,
	targetInstances []string,
	transport *http.Transport,
) {
	// Define response structure
	type InstanceResponse struct {
		Instance   string          `json:"instance"`
		StatusCode int             `json:"statusCode"`
		Error      string          `json:"error,omitempty"`
		Headers    http.Header     `json:"headers,omitempty"`
		Body       json.RawMessage `json:"body,omitempty"`
	}

	// Create HTTP client with the transport
	client := http.Client{Transport: transport}

	// Create channel for responses
	responsesCh := make(chan InstanceResponse, len(targetInstances))

	// Set up a context with timeout
	ctx, cancel := context.WithTimeout(req.Context(), r.config.RequestTimeout)
	defer cancel()

	// Send request to each instance in parallel
	for _, instance := range targetInstances {
		go func(instance string) {
			// Clone the request for this instance
			reqClone := req.Clone(ctx)

			// Create target URL
			targetURL, err := url.Parse(fmt.Sprintf("https://%s", instance))
			if err != nil {
				responsesCh <- InstanceResponse{
					Instance: instance,
					Error:    fmt.Sprintf("invalid instance URL: %v", err),
				}
				return
			}

			// Prepare the request
			httputil.NewSingleHostReverseProxy(targetURL).Director(reqClone)

			// Send the request
			resp, err := client.Do(reqClone)
			if err != nil {
				responsesCh <- InstanceResponse{
					Instance: instance,
					Error:    fmt.Sprintf("request failed: %v", err),
				}
				return
			}
			defer resp.Body.Close()

			// Read response body
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				responsesCh <- InstanceResponse{
					Instance:   instance,
					StatusCode: resp.StatusCode,
					Headers:    resp.Header,
					Error:      fmt.Sprintf("failed to read response: %v", err),
				}
				return
			}

			// Create response object
			responsesCh <- InstanceResponse{
				Instance:   instance,
				StatusCode: resp.StatusCode,
				Headers:    resp.Header,
				Body:       bodyBytes,
			}
		}(instance)
	}

	// Collect responses with timeout
	responses := make([]InstanceResponse, 0, len(targetInstances))

	// Wait for all responses or timeout
	for i := 0; i < len(targetInstances); i++ {
		select {
		case resp := <-responsesCh:
			responses = append(responses, resp)
		case <-ctx.Done():
			// Add timeout information and break
			r.config.Log.Warn("Timeout waiting for instance responses",
				"completed", len(responses), "total", len(targetInstances))
			responses = append(responses, InstanceResponse{
				Error: "request timeout",
			})
			break
		}
	}

	// Marshal the aggregated responses to JSON
	jsonResp, err := json.Marshal(map[string]interface{}{
		"responses": responses,
		"count":     len(responses),
		"total":     len(targetInstances),
	})
	if err != nil {
		r.config.Log.Error("Failed to marshal response", "err", err)
		http.Error(w, "Failed to process response", http.StatusInternalServerError)
		return
	}

	// Set content type and write response
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	if _, err := w.Write(jsonResp); err != nil {
		r.config.Log.Error("Failed to write response", "err", err)
	}
}
