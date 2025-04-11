// Package server provides a reusable HTTP server implementation with common functionality
// for TEE registry system components.
//
// The server package implements a base HTTP server with standard health endpoints,
// graceful shutdown capabilities, metrics, and flexible routing. This allows different
// components of the TEE registry system to reuse common server functionality while
// implementing their specific endpoints.
//
// # Key Components
//
//   - BaseServer: Core HTTP server with health checks, metrics, and lifecycle management
//   - RouteRegistrar: Interface for components to register their routes with the server
//
// # Server Lifecycle
//
// The BaseServer implements a complete server lifecycle:
//
//  1. Initialization: Configure server with HTTP settings and route registrars
//  2. Startup: Run HTTP and metrics servers in background goroutines
//  3. Operation: Handle requests with proper logging and monitoring
//  4. Readiness Control: Support drain/undrain operations for load balancers
//  5. Graceful Shutdown: Wait for in-flight requests to complete
//
// # Health and Diagnostics
//
// All servers built with BaseServer automatically include:
//
//   - Liveness Check: Simple endpoint to verify server is running (/livez)
//   - Readiness Check: Endpoint indicating if server is ready to accept requests (/readyz)
//   - Drain Control: Endpoints to prepare for graceful shutdown (/drain, /undrain)
//   - Metrics: Optional Prometheus-compatible metrics endpoint
//   - Profiling: Optional pprof debugging endpoints when enabled
//
// # Usage Example
//
//	// Implement the RouteRegistrar interface for your handler
//	func (h *MyHandler) RegisterRoutes(r chi.Router) {
//	    r.Get("/api/resource/{id}", h.HandleGetResource)
//	    r.Post("/api/resource", h.HandleCreateResource)
//	}
//
//	// Create your specialized server with the base server embedded
//	type MyServer struct {
//	    *server.BaseServer
//	    handler *MyHandler
//	}
//
//	// Create a new server instance
//	func NewMyServer(cfg *api.HTTPServerConfig) (*MyServer, error) {
//	    handler := NewMyHandler()
//
//	    // Create base server with the handler as a route registrar
//	    baseServer, err := server.New(cfg, handler)
//	    if err != nil {
//	        return nil, err
//	    }
//
//	    return &MyServer{
//	        BaseServer: baseServer,
//	        handler:    handler,
//	    }, nil
//	}
//
//	// Use the server
//	srv, _ := NewMyServer(config)
//	srv.RunInBackground()
//	defer srv.Shutdown()
//
// This approach ensures consistent behavior across different server types while
// allowing specialized functionality to be easily added.
package server
