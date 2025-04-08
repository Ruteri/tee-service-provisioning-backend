/*
Package servers implements HTTP server functionality for a TEE registry system.

This package handles HTTP server configuration, lifecycle management, and routing
for both the Registry API and Admin API components of the system.

# Server Types

The package provides a unified Server implementation that can be configured for:

1. Registry API mode - Serving TEE instance registration and configuration endpoints
2. Admin API mode - Providing KMS bootstrapping endpoints
3. Combined mode - Supporting both Registry and Admin APIs

# Server Configuration

ServerConfig provides comprehensive configuration options:

- Network listening addresses for main API and metrics
- Logging configuration
- Timeout settings for various operations
- Graceful shutdown parameters
- pprof debugging configuration
- KMS bootstrapping settings

# Server Lifecycle

The Server implements a complete lifecycle management system:

- Initialization with appropriate configuration and handlers
- Background operation to avoid blocking the main application
- Graceful shutdown with connection draining
- Metrics exposure through a dedicated port
- Health and readiness probes for Kubernetes integration

# Metrics Support

The server integrates with the metrics package to export:

- HTTP server metrics (requests, errors, latencies)
- System metrics (memory, CPU, GC)
- Custom application metrics

# Bootstrap Process

When configured for KMS bootstrapping, the server:

1. Starts a dedicated Admin API server
2. Waits for administrators to complete the bootstrap process
3. Initializes the Registry API server with the bootstrapped KMS
4. Provides status updates during the bootstrap process

# Example Usage

	// Create server configuration
	cfg := &servers.ServerConfig{
	    ListenAddr:      ":8080",
	    MetricsAddr:     ":9090",
	    EnablePprof:     true,
	    Log:             logger,
	    DrainDuration:   30 * time.Second,
	    ReadTimeout:     5 * time.Second,
	    WriteTimeout:    10 * time.Second,
	}

	// Create and run server
	server, err := servers.New(cfg, handler)
	if err != nil {
	    log.Fatalf("Failed to create server: %v", err)
	}
	server.RunInBackground()
	defer server.Shutdown()
*/
package servers
