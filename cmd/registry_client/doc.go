// Package main (cmd/registry_client) implements a client for the TEE Registry System's provisioning API.
//
// The registry client provides command-line tools for TEE instance registration
// and application metadata retrieval. It supports Intel TDX attestation verification
// to ensure the authenticity and integrity of TEE applications.
//
// The client supports two main commands:
//
//	register - Register a new TEE instance with the provisioning server by
//	           generating a Certificate Signing Request (CSR) and submitting it
//	           along with attestation evidence. Upon successful registration, the
//	           server returns cryptographic materials and configuration.
//
//	metadata - Retrieve application metadata including the CA certificate, public key,
//	           and attestation evidence. The client also verifies the DCAP attestation
//	           to ensure the authenticity of the application.
//
// During normal operation in a TEE environment, the attestation evidence is
// automatically collected from the platform. For development and testing purposes,
// attestation headers can be manually specified using the debug flags.
//
// The client implements the Report Data verification to ensure that the attestation
// is bound to the specific application contract address and cryptographic materials,
// providing end-to-end verification of the TEE application's identity.
package main
