// Package main (cmd/operator) implements an operator client for the TEE Registry System. This tool
// provides the ability for authorized operators to cryptographically sign the public
// keys of TEE instances during their provisioning process, providing an additional
// layer of authorization beyond attestation verification.
//
// In the TEE Registry System's security model, operator signatures serve as an explicit
// authorization mechanism for TEE instance provisioning. When a new TEE instance boots,
// it generates a keypair and exposes the public key through an HTTP endpoint. An
// authorized operator can use this tool to:
//
//  1. Retrieve the instance's public key
//  2. Sign it using their Ethereum private key
//  3. Submit the signature back to the instance
//
// The TEE instance then includes this signature as an X.509 extension in its Certificate
// Signing Request (CSR). During registration, the provisioning server verifies both the
// attestation evidence and the operator's signature, ensuring that only instances
// approved by authorized operators can register with the system.
//
// This two-factor authorization (attestation + operator signature) provides enhanced
// security for sensitive deployments by requiring explicit operator approval for each
// TEE instance.
package main
