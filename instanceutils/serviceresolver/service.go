package serviceresolver

import (
	"github.com/miekg/dns"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

// ServiceMetadata contains the application's PKI and instance IP addresses.
// This information enables secure connection establishment between TEE instances.
type ServiceMetadata struct {
	// PKI contains the application's CA certificate, public key, and attestation
	PKI interfaces.AppPKI
	
	// IPs contains the IP addresses of all registered instances
	IPs []string
}

// ResolveServiceMetadata retrieves application metadata from an onchain discovery contract.
// It fetches the PKI information and resolves all registered domain names to IP addresses.
//
// The discovery contract is expected to implement the OnchainDiscovery interface,
// providing both PKI information and instance domain names registered by operators.
//
// Parameters:
//   - discoveryContract: Onchain contract that implements the OnchainDiscovery interface
//
// Returns:
//   - ServiceMetadata containing PKI information and IP addresses
//   - Error if PKI retrieval or domain resolution fails
func ResolveServiceMetadata(discoveryContract interfaces.OnchainDiscovery) (*ServiceMetadata, error) {
	appIps := []string{}
	domainNames, err := discoveryContract.InstanceDomainNames()
	if err != nil {
		return nil, err
	}

	for _, domain := range domainNames {
		domainIps, err := resolveDomainIPs(domain)
		if err != nil {
			continue
		}

		appIps = append(appIps, domainIps...)
	}

	pki, err := discoveryContract.PKI()
	if err != nil {
		return nil, err
	}

	return &ServiceMetadata{
		PKI: pki,
		IPs: appIps,
	}, nil
}

// resolveDomainIPs resolves a domain name to IP addresses using DNS SRV records.
// It queries the local DNS resolver and extracts the target addresses from SRV records.
//
// Parameters:
//   - domain: Domain name to resolve
//
// Returns:
//   - Slice of IP addresses (target fields from SRV records)
//   - Error if DNS resolution fails
func resolveDomainIPs(domain string) ([]string, error) {
	m1 := new(dns.Msg)
	m1.Id = dns.Id()
	m1.RecursionDesired = true
	m1.Question = make([]dns.Question, 1)
	m1.Question[0] = dns.Question{domain, dns.TypeSRV, dns.ClassINET}

	c := new(dns.Client)
	in, _, err := c.Exchange(m1, "127.0.0.53:53")

	if err != nil {
		return nil, err
	}

	targets := make([]string, 0, len(in.Answer))

	// Parse SRV records from the answer
	for _, answer := range in.Answer {
		if srv, ok := answer.(*dns.SRV); ok {
			targets = append(targets, srv.Target) // Note: ignoring srv.Port here! We are using predefined ports for now
		}
	}

	return targets, nil
}
