package serviceresolver

import (
	"github.com/miekg/dns"
	"github.com/ruteri/tee-service-provisioning-backend/interfaces"
)

type ServiceMetadata struct {
	PKI interfaces.AppPKI
	IPs []string
}

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
