package kms

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
)

type AttestationProvider interface {
	Attest(userData [64]byte) ([]byte, error)
}

type RemoteAttestationProvider struct {
	Address string
}

func (p *RemoteAttestationProvider) Attest(userData [64]byte) ([]byte, error) {
	extraDataHex := hex.EncodeToString(userData[:])

	url := fmt.Sprintf("%s/attest/%s", p.Address, extraDataHex)
	resp, err := http.DefaultClient.Get(url)
	if err != nil {
		return nil, fmt.Errorf("calling remote quote provider: %w", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("remote quote provider returned status %d: %s", resp.StatusCode, string(body))
	}

	// Read the quote
	rawQuote, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading quote from response: %w", err)
	}
	return rawQuote, nil
}
