package cryptoutils

import (
	"encoding/json"
	"fmt"
	"net/http"
)

const (
	// AttestationTypeHeader specifies the TEE attestation mechanism used.
	// Supported values: "azure-tdx", "qemu-tdx"
	AttestationTypeHeader = "X-Flashbots-Attestation-Type"

	// MeasurementHeader contains a JSON-encoded map of measurement values.
	// Format: {"0":"00", "1":"01", ...} mapping register index to hex value.
	MeasurementHeader = "X-Flashbots-Measurement"
)

// MeasurementsFromATLS extracts attestation type and measurements from client request
// Currently implementation assumes measurements are verified by cvm-reverse-proxy and
// the correct (and valid) headers have been set.
func MeasurementsFromATLS(r *http.Request) (AttestationType, map[int]string, error) {
	// Parse attestation type from header
	attestationType, err := AttestationTypeFromString(r.Header.Get(AttestationTypeHeader))
	if err != nil {
		return AttestationType{}, nil, fmt.Errorf("could not extract attestation type from header %s: %w", r.Header.Get(AttestationTypeHeader), err)
	}

	// Parse measurements from header
	measurementsJSON := r.Header.Get(MeasurementHeader)
	if measurementsJSON == "" {
		return AttestationType{}, nil, fmt.Errorf("measurements header missing")
	}

	// Parse measurements JSON to map
	var measurements map[int]string
	if err := json.Unmarshal([]byte(measurementsJSON), &measurements); err != nil {
		return AttestationType{}, nil, fmt.Errorf("could not parse measurements: %w", err)
	}

	return attestationType, measurements, nil
}
