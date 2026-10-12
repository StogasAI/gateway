package attest

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const (
	DefaultSEVGuestPath = "/dev/sev-guest"
	EnvelopeSchemaV1    = "stogas.sev-snp-quote-envelope.v1"
	ProviderSEVGuest    = "sev_guest"
	snpReportSize       = 0x4a0
	snpReportVersionMin = 2
	snpReportVersionMax = 5
	snpReportSigAlgo    = 1
	snpMeasurementStart = 0x90
	snpMeasurementEnd   = 0xc0
)

type Attester interface {
	Quote(ctx context.Context, reportData [64]byte) ([]byte, error)
}

type Envelope struct {
	Schema   string `json:"schema"`
	Provider string `json:"provider"`
	Report   string `json:"report"`
}

func NormalizeReportBlob(report []byte) []byte {
	if isSNPReport(report) {
		return report[:snpReportSize]
	}
	if len(report) < 0x20+snpReportSize {
		return report
	}
	status := binary.LittleEndian.Uint32(report[0:4])
	size := binary.LittleEndian.Uint32(report[4:8])
	if status != 0 || int(size) < snpReportSize || int(size) > len(report)-0x20 {
		return report
	}
	payload := report[0x20 : 0x20+int(size)]
	if !isSNPReport(payload) {
		return report
	}
	return payload[:snpReportSize]
}

func isSNPReport(report []byte) bool {
	if len(report) < snpReportSize {
		return false
	}
	version := binary.LittleEndian.Uint32(report[0:4])
	if version < snpReportVersionMin || version > snpReportVersionMax {
		return false
	}
	vmpl := binary.LittleEndian.Uint32(report[0x30:0x34])
	if vmpl > 3 {
		return false
	}
	sigAlgo := binary.LittleEndian.Uint32(report[0x34:0x38])
	return sigAlgo == snpReportSigAlgo
}

func EncodeEnvelope(envelope Envelope) ([]byte, error) {
	if envelope.Schema == "" {
		envelope.Schema = EnvelopeSchemaV1
	}
	if envelope.Schema != EnvelopeSchemaV1 {
		return nil, fmt.Errorf("unsupported quote envelope schema %q", envelope.Schema)
	}
	if strings.TrimSpace(envelope.Provider) == "" {
		return nil, errors.New("quote envelope provider is required")
	}
	if strings.TrimSpace(envelope.Report) == "" {
		return nil, errors.New("quote envelope report is required")
	}
	return json.Marshal(envelope)
}

func MeasurementHex(envelopeBytes []byte) (string, error) {
	var envelope Envelope
	if err := json.Unmarshal(envelopeBytes, &envelope); err != nil {
		return "", fmt.Errorf("decode quote envelope: %w", err)
	}
	if envelope.Schema != EnvelopeSchemaV1 {
		return "", fmt.Errorf("unsupported quote envelope schema %q", envelope.Schema)
	}
	report, err := base64.RawURLEncoding.DecodeString(envelope.Report)
	if err != nil {
		return "", fmt.Errorf("decode SNP report: %w", err)
	}
	report = NormalizeReportBlob(report)
	if !isSNPReport(report) {
		return "", errors.New("quote envelope does not contain a valid SNP report")
	}
	return hex.EncodeToString(report[snpMeasurementStart:snpMeasurementEnd]), nil
}
