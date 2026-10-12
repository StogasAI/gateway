package attest

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"testing"
)

func TestNormalizeReportBlobUnwrapsFirmwareResponse(t *testing.T) {
	report := make([]byte, snpReportSize)
	binary.LittleEndian.PutUint32(report[0:4], snpReportVersionMin)
	binary.LittleEndian.PutUint32(report[0x34:0x38], snpReportSigAlgo)
	report[0x50] = 0xaa
	response := make([]byte, 4000)
	binary.LittleEndian.PutUint32(response[4:8], uint32(len(report)))
	copy(response[0x20:], report)

	if normalized := NormalizeReportBlob(response); !bytes.Equal(normalized, report) {
		t.Fatal("firmware response was not unwrapped to the SNP report")
	}
}

func TestNormalizeReportBlobDoesNotUnwrapInvalidFirmwarePayload(t *testing.T) {
	wrapped := make([]byte, 0x20+snpReportSize)
	binary.LittleEndian.PutUint32(wrapped[4:8], snpReportSize)

	normalized := NormalizeReportBlob(wrapped)
	if !bytes.Equal(normalized, wrapped) {
		t.Fatal("invalid firmware payload was unwrapped")
	}
}

func TestMeasurementHexReadsSNPReportMeasurement(t *testing.T) {
	report := make([]byte, snpReportSize)
	binary.LittleEndian.PutUint32(report[0:4], snpReportVersionMin)
	binary.LittleEndian.PutUint32(report[0x34:0x38], snpReportSigAlgo)
	for index := snpMeasurementStart; index < snpMeasurementEnd; index++ {
		report[index] = byte(index - snpMeasurementStart + 1)
	}
	envelope, err := EncodeEnvelope(Envelope{
		Provider: ProviderSEVGuest,
		Report:   base64.RawURLEncoding.EncodeToString(report),
	})
	if err != nil {
		t.Fatal(err)
	}

	measurement, err := MeasurementHex(envelope)
	if err != nil {
		t.Fatal(err)
	}
	if measurement != "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30" {
		t.Fatalf("unexpected measurement: %s", measurement)
	}
}

func TestEncodeEnvelopeValidatesRequiredFields(t *testing.T) {
	if _, err := EncodeEnvelope(Envelope{Provider: ProviderSEVGuest}); err == nil {
		t.Fatal("expected missing report to fail")
	}
	if _, err := EncodeEnvelope(Envelope{Report: "cmVwb3J0"}); err == nil {
		t.Fatal("expected missing provider to fail")
	}
	if _, err := EncodeEnvelope(Envelope{Schema: "wrong", Provider: ProviderSEVGuest, Report: "cmVwb3J0"}); err == nil {
		t.Fatal("expected wrong schema to fail")
	}
}
