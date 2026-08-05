package provision

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"sort"
	"strings"
)

const (
	heartbeatSignatureDomain = "stogas.gateway-heartbeat.v1"
	csrSignatureDomain       = "stogas.gateway-csr-submission.v1"
)

func signHeartbeat(input HeartbeatInput) (string, error) {
	if len(input.SigningKey) != ed25519.PrivateKeySize {
		return "", errors.New("heartbeat signing key is required")
	}
	transcript, err := heartbeatSignatureTranscript(input)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(input.SigningKey, transcript)), nil
}

func heartbeatSignatureTranscript(input HeartbeatInput) ([]byte, error) {
	if input.Quote == nil {
		return nil, errors.New("heartbeat quote snapshot is required")
	}
	reportHash, err := hex.DecodeString(strings.ToLower(input.Quote.ReportDataHex))
	if err != nil || len(reportHash) != 64 {
		return nil, errors.New("heartbeat report-data hash must be 64 bytes")
	}
	quoteHash := sha256.Sum256(input.Quote.Quote)
	fields := [][]byte{
		[]byte(input.NodeID),
		[]byte(formatTime(input.CertExpiresAt)),
		[]byte(formatTime(input.ObservedAt)),
		[]byte(formatTime(input.Quote.GeneratedAt)),
		quoteHash[:],
		reportHash,
	}
	if input.Health.Ready {
		fields = append(fields, []byte{1})
	} else {
		fields = append(fields, []byte{0})
	}
	fields = append(fields, []byte(input.Health.LastQuoteError))

	names := make([]string, 0, len(input.Health.SecretVersions))
	for name := range input.Health.SecretVersions {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) > math.MaxUint32 {
		return nil, errors.New("heartbeat contains too many secret versions")
	}

	var transcript bytes.Buffer
	transcript.WriteString(heartbeatSignatureDomain)
	transcript.WriteByte(0)
	for _, field := range fields {
		if err := appendTranscriptField(&transcript, field); err != nil {
			return nil, err
		}
	}
	if err := binary.Write(&transcript, binary.BigEndian, uint32(len(names))); err != nil {
		return nil, err
	}
	for _, name := range names {
		if err := appendTranscriptField(&transcript, []byte(name)); err != nil {
			return nil, err
		}
		if err := appendTranscriptField(&transcript, []byte(input.Health.SecretVersions[name])); err != nil {
			return nil, err
		}
	}
	return transcript.Bytes(), nil
}

func signCertificateCSRSubmission(input CertificateCSRSubmission) (string, error) {
	if len(input.SigningKey) != ed25519.PrivateKeySize {
		return "", errors.New("certificate CSR signing key is required")
	}
	transcript, err := certificateCSRSignatureTranscript(input.NodeID, input.OrderID, input.CSRDER)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(ed25519.Sign(input.SigningKey, transcript)), nil
}

func certificateCSRSignatureTranscript(nodeID, orderID string, csrDER []byte) ([]byte, error) {
	if len(csrDER) == 0 {
		return nil, errors.New("certificate CSR DER is required")
	}
	digest := sha256.Sum256(csrDER)
	var transcript bytes.Buffer
	transcript.WriteString(csrSignatureDomain)
	transcript.WriteByte(0)
	for _, field := range [][]byte{
		[]byte(strings.ToLower(nodeID)),
		[]byte(orderID),
		digest[:],
	} {
		if err := appendTranscriptField(&transcript, field); err != nil {
			return nil, err
		}
	}
	return transcript.Bytes(), nil
}

func appendTranscriptField(transcript *bytes.Buffer, value []byte) error {
	if uint64(len(value)) > math.MaxUint32 {
		return fmt.Errorf("signed transcript field exceeds %d bytes", uint64(math.MaxUint32))
	}
	if err := binary.Write(transcript, binary.BigEndian, uint32(len(value))); err != nil {
		return err
	}
	_, err := transcript.Write(value)
	return err
}
