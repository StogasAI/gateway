package attest

import (
	"bytes"
	"crypto/hpke"
	"crypto/mldsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
)

const (
	BootSchema           = "stogas.node-boot.v1"
	BootReportDataSchema = "stogas.node-report.v1"
)

// Fields stay in canonical JSON key order. All values use restricted ASCII
// encodings, so JSON escaping and number formatting cannot change the commitment.
type BootReportData struct {
	Environment           string `json:"environment"`
	HPKEPublicKey         string `json:"hpke_public_key"`
	RegistrationChallenge string `json:"registration_challenge"`
	Schema                string `json:"schema"`
	SigningPublicKey      string `json:"signing_public_key"`
	TLSSPKISHA256         string `json:"tls_spki_sha256"`
}

type BootRecord struct {
	GatewayReleaseID     string         `json:"gateway_release_id"`
	HardwarePolicySHA256 string         `json:"hardware_policy_sha256"`
	Report               string         `json:"report"`
	ReportData           BootReportData `json:"report_data"`
	Schema               string         `json:"schema"`
}

// Commitment binds locally generated boot keys to Control's one-use challenge.
// This encoder neither authenticates keys nor exposes an arbitrary quote API.
func (data BootReportData) Commitment() ([64]byte, error) {
	if data.Schema != BootReportDataSchema || data.Environment != "prod" && data.Environment != "staging" {
		return [64]byte{}, errors.New("invalid boot report-data profile")
	}
	if !bootHex(data.TLSSPKISHA256, 32) || !bootHex(data.RegistrationChallenge, 32) {
		return [64]byte{}, errors.New("invalid boot digest or challenge")
	}
	signingKey, err := bootBase64(data.SigningPublicKey, 1952)
	if err != nil {
		return [64]byte{}, err
	}
	if _, err := mldsa.NewPublicKey(mldsa.MLDSA65(), signingKey); err != nil {
		return [64]byte{}, err
	}
	recipient, err := bootBase64(data.HPKEPublicKey, 1216)
	if err != nil {
		return [64]byte{}, err
	}
	if _, err := hpke.MLKEM768X25519().NewPublicKey(recipient); err != nil {
		return [64]byte{}, err
	}
	encoded, err := json.Marshal(data)
	if err != nil {
		return [64]byte{}, err
	}
	return sha512.Sum512(encoded), nil
}

// Document returns the exact immutable bytes logged by Control and committed by
// live sessions. It checks local consistency; the guest still verifies hardware
// appraisal and actual inclusion through the shared verifier before serving.
func (record BootRecord) Document() ([]byte, error) {
	if record.Schema != BootSchema || !bootHex(record.GatewayReleaseID, 32) || !bootHex(record.HardwarePolicySHA256, 32) {
		return nil, errors.New("invalid boot document profile or reference")
	}
	report, err := bootBase64(record.Report, snpReportSize)
	if err != nil {
		return nil, err
	}
	commitment, err := record.ReportData.Commitment()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(report[0x50:0x90], commitment[:]) {
		return nil, errors.New("boot quote report data differs")
	}
	document, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	return append(document, '\n'), nil
}

func (record BootRecord) Digest() ([32]byte, error) {
	document, err := record.Document()
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(document), nil
}

func bootHex(value string, size int) bool {
	if len(value) != size*2 {
		return false
	}
	for _, character := range []byte(value) {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}

func bootBase64(value string, size int) ([]byte, error) {
	if len(value) != base64.RawURLEncoding.EncodedLen(size) {
		return nil, errors.New("invalid boot public field length")
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || len(decoded) != size {
		return nil, errors.New("invalid boot public field encoding")
	}
	return decoded, nil
}
