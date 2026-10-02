package attest

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestBootCommitmentAndDocumentSharedVector(t *testing.T) {
	data, err := os.ReadFile("testdata/node-boot-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Record     BootRecord `json:"record"`
		Commitment string     `json:"report_data_sha512"`
		Digest     string     `json:"document_sha256"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	commitment, err := vector.Record.ReportData.Commitment()
	if err != nil || hex.EncodeToString(commitment[:]) != vector.Commitment {
		t.Fatal("report-data commitment differs", err)
	}
	digest, err := vector.Record.Digest()
	if err != nil || hex.EncodeToString(digest[:]) != vector.Digest {
		t.Fatal("boot document digest differs", err)
	}
	// Any change to a locally committed boot field must invalidate its existing quote binding.
	for _, change := range []func(*BootReportData){
		func(d *BootReportData) { d.Environment = "staging" },
		func(d *BootReportData) { d.RegistrationChallenge = strings.Repeat("55", 32) },
		func(d *BootReportData) { d.TLSSPKISHA256 = strings.Repeat("55", 32) },
		func(d *BootReportData) { d.SigningPublicKey = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) },
		func(d *BootReportData) { d.HPKEPublicKey += "=" },
		func(d *BootReportData) { d.Schema += ".unknown" },
	} {
		record := vector.Record
		change(&record.ReportData)
		if _, err := record.Document(); err == nil {
			t.Fatal("accepted changed boot binding")
		}
	}
	for _, change := range []func(*BootRecord){
		func(r *BootRecord) { r.Schema += ".unknown" },
		func(r *BootRecord) { r.Report += "=" },
		func(r *BootRecord) { r.Report = "" },
		func(r *BootRecord) { r.GatewayReleaseID = strings.Repeat("AF", 32) },
		func(r *BootRecord) { r.HardwarePolicySHA256 = "22" },
	} {
		record := vector.Record
		change(&record)
		if _, err := record.Document(); err == nil {
			t.Fatal("accepted invalid boot document")
		}
	}
}
