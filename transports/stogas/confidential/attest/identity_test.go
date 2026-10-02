package attest

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestSNPNodeIdentitySharedVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/node-ids-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		ReportID string `json:"report_id"`
		NodeID   string `json:"node_id"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, vector := range vectors {
		raw, err := hex.DecodeString(vector.ReportID)
		if err != nil || len(raw) != 32 {
			t.Fatal("invalid fixture report ID", err)
		}
		if actual := SNPNodeID([32]byte(raw)); actual != vector.NodeID || len(actual) > 80 {
			t.Fatalf("node identity mismatch: %s", actual)
		}
	}
}
