package channel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"testing"
	"time"
)

// Measures authenticated record consumption through the actual Go/Rust stream
// boundary. The independently encoded client bytes are prepared outside timing.
// Authorization must precede this work in the HTTP inference pipeline.
func TestRecordConsumptionProbe(t *testing.T) {
	input := os.Getenv("STOGAS_RECORD_CONSUMPTION_PROBE")
	if input == "" {
		t.Skip("opt-in authenticated record consumption probe")
	}
	var config struct {
		BodyBytes int `json:"body_bytes"`
		Rounds    int `json:"rounds"`
	}
	if err := json.Unmarshal([]byte(input), &config); err != nil || config.BodyBytes < 1 || config.BodyBytes > MaxRequestBodyBytes || config.Rounds < 1 {
		t.Fatal("invalid record consumption configuration", err)
	}
	// Only the final request data record may be short.
	records := (config.BodyBytes + MaxRecordPlaintext - 1) / MaxRecordPlaintext
	body := make([]byte, MaxRecordPlaintext)
	var samples []map[string]any
	var wireBytes int
	for range config.Rounds {
		// Each session has fresh setup keys; encode its upload before timing.
		session, client := testServerSession(t)
		encoder := newRecords(requestMessage(client, 0), client.ID, 0, requestDirection)
		metadata := sealRecord(t, encoder, Metadata, []byte(`{"method":"POST","path":"/v1/chat/completions"}`))
		wire := make([]byte, 0, config.BodyBytes+(records+1)*RecordOverhead)
		for remaining := config.BodyBytes; remaining > 0; {
			size := min(remaining, len(body))
			wire = append(wire, sealRecord(t, encoder, Data, body[:size])...)
			remaining -= size
		}
		wire = append(wire, sealRecord(t, encoder, Finished, nil)...)
		encoder.fail(ErrClosed)
		wireBytes = len(metadata) + len(wire)
		state, _, err := session.AcceptStart(0, metadata)
		if err != nil {
			t.Fatal(err)
		}
		incoming := &Incoming{State: state, input: bytes.NewReader(wire)}
		beforeCPU, started := dosCPUSeconds(), time.Now()
		count, err := io.Copy(io.Discard, incoming)
		elapsed, cpu := time.Since(started).Seconds(), dosCPUSeconds()-beforeCPU
		consumed := incoming.Consumed()
		incoming.Close()
		session.Close()
		if err != nil || count != int64(config.BodyBytes) || !consumed {
			t.Fatal("authenticated body did not complete", count, err)
		}
		samples = append(samples, map[string]any{"elapsed_seconds": elapsed, "cpu_seconds": cpu, "records_per_second": float64(records) / elapsed})
	}
	encoded, err := json.Marshal(map[string]any{"config": config, "data_records": records, "wire_bytes": wireBytes, "samples": samples})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("RECORD_CONSUMPTION_PROBE=%s\n", encoded)
}
