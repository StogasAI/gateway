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
		BodyBytes   int `json:"body_bytes"`
		RecordBytes int `json:"record_bytes"`
		Rounds      int `json:"rounds"`
	}
	if err := json.Unmarshal([]byte(input), &config); err != nil || config.BodyBytes < 1 || config.BodyBytes > MaxRequestBodyBytes || config.RecordBytes < 0 || config.RecordBytes > MaxRecordPlaintext || config.Rounds < 1 {
		t.Fatal("invalid record consumption configuration", err)
	}
	if config.RecordBytes == 0 {
		config.RecordBytes = MaxRecordPlaintext
	}
	records := (config.BodyBytes + config.RecordBytes - 1) / config.RecordBytes
	if records+2 > MaxRecords {
		t.Fatal("metadata, data and completion exceed the protocol record ceiling")
	}
	root, id := [32]byte{1}, [32]byte{2}
	encoder, err := newRecords(requestMessage(root, 0), id, 0, requestDirection)
	if err != nil {
		t.Fatal(err)
	}
	defer encoder.fail(ErrClosed)
	metadata := sealRecord(t, encoder, Metadata, []byte(`{"method":"POST","path":"/v1/chat/completions"}`))
	wire := make([]byte, 0, config.BodyBytes+(records+1)*RecordOverhead)
	body := make([]byte, config.RecordBytes)
	for remaining := config.BodyBytes; remaining > 0; {
		size := min(remaining, len(body))
		wire = append(wire, sealRecord(t, encoder, Data, body[:size])...)
		remaining -= size
	}
	wire = append(wire, sealRecord(t, encoder, Finished, nil)...)
	var samples []map[string]any
	for range config.Rounds {
		session := testServerSession(root, id)
		state, _, err := session.AcceptStart(0, bytes.Clone(metadata))
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
	encoded, err := json.Marshal(map[string]any{"config": config, "data_records": records, "wire_bytes": len(metadata) + len(wire), "samples": samples})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("RECORD_CONSUMPTION_PROBE=%s\n", encoded)
}
