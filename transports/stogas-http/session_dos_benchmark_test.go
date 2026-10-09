package stogashttp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	ref "github.com/StogasAI/verifier/go/reference"
	"github.com/maximhq/bifrost/transports/stogas/confidential/channel"
)

// This opt-in probe exercises the actual HTTP/2 adapter, IP buckets, request
// reservations, session store and Rust admission. Synthetic quote setup is
// outside measurement. It does not measure SNP, provider work, account checks
// or ingress PROXY parsing. Quote and retained-session byte admission is real.
func TestSessionHTTPDoSProbe(t *testing.T) {
	input := os.Getenv("STOGAS_SESSION_HTTP_DOS_PROBE")
	if input == "" {
		t.Skip("opt-in loopback HTTP/2 denial-of-service probe")
	}
	var config struct {
		Workers        int    `json:"workers"`
		PerSecond      int    `json:"per_second"`
		Seconds        int    `json:"seconds"`
		Encrypted      bool   `json:"encrypted"`
		Distributed    bool   `json:"distributed"`
		VictimRate     int    `json:"victim_rate"`
		ResponseMillis int    `json:"response_millis"`
		Attack         string `json:"attack"`
		Gap            int    `json:"gap"`
	}
	if err := json.Unmarshal([]byte(input), &config); err != nil || config.Workers < 0 || config.PerSecond < 0 || config.Seconds <= 0 || config.VictimRate < 0 || config.ResponseMillis < 0 || config.ResponseMillis >= 15000 {
		t.Fatal("invalid probe configuration", err)
	}
	if config.Attack != "" && config.Attack != "header" && config.Attack != "body" {
		t.Fatal("unknown attack")
	}
	if config.Gap < 0 || config.Gap >= channel.ReplayWindow {
		t.Fatal("attack gap exceeds session window")
	}
	if config.VictimRate == 0 {
		config.VictimRate = 60
	}
	// Bound fixture storage and post-run response key reconstruction.
	if config.Seconds*config.VictimRate > 4000 {
		t.Fatal("probe exceeds independent fixture capacity")
	}
	var dispatched, legitimate atomic.Uint64
	fixture := newSessionHTTPFixture(t, func(ctx *requestContext) {
		if ctx.request.URL.Path != "/benchmark-victim" && !(config.Encrypted && ctx.request.URL.Path == "/v1/chat/completions") {
			dispatched.Add(1)
			ctx.writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		if _, err := io.Copy(io.Discard, ctx.request.Body); err != nil {
			ctx.writer.WriteHeader(http.StatusBadRequest)
			return
		}
		legitimate.Add(1)
		if config.ResponseMillis > 0 {
			time.Sleep(time.Duration(config.ResponseMillis) * time.Millisecond)
		}
		_, _ = ctx.writer.Write(make([]byte, 4096))
	}, true)
	client := fixture.endpoint.Client()
	client.Timeout = 15 * time.Second
	// Give legitimate traffic its own source IP and TLS connection, so sharing
	// an IP bucket or a client-side connection cannot manufacture interference.
	victimTransport := client.Transport.(*http.Transport).Clone()
	victimTransport.DialContext = (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 0, 0, 2)}}).DialContext
	defer victimTransport.CloseIdleConnections()
	victim := &http.Client{Transport: victimTransport, Timeout: 15 * time.Second}
	type firstRecord struct {
		received time.Time
		encoded  []byte
	}
	var pendingStarts, peakPendingStarts atomic.Int64
	do := func(client *http.Client, path string, wire []byte, first *firstRecord) (int, error) {
		request, err := http.NewRequest(http.MethodPost, fixture.endpoint.URL+path, bytes.NewReader(wire))
		if err != nil {
			return 0, err
		}
		request.Header.Set("Content-Type", sessionContentType)
		request.Header.Set(sessionNodeHeader, fixture.server.sessionNodeID)
		response, err := client.Do(request)
		if err != nil {
			return 0, err
		}
		defer response.Body.Close()
		if first != nil && response.StatusCode == http.StatusOK {
			var prefix [4]byte
			if _, err = io.ReadFull(response.Body, prefix[:]); err != nil {
				return response.StatusCode, err
			}
			size, sizeErr := channel.RecordSize(prefix[:])
			if sizeErr != nil {
				return response.StatusCode, sizeErr
			}
			first.encoded = make([]byte, size)
			copy(first.encoded, prefix[:])
			if _, err = io.ReadFull(response.Body, first.encoded[4:]); err != nil {
				return response.StatusCode, err
			}
			first.received = time.Now()
			pendingStarts.Add(-1)
		}
		_, err = io.Copy(io.Discard, response.Body)
		if response.ProtoMajor != 2 {
			return 0, fmt.Errorf("expected HTTP/2, got %s", response.Proto)
		}
		return response.StatusCode, err
	}
	victimPath := "/benchmark-victim"
	var victimInputs [][]byte
	if config.Encrypted {
		victimPath = sessionPath
		metadata := []byte(`{"method":"POST","path":"/v1/chat/completions","headers":{"content-type":"application/json","authorization":"Bearer fixture"}}`)
		warmup, decoder := fixture.request(t, metadata, []byte(`{}`))
		response := fixture.post(t, warmup, true)
		status, body := readSessionResponse(t, response, decoder)
		if status.Status != 200 || len(body) != 4096 {
			t.Fatal("encrypted warmup failed")
		}
		// Prepare independent reference requests outside measurement.
		for range config.Seconds * config.VictimRate {
			wire, _ := fixture.request(t, metadata, []byte(`{}`))
			victimInputs = append(victimInputs, wire)
		}
	}
	if status, err := do(victim, "/benchmark-victim", nil, nil); err != nil || status != 200 {
		t.Fatal("victim warmup", status, err)
	}
	seed, hello := sessionTestHello(t)
	inputs := make([][]byte, config.Workers)
	attackers := make([]*http.Client, config.Workers)
	for index := range inputs {
		attackers[index] = client
		if config.Distributed {
			transport := client.Transport.(*http.Transport).Clone()
			transport.DialContext = (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 1, byte(index/256), byte(index%256))}}).DialContext
			defer transport.CloseIdleConnections()
			attackers[index] = &http.Client{Transport: transport, Timeout: 15 * time.Second}
		}
		id, setupWire, err := fixture.server.sessions.Open(context.Background(), hello)
		if err != nil {
			t.Fatal(err)
		}
		if config.Attack == "body" {
			root, public := sessionTestSetupKeys(t, seed, hello, setupWire, []byte(`{"fixture":"HTTP adapter only"}`))
			peer := ref.New(root, &ref.Keys{Public: [ref.PublicBytes]byte(public)}, true)
			var message ref.Message
			for request := range uint64(config.Gap) + 1 {
				message = peer.Send(request, bytes.Repeat([]byte{7}, 32), bytes.Repeat([]byte{9}, 32))
			}
			record := ref.SealRecord(message.Secret, id[:], uint64(config.Gap), 1, 0, message.Header, byte(channel.Metadata), []byte{0})
			record[len(record)-1] ^= 1
			wire := append([]byte("STGS\x01\x03"), id[:]...)
			wire = binary.BigEndian.AppendUint64(wire, uint64(config.Gap))
			inputs[index] = append(wire, record...)
		} else {
			inputs[index] = forgedSessionStart(id)
		}
		if status, err := do(attackers[index], sessionPath, inputs[index], nil); err != nil || status != 400 {
			t.Fatal("forged-start warmup", status, err)
		}
	}
	var start time.Time
	ready := make(chan struct{})
	var stop atomic.Bool
	var attempted, rejected, capacityRejected, failures atomic.Uint64
	var workers sync.WaitGroup
	for worker, wire := range inputs {
		workers.Go(func() {
			<-ready
			for sequence := worker; !stop.Load(); sequence += config.Workers {
				if config.PerSecond > 0 {
					if delay := time.Until(start.Add(time.Duration(sequence) * time.Second / time.Duration(config.PerSecond))); delay > 0 {
						time.Sleep(delay)
					}
				}
				if stop.Load() {
					return
				}
				status, err := do(attackers[worker], sessionPath, wire, nil)
				if err != nil || (status != 400 && status != 429 && status != 503) {
					failures.Add(1)
				}
				if status == 503 {
					capacityRejected.Add(1)
				}
				if status == 429 {
					rejected.Add(1)
				}
				attempted.Add(1)
			}
		})
	}
	cpu := func() float64 {
		var usage syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
			t.Fatal(err)
		}
		return float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6
	}
	legitimate.Store(0)
	before := cpu()
	start = time.Now()
	finish := start.Add(time.Duration(config.Seconds) * time.Second)
	close(ready)
	defer func() {
		stop.Store(true)
		workers.Wait()
	}()
	type victimResult struct {
		first     firstRecord
		started   time.Time
		completed time.Duration
		status    int
		err       error
	}
	results := make([]victimResult, config.Seconds*config.VictimRate)
	var victims sync.WaitGroup
	launched := 0
	// Fixed offered times and concurrent requests keep slow responses from
	// silently reducing load. This probe does not consume a database rate bucket.
	for sequence := range results {
		if delay := time.Until(start.Add(time.Duration(sequence) * time.Second / time.Duration(config.VictimRate))); delay > 0 {
			time.Sleep(delay)
		}
		if !time.Now().Before(finish) {
			break
		}
		launched++
		victims.Go(func() {
			result := &results[sequence]
			result.started = time.Now()
			var wire []byte
			var first *firstRecord
			if config.Encrypted {
				wire, first = victimInputs[sequence], &result.first
				pending := pendingStarts.Add(1)
				for peak := peakPendingStarts.Load(); pending > peak; peak = peakPendingStarts.Load() {
					if peakPendingStarts.CompareAndSwap(peak, pending) {
						break
					}
				}
			}
			result.status, result.err = do(victim, victimPath, wire, first)
			result.completed = time.Since(result.started)
			if first != nil && first.received.IsZero() {
				pendingStarts.Add(-1)
			}
		})
	}
	victims.Wait()
	stop.Store(true)
	workers.Wait()
	elapsed := time.Since(start)
	usedCPU := cpu() - before
	var usage syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	threadCount, _ := runtime.ThreadCreateProfile(nil)
	var latency, firstLatency []int64
	firstKinds := make(map[channel.Kind]int)
	victimRejected := 0
	for sequence, result := range results[:launched] {
		if result.err != nil || (result.status != 200 && result.status != 503) {
			t.Fatal("victim failed", result.status, result.err)
		}
		if result.status == 503 {
			victimRejected++
		}
		latency = append(latency, result.completed.Nanoseconds())
		if !result.first.received.IsZero() {
			firstLatency = append(firstLatency, result.first.received.Sub(result.started).Nanoseconds())
			// Verify captured records after timing. Fixture key reconstruction is
			// deliberately independent and quadratic, unlike the production SDK.
			number := binary.BigEndian.Uint64(victimInputs[sequence][channel.RequestPrefixBytes-8 : channel.RequestPrefixBytes])
			kind, _, err := readSessionRecord(t, bytes.NewReader(result.first.encoded), &sessionTestCipher{fixture: fixture, requestNumber: number})
			if err != nil || (kind != channel.Keepalive && kind != channel.Metadata) {
				t.Fatal("invalid first response record", kind, err)
			}
			firstKinds[kind]++
		}
	}
	if legitimate.Load() != uint64(len(latency)-victimRejected) {
		t.Fatal("legitimate encrypted requests did not dispatch", legitimate.Load(), len(latency))
	}
	if failures.Load() != 0 || dispatched.Load() != 0 {
		t.Fatal("unexpected network failure or forged request dispatch", failures.Load(), dispatched.Load())
	}
	slices.Sort(latency)
	percentile := func(p int) float64 { return float64(latency[(len(latency)*p+99)/100-1]) / 1e6 }
	slices.Sort(firstLatency)
	firstPercentile := func(p int) float64 {
		if len(firstLatency) == 0 {
			return 0
		}
		return float64(firstLatency[(len(firstLatency)*p+99)/100-1]) / 1e6
	}
	result, err := json.Marshal(map[string]any{
		"config": config, "elapsed_seconds": elapsed.Seconds(), "cpu_seconds": usedCPU,
		"max_rss_kib": usage.Maxrss, "created_threads": threadCount,
		"attack_operations": attempted.Load(), "ip_rejected": rejected.Load(), "victim_completions": len(latency) - victimRejected, "victim_capacity_rejected": victimRejected, "attack_capacity_rejected": capacityRejected.Load(), "sessions": fixture.server.sessions.Diagnostics(),
		"victim_p50_ms": percentile(50), "victim_p95_ms": percentile(95), "victim_p99_ms": percentile(99),
		"victim_max_ms": float64(latency[len(latency)-1]) / 1e6, "ip_diagnostics": fixture.server.ipAdmission.diagnostics(),
		"victim_offered": len(results), "victim_generator_missed": len(results) - launched,
		"first_record_p50_ms": firstPercentile(50), "first_record_p99_ms": firstPercentile(99), "first_record_max_ms": firstPercentile(100),
		"first_record_kinds": firstKinds, "peak_pending_first_records": peakPendingStarts.Load(),
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("SESSION_HTTP_DOS_PROBE=%s\n", result)
}

// Only a session ID is needed; neither its root nor any account key is used.
func forgedSessionStart(id [32]byte) []byte {
	header := make([]byte, channel.MaxRatchetHeaderBytes)
	record := binary.BigEndian.AppendUint32(nil, uint32(6+len(header)+18))
	record = binary.BigEndian.AppendUint16(record, uint16(len(header)))
	record = append(record, header...)
	record = append(record, make([]byte, 18)...)
	wire := append([]byte("STGS\x01\x03"), id[:]...)
	wire = binary.BigEndian.AppendUint64(wire, channel.ReplayWindow-1)
	return append(wire, record...)
}
