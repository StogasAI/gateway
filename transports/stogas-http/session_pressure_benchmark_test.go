package stogashttp

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/confidential/channel"
)

// Uses actual session/quote/request byte reservations and idle reclamation.
// Quote latency is synthetic; no provider or account/database work runs.
func TestSessionPressureProbe(t *testing.T) {
	input := os.Getenv("STOGAS_SESSION_PRESSURE_PROBE")
	if input == "" {
		t.Skip("opt-in established-session and setup pressure probe")
	}
	var config struct {
		Mode         string `json:"mode"`
		Workers      int    `json:"workers"`
		PerSecond    int    `json:"per_second"`
		Seconds      int    `json:"seconds"`
		QuoteMillis  int    `json:"quote_millis"`
		BodyBytes    int    `json:"body_bytes"`
		ChunkBytes   int    `json:"chunk_bytes"`
		ChunkMicros  int    `json:"chunk_micros"`
		CancelMillis int    `json:"cancel_millis"`
		Corrupt      bool   `json:"corrupt"`
	}
	if err := json.Unmarshal([]byte(input), &config); err != nil || config.Seconds < 1 || config.Workers < 0 || config.PerSecond < 1 || config.QuoteMillis < 0 || (config.Mode != "setup" && config.Mode != "mixed" && config.Mode != "records") || (config.Mode == "records" && (config.BodyBytes < 1 || config.BodyBytes > channel.MaxRequestBodyBytes)) {
		t.Fatal("invalid pressure configuration", err)
	}
	var dispatched atomic.Uint64
	fixture := newSessionHTTPFixtureWithReporter(t, func(ctx *requestContext) {
		if _, err := io.Copy(io.Discard, ctx.request.Body); err != nil {
			ctx.writer.WriteHeader(400)
			return
		}
		dispatched.Add(1)
		_, _ = ctx.writer.Write(make([]byte, 4096))
	}, true, &sessionTestAttester{delay: time.Duration(config.QuoteMillis) * time.Millisecond})
	ready := httptest.NewServer(requestHandler(fixture.server.readiness))
	t.Cleanup(ready.Close)
	clientFor := func(index int) *http.Client {
		transport := fixture.endpoint.Client().Transport.(*http.Transport).Clone()
		transport.DialContext = (&net.Dialer{LocalAddr: &net.TCPAddr{IP: net.IPv4(127, 2, byte(index/256), byte(index%256))}}).DialContext
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: serverReadTimeout}
	}
	do := func(client *http.Client, wire []byte, owner, pressure bool) (int, error) {
		var input io.Reader = bytes.NewReader(wire)
		ctx := context.Background()
		if pressure && config.ChunkBytes > 0 {
			input = &pressureChunkReader{input: input, size: config.ChunkBytes, delay: time.Duration(config.ChunkMicros) * time.Microsecond}
		}
		if pressure && config.CancelMillis > 0 {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(ctx, time.Duration(config.CancelMillis)*time.Millisecond)
			defer cancel()
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, fixture.endpoint.URL+sessionPath, input)
		if err != nil {
			return 0, err
		}
		request.Header.Set("Content-Type", sessionContentType)
		if owner {
			request.Header.Set(sessionNodeHeader, fixture.server.sessionNodeID)
		}
		response, err := client.Do(request)
		if err != nil {
			return 0, err
		}
		defer response.Body.Close()
		if pressure && config.Corrupt && response.StatusCode == 200 {
			number := binary.BigEndian.Uint64(wire[channel.RequestPrefixBytes-8 : channel.RequestPrefixBytes])
			metadata, _ := readSessionResponse(t, response, &sessionTestCipher{fixture: fixture, requestNumber: number})
			return metadata.Status, nil
		}
		_, err = io.Copy(io.Discard, response.Body)
		if response.ProtoMajor != 2 {
			return 0, fmt.Errorf("expected HTTP/2, got %s", response.Proto)
		}
		return response.StatusCode, err
	}
	const victimRate = 60
	metadata := []byte(`{"method":"POST","path":"/v1/chat/completions","headers":{"content-type":"application/json","authorization":"Bearer fixture"}}`)
	warmup, decoder := fixture.request(t, metadata, []byte(`{}`))
	status, body := readSessionResponse(t, fixture.post(t, warmup, true), decoder)
	if status.Status != 200 || len(body) != 4096 {
		t.Fatal("encrypted warmup failed")
	}
	victim := clientFor(0)
	_, hello := sessionTestHello(t)
	attackers := make([]*http.Client, config.Workers)
	inputs := make([][]byte, config.Workers)
	for i := range attackers {
		attackers[i] = clientFor(i + 1)
		inputs[i] = hello
		if config.Mode == "records" {
			// Complete, independently encoded uploads reach the real receiver.
			// Only the final record may be short. Encoding is outside timing.
			inputs[i], _ = fixture.request(t, metadata, make([]byte, config.BodyBytes))
			if config.Corrupt {
				inputs[i][len(inputs[i])-1] ^= 1
			}
		}
		if config.Mode == "mixed" && i%2 != 0 {
			id, _, err := fixture.server.sessions.Open(context.Background(), hello)
			if err != nil {
				t.Fatal(err)
			}
			inputs[i] = forgedSessionStart(id)
		}
	}
	var wires [][]byte
	for range config.Seconds*victimRate + 2 {
		wire, _ := fixture.request(t, metadata, []byte(`{}`))
		wires = append(wires, wire)
	}
	if len(attackers) > 0 && config.Mode != "records" {
		if status, err := do(attackers[0], hello, false, false); err != nil || status != 200 {
			t.Fatal("setup attacker warmup", status, err)
		}
	}
	var stop atomic.Bool
	var attempted, setupOK, recordOK, invalid, rateRejected, capacityRejected, networkErrors, canceled atomic.Uint64
	attackSeconds := make([]float64, len(attackers))
	var workers sync.WaitGroup
	var usage syscall.Rusage
	cpu := func() float64 {
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
			t.Fatal(err)
		}
		return float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6
	}
	beforeCPU := cpu()
	dispatched.Store(0)
	start := time.Now()
	finish := start.Add(time.Duration(config.Seconds) * time.Second)
	for i := range attackers {
		workers.Go(func() {
			for n := i; !stop.Load(); n += len(attackers) {
				if delay := time.Until(start.Add(time.Duration(n) * time.Second / time.Duration(config.PerSecond))); delay > 0 {
					time.Sleep(delay)
				}
				if stop.Load() {
					return
				}
				began := time.Now()
				status, err := do(attackers[i], inputs[i], config.Mode == "records" || config.Mode == "mixed" && i%2 != 0, true)
				attackSeconds[i] += time.Since(began).Seconds()
				attempted.Add(1)
				if err != nil {
					if config.CancelMillis > 0 && config.Mode == "records" && errors.Is(err, context.DeadlineExceeded) {
						canceled.Add(1)
						return
					}
					networkErrors.Add(1)
					continue
				}
				switch status {
				case 200:
					if config.Mode == "records" {
						recordOK.Add(1)
					} else {
						setupOK.Add(1)
					}
				case 400:
					invalid.Add(1)
				case 429:
					rateRejected.Add(1)
				case 503:
					capacityRejected.Add(1)
				default:
					networkErrors.Add(1)
				}
				if config.Mode == "records" {
					return
				}
			}
		})
	}
	type sample struct {
		Second   float64 `json:"second"`
		Sessions any     `json:"sessions"`
		Memory   any     `json:"memory"`
	}
	var readiness []float64
	var snapshots []sample
	var readyErrors uint64
	workers.Go(func() {
		client := &http.Client{Timeout: 2 * time.Second}
		defer client.CloseIdleConnections()
		for n := 0; !stop.Load(); n++ {
			began := time.Now()
			response, err := client.Get(ready.URL + "/ready")
			readiness = append(readiness, float64(time.Since(began).Nanoseconds())/1e6)
			if err != nil {
				readyErrors++
			} else {
				if response.StatusCode != 204 {
					readyErrors++
				}
				_, _ = io.Copy(io.Discard, response.Body)
				response.Body.Close()
			}
			if n%10 == 0 {
				snapshots = append(snapshots, sample{time.Since(start).Seconds(), fixture.server.sessions.Diagnostics(), fixture.server.memory.diagnostics()})
			}
			time.Sleep(100 * time.Millisecond)
		}
	})
	defer func() { stop.Store(true); workers.Wait() }()
	var latencies []float64
	outcomes := map[int]int{}
	for i := 0; time.Now().Before(finish); i++ {
		if delay := time.Until(start.Add(time.Duration(i) * time.Second / victimRate)); delay > 0 {
			time.Sleep(delay)
		}
		began := time.Now()
		status, err := do(victim, wires[i], true, false)
		if err != nil {
			t.Fatal("victim network failure", err)
		}
		latencies = append(latencies, float64(time.Since(began).Nanoseconds())/1e6)
		outcomes[status]++
		if status != 200 && status != 400 && status != 503 {
			t.Fatal("unexpected victim status", status)
		}
	}
	stop.Store(true)
	workers.Wait()
	usedCPU := cpu() - beforeCPU
	if config.Workers > 0 && config.Mode != "records" && setupOK.Load() == 0 {
		t.Fatal("setup pressure never reached session creation")
	}
	if config.Mode == "records" && recordOK.Load()+canceled.Load()+invalid.Load() != uint64(config.Workers) {
		t.Error("record requests did not finish", recordOK.Load(), canceled.Load(), invalid.Load())
	}
	if networkErrors.Load() != 0 || dispatched.Load() != uint64(outcomes[200])+recordOK.Load() {
		t.Error("unexpected dispatch or transport failure", networkErrors.Load(), dispatched.Load(), outcomes)
	}
	stats := func(values []float64) map[string]any {
		slices.Sort(values)
		return map[string]any{"count": len(values), "p50_ms": values[(len(values)*50+99)/100-1], "p99_ms": values[(len(values)*99+99)/100-1], "max_ms": values[len(values)-1]}
	}
	result := map[string]any{
		"config": config, "elapsed_seconds": time.Since(start).Seconds(), "cpu_seconds": usedCPU, "max_rss_kib": usage.Maxrss,
		"attack_operations": attempted.Load(), "setup_completed": setupOK.Load(), "record_requests_completed": recordOK.Load(), "forged_rejected": invalid.Load(), "ip_rejected": rateRejected.Load(), "capacity_rejected": capacityRejected.Load(),
		"network_errors": networkErrors.Load(),
		"canceled":       canceled.Load(), "attack_seconds": attackSeconds,
		"victim_outcomes": outcomes, "victim_latency": stats(latencies), "readiness": stats(readiness), "readiness_errors": readyErrors,
		"sessions": fixture.server.sessions.Diagnostics(), "memory": fixture.server.memory.diagnostics(), "timeline": snapshots,
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("SESSION_PRESSURE_PROBE=%s\n", encoded)
}

type pressureChunkReader struct {
	input io.Reader
	size  int
	delay time.Duration
}

func (r *pressureChunkReader) Read(output []byte) (int, error) {
	if r.delay > 0 {
		time.Sleep(r.delay)
	}
	return r.input.Read(output[:min(len(output), r.size)])
}
