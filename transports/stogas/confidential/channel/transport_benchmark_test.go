package channel

// This opt-in loopback peer measures the real TLS/HTTP2 and channel record
// implementations. Attestation, authorization and inference are deliberately
// outside the timed warm path. It never binds an externally reachable address.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/net/http2"
)

type benchmarkWire struct {
	net.Conn
	read, written *atomic.Uint64
}

func (c benchmarkWire) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.read.Add(uint64(n))
	return n, err
}
func (c benchmarkWire) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.written.Add(uint64(n))
	return n, err
}

type benchmarkListener struct {
	net.Listener
	read, written *atomic.Uint64
}

func (l benchmarkListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return benchmarkWire{c, l.read, l.written}, nil
}

type benchmarkMetrics struct {
	CPUSeconds float64 `json:"cpu_seconds"`
	Allocated  uint64  `json:"allocated_bytes"`
	Heap       uint64  `json:"heap_bytes"`
	GC         uint32  `json:"gc_count"`
	RSSKiB     uint64  `json:"rss_kib"`
	PeakRSSKiB uint64  `json:"peak_rss_kib"`
	Read       uint64  `json:"read_wire_bytes"`
	Written    uint64  `json:"written_wire_bytes"`
	Errors     uint64  `json:"errors"`
}

func benchmarkStats(read, written, failures *atomic.Uint64) benchmarkMetrics {
	var usage syscall.Rusage
	_ = syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	var memory runtime.MemStats
	runtime.ReadMemStats(&memory)
	stats := benchmarkMetrics{
		CPUSeconds: float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6,
		Allocated:  memory.TotalAlloc, Heap: memory.HeapAlloc, GC: memory.NumGC,
		Read: read.Load(), Written: written.Load(), Errors: failures.Load(),
	}
	status, _ := os.ReadFile("/proc/self/status")
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, _ := strconv.ParseUint(fields[1], 10, 64)
		switch fields[0] {
		case "VmRSS:":
			stats.RSSKiB = value
		case "VmHWM:":
			stats.PeakRSSKiB = value
		}
	}
	return stats
}

func TestTransportBenchmarkServer(t *testing.T) {
	path := os.Getenv("STOGAS_TRANSPORT_BENCH_CONFIG")
	if path == "" {
		t.Skip("opt-in loopback benchmark peer")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	admin, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	var read, written, failures atomic.Uint64
	store, err := NewStore(newSetup(t, &setupReporter{}), func() (func(), bool) { return func() {}, true })
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var current [32]byte
	var sessionMu sync.Mutex
	stopped := make(chan struct{})
	control := http.NewServeMux()
	control.HandleFunc("POST /reset", func(w http.ResponseWriter, r *http.Request) {
		sessionMu.Lock()
		defer sessionMu.Unlock()
		store.Remove(current)
		runtime.GC()
		_ = os.WriteFile("/proc/self/clear_refs", []byte("5"), 0600)
		w.WriteHeader(204)
	})
	control.HandleFunc("GET /metrics", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(benchmarkStats(&read, &written, &failures))
	})
	control.HandleFunc("POST /stop", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(204); close(stopped) })
	adminServer := &http.Server{Handler: control, ReadHeaderTimeout: 5 * time.Second}
	go func() { _ = adminServer.Serve(admin) }()
	defer adminServer.Close()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fail := func(err error) { failures.Add(1); http.Error(w, err.Error(), 500) }
		if r.URL.Path == "/setup" {
			hello, err := io.ReadAll(io.LimitReader(r.Body, int64(ClientSetupBytes+1)))
			if err != nil {
				fail(err)
				return
			}
			id, response, err := store.Open(r.Context(), hello)
			if err != nil {
				fail(err)
				return
			}
			sessionMu.Lock()
			current = id
			sessionMu.Unlock()
			_, _ = w.Write(response)
			return
		}
		body := io.Reader(r.Body)
		output := io.Writer(w)
		var outgoing *Outgoing
		if r.URL.Path == "/e2ee" {
			incoming, _, err := Accept(store, r.Body)
			if err != nil {
				fail(err)
				return
			}
			defer incoming.Close()
			body = incoming
			outgoing = NewOutgoing(incoming.State, w)
			output = outgoing
		}
		buffer := make([]byte, MaxRecordPlaintext)
		n, err := io.CopyBuffer(io.Discard, body, buffer)
		clear(buffer)
		if err != nil {
			fail(err)
			return
		}
		w.Header().Set("X-Received-Bytes", strconv.FormatInt(n, 10))
		w.Header().Set("X-TLS-Cipher", tls.CipherSuiteName(r.TLS.CipherSuite))
		if outgoing != nil {
			if err := outgoing.Metadata([]byte(`{"status":200,"headers":{}}`)); err != nil {
				fail(err)
				return
			}
		}
		remaining, _ := strconv.Atoi(r.Header.Get("X-Response-Bytes"))
		chunk, _ := strconv.Atoi(r.Header.Get("X-Response-Chunk"))
		if remaining < 1 || remaining > 64*1024*1024 || chunk < 1 || chunk > MaxRecordPlaintext {
			failures.Add(1)
			return
		}
		response := make([]byte, chunk)
		for i := range response {
			response[i] = 'x'
		}
		for remaining > 0 {
			size := min(remaining, chunk)
			if _, err := output.Write(response[:size]); err != nil {
				fail(err)
				return
			}
			remaining -= size
			if r.Header.Get("X-Flush") == "1" {
				if err := http.NewResponseController(w).Flush(); err != nil {
					fail(err)
					return
				}
			}
		}
		if outgoing != nil {
			if err := outgoing.Finish(); err != nil {
				fail(err)
			}
		}
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, NextProtos: []string{"h2"}, SessionTicketsDisabled: true}}
	if err := http2.ConfigureServer(server, &http2.Server{MaxConcurrentStreams: 250, MaxReadFrameSize: 1 << 20, MaxUploadBufferPerConnection: 1 << 20, MaxUploadBufferPerStream: 1 << 20}); err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = server.Serve(tls.NewListener(benchmarkListener{listener, &read, &written}, server.TLSConfig))
	}()
	defer server.Close()
	config, _ := json.Marshal(map[string]any{"address": listener.Addr().String(), "admin": "http://" + admin.Addr().String(), "certificate": der, "go_version": runtime.Version(), "gomaxprocs": runtime.GOMAXPROCS(0)})
	if err := os.WriteFile(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(path)
	select {
	case <-stopped:
	case <-time.After(30 * time.Minute):
		t.Fatal("benchmark peer deadline")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
}
