package channel

// Software-cost probes use real TLS, HPKE and ratchet implementations. Only the
// hardware report comes from the existing synthetic test backend. They exclude
// network ingress, account authorization, inference and hardware quote latency.

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
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

	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
)

func dosCPUSeconds() float64 {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil {
		panic(err)
	}
	return float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6
}

// An attacker needs no ratchet root or account credential to construct this
// valid-shaped header and invalid tag. The same bytes can be submitted again.
func dosForgedStart(t testing.TB, number uint64) []byte {
	t.Helper()
	encoder := newRecords(referenceMessage{secret: [32]byte{99}, header: make([]byte, MaxRatchetHeaderBytes)}, [32]byte{2}, number, requestDirection)
	encoded, err := encoder.seal(Metadata, []byte{0})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

type dosWire struct {
	*bytes.Reader
	output  bytes.Buffer
	written int
	capture bool
}

func (w *dosWire) Write(p []byte) (int, error) {
	w.written += len(p)
	if w.capture {
		return w.output.Write(p)
	}
	return len(p), nil
}
func (*dosWire) Close() error                     { return nil }
func (*dosWire) LocalAddr() net.Addr              { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 443} }
func (*dosWire) RemoteAddr() net.Addr             { return &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 12345} }
func (*dosWire) SetDeadline(time.Time) error      { return nil }
func (*dosWire) SetReadDeadline(time.Time) error  { return nil }
func (*dosWire) SetWriteDeadline(time.Time) error { return nil }

type dosSetup struct {
	tlsConfig *tls.Config
	client    *tls.Config
	hello     []byte
	e2ee      *ServerSetup
	e2eeHello []byte
	issued    atomic.Uint64
}

func newDoSSetup(t testing.TB) *dosSetup {
	t.Helper()
	reporter := &setupReporter{}
	batcher, err := attest.NewBatcher(reporter, func() (func(), bool) { return func() {}, true })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := batcher.Close(context.Background()); err != nil {
			t.Error(err)
		}
	})
	boot := attest.BootEvidence{Document: []byte(`{"benchmark":"software only"}`), Inclusion: []byte(`{}`)}
	issuer, err := attest.NewNativeIssuer(attest.Production, "gateway.test", boot, batcher)
	if err != nil {
		t.Fatal(err)
	}
	probe := &dosSetup{}
	probe.tlsConfig, err = attest.ConfigureTLS(&tls.Config{}, func() bool { return true }, func(ctx context.Context, challenge [32]byte) (*tls.Certificate, error) {
		certificate, err := issuer(ctx, challenge)
		if err == nil {
			probe.issued.Add(1)
		}
		return certificate, err
	})
	if err != nil {
		t.Fatal(err)
	}
	probe.client = &tls.Config{InsecureSkipVerify: true, ServerName: "gateway.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{attest.NativeALPN([32]byte{1}), "h2"}}
	// Capture one genuine ClientHello. Replaying it then abandoning the handshake
	// measures server work without charging repeated client key generation.
	wire := &dosWire{Reader: bytes.NewReader(nil), capture: true}
	if err := tls.Client(wire, probe.client).Handshake(); err == nil || wire.output.Len() == 0 {
		t.Fatal("ClientHello capture failed", err)
	}
	probe.hello = slices.Clone(wire.output.Bytes())
	probe.e2ee, err = NewServerSetup(attest.Production, boot, 10*time.Minute, batcher)
	if err != nil {
		t.Fatal(err)
	}
	private, err := hpke.MLKEM768X25519().NewPrivateKey(bytes.Repeat([]byte{1}, 32))
	if err != nil {
		t.Fatal(err)
	}
	probe.e2eeHello = append([]byte(ClientSetupHeader), byte(attest.Production))
	probe.e2eeHello = append(probe.e2eeHello, make([]byte, 32)...)
	probe.e2eeHello = append(probe.e2eeHello, private.PublicKey().Bytes()...)
	return probe
}

func (p *dosSetup) abandonedTLS() error {
	wire := &dosWire{Reader: bytes.NewReader(p.hello)}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	err := tls.Server(wire, p.tlsConfig).HandshakeContext(ctx)
	if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
		return fmt.Errorf("expected abandoned TLS handshake: %w", err)
	}
	if wire.written < 4096 {
		return errors.New("server did not send its attested ML-DSA certificate flight")
	}
	return nil
}

func BenchmarkUnauthenticatedAdmission(b *testing.B) {
	// Match the replayed ClientHello/abandoned server-flight method below,
	// using ordinary TLS with a pre-existing certificate and no attestation.
	for _, profile := range []struct {
		curve tls.CurveID
		ecdsa bool
	}{{tls.X25519, false}, {tls.X25519MLKEM768, false}, {tls.X25519, true}, {tls.X25519MLKEM768, true}} {
		b.Run(fmt.Sprintf("ordinary_tls_abandoned/%s/ecdsa=%t", profile.curve, profile.ecdsa), func(b *testing.B) {
			fixture := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
			defer fixture.Close()
			config := fixture.TLS.Clone()
			if fixture.Certificate().PublicKeyAlgorithm != x509.RSA {
				b.Fatal("ordinary TLS baseline expects the httptest RSA certificate")
			}
			if profile.ecdsa {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					b.Fatal(err)
				}
				template := *fixture.Certificate()
				template.SignatureAlgorithm = x509.ECDSAWithSHA256
				template.PublicKey = &key.PublicKey
				template.PublicKeyAlgorithm = x509.ECDSA
				certificate, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
				if err != nil {
					b.Fatal(err)
				}
				config.Certificates = []tls.Certificate{{Certificate: [][]byte{certificate}, PrivateKey: key}}
			}
			config.MinVersion = tls.VersionTLS13
			config.MaxVersion = tls.VersionTLS13
			config.CurvePreferences = []tls.CurveID{profile.curve}
			client := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{profile.curve}}
			capture := &dosWire{Reader: bytes.NewReader(nil), capture: true}
			if err := tls.Client(capture, client).Handshake(); err == nil || capture.output.Len() == 0 {
				b.Fatal("ClientHello capture failed", err)
			}
			hello := slices.Clone(capture.output.Bytes())
			b.ReportAllocs()
			b.ResetTimer()
			cpu := dosCPUSeconds()
			for range b.N {
				wire := &dosWire{Reader: bytes.NewReader(hello)}
				err := tls.Server(wire, config).Handshake()
				if (!errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF)) || wire.written < 500 {
					b.Fatal("expected ordinary TLS server flight followed by EOF", wire.written, err)
				}
			}
			b.ReportMetric((dosCPUSeconds()-cpu)*1e9/float64(b.N), "cpu-ns/op")
			b.ReportMetric(float64(len(hello)), "request-B/op")
		})
	}
	for _, gap := range []uint64{0, 32, 100, 256, ReplayWindow - 1, ReplayWindow} {
		b.Run(fmt.Sprintf("forged_start/gap=%d", gap), func(b *testing.B) {
			session, _ := testServerSession(b)
			defer session.Close()
			forged := dosForgedStart(b, gap)
			want := ErrAuthentication
			if gap == ReplayWindow {
				want = ErrRecordLimit
			}
			b.ReportAllocs()
			b.ResetTimer()
			cpu := dosCPUSeconds()
			for range b.N {
				if _, _, err := session.AcceptStart(gap, forged); !errors.Is(err, want) {
					b.Fatal(err)
				}
			}
			b.ReportMetric((dosCPUSeconds()-cpu)*1e9/float64(b.N), "cpu-ns/op")
			b.ReportMetric(float64(len(forged)+RequestPrefixBytes), "request-B/op")
		})
	}
	b.Run("native_tls_abandoned_software_only", func(b *testing.B) {
		probe := newDoSSetup(b)
		b.ReportAllocs()
		b.ResetTimer()
		cpu := dosCPUSeconds()
		for range b.N {
			if err := probe.abandonedTLS(); err != nil {
				b.Fatal(err)
			}
		}
		if probe.issued.Load() != uint64(b.N) {
			b.Fatal("an attempt bypassed fresh certificate generation")
		}
		b.ReportMetric((dosCPUSeconds()-cpu)*1e9/float64(b.N), "cpu-ns/op")
		b.ReportMetric(float64(len(probe.hello)), "request-B/op")
	})
	b.Run("e2ee_setup_software_only", func(b *testing.B) {
		probe := newDoSSetup(b)
		b.ReportAllocs()
		b.ResetTimer()
		cpu := dosCPUSeconds()
		for range b.N {
			session, _, err := probe.e2ee.Accept(context.Background(), probe.e2eeHello)
			if err != nil {
				b.Fatal(err)
			}
			session.Close()
		}
		b.ReportMetric((dosCPUSeconds()-cpu)*1e9/float64(b.N), "cpu-ns/op")
		b.ReportMetric(float64(len(probe.e2eeHello)), "request-B/op")
	})
}

// Runs only when explicitly requested, on caller-selected CPUs. A genuine warm
// TLS request/reply competes with independent forged ratchet starts or native
// TLS ClientHellos. Rates are experiment inputs, never production policy.
func TestAdmissionCPUContentionProbe(t *testing.T) {
	input := os.Getenv("STOGAS_ADMISSION_CPU_PROBE")
	if input == "" {
		t.Skip("opt-in software CPU contention probe")
	}
	var config struct {
		Kind      string `json:"kind"`
		Workers   int    `json:"workers"`
		PerSecond int    `json:"per_second"`
		Seconds   int    `json:"seconds"`
	}
	if err := json.Unmarshal([]byte(input), &config); err != nil || config.Workers < 0 || config.Seconds <= 0 || config.PerSecond < 0 || (config.Kind != "ratchet" && config.Kind != "tls") {
		t.Fatal("invalid benchmark configuration", err)
	}
	probe := newDoSSetup(t)
	clientWire, serverWire := net.Pipe()
	defer clientWire.Close()
	defer serverWire.Close()
	client, server := tls.Client(clientWire, probe.client), tls.Server(serverWire, probe.tlsConfig)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	serverReady := make(chan error, 1)
	go func() { serverReady <- server.HandshakeContext(ctx) }()
	if err := client.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := <-serverReady; err != nil {
		t.Fatal(err)
	}
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		var body [4096]byte
		for {
			if _, err := io.ReadFull(server, body[:]); err != nil {
				return
			}
			if _, err := server.Write(body[:1]); err != nil {
				return
			}
		}
	}()
	start := make(chan struct{})
	var stop atomic.Bool
	var attempted atomic.Uint64
	var failed atomic.Uint64
	var workers sync.WaitGroup
	var began time.Time
	for worker := range config.Workers {
		session, _ := testServerSession(t)
		forged := dosForgedStart(t, ReplayWindow-1)
		workers.Go(func() {
			defer session.Close()
			<-start
			for sequence := worker; !stop.Load(); sequence += config.Workers {
				if config.PerSecond > 0 {
					if wait := time.Until(began.Add(time.Duration(sequence) * time.Second / time.Duration(config.PerSecond))); wait > 0 {
						time.Sleep(wait)
					}
				}
				if stop.Load() {
					return
				}
				var err error
				if config.Kind == "ratchet" {
					_, _, err = session.AcceptStart(ReplayWindow-1, forged)
					if errors.Is(err, ErrAuthentication) {
						err = nil
					}
				} else {
					err = probe.abandonedTLS()
				}
				if err != nil {
					failed.Add(1)
				}
				attempted.Add(1)
			}
		})
	}
	var unused atomic.Uint64
	before := benchmarkStats(&unused, &unused, &unused)
	began = time.Now()
	finish := began.Add(time.Duration(config.Seconds) * time.Second)
	close(start)
	defer func() {
		stop.Store(true)
		workers.Wait()
	}()
	var payload [4096]byte
	var reply [1]byte
	var latency []int64
	_ = clientWire.SetDeadline(finish.Add(5 * time.Second))
	for time.Now().Before(finish) {
		iteration := time.Now()
		if _, err := client.Write(payload[:]); err != nil {
			t.Fatal(err)
		}
		if _, err := io.ReadFull(client, reply[:]); err != nil {
			t.Fatal(err)
		}
		latency = append(latency, time.Since(iteration).Nanoseconds())
	}
	stop.Store(true)
	workers.Wait()
	elapsed := time.Since(began)
	after := benchmarkStats(&unused, &unused, &unused)
	clientWire.Close()
	serverWire.Close()
	<-serverDone
	if failed.Load() != 0 || len(latency) == 0 {
		t.Fatal("unexpected probe failures", failed.Load())
	}
	slices.Sort(latency)
	percentile := func(percent int) float64 { return float64(latency[(len(latency)*percent+99)/100-1]) / 1e6 }
	result, err := json.Marshal(map[string]any{
		"config": config, "elapsed_seconds": elapsed.Seconds(), "attack_operations": attempted.Load(),
		"completed_tls_roundtrips": len(latency), "p50_ms": percentile(50), "p95_ms": percentile(95), "p99_ms": percentile(99),
		"max_ms": float64(latency[len(latency)-1]) / 1e6, "cpu_seconds": after.CPUSeconds - before.CPUSeconds,
		"rss_before_kib": before.RSSKiB, "rss_after_kib": after.RSSKiB, "peak_rss_kib": after.PeakRSSKiB,
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Printf("ADMISSION_CPU_PROBE=%s\n", result)
}
