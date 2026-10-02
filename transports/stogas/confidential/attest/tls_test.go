package attest

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"
)

func TestNativeCallbackHasAbsoluteDeadlineBeyondSocketTimeout(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		clientWire, serverWire := net.Pipe()
		defer clientWire.Close()
		defer serverWire.Close()
		start := time.Now()
		deadline := start.Add(time.Second)
		var entered atomic.Bool
		config, err := ConfigureTLS(&tls.Config{}, func() bool { return true }, func(ctx context.Context, _ [32]byte) (*tls.Certificate, error) {
			entered.Store(true)
			if actual, ok := ctx.Deadline(); !ok || !actual.Equal(deadline) {
				t.Error("setup deadline was absent or reset", actual)
			}
			<-ctx.Done()
			return nil, ctx.Err()
		})
		if err != nil {
			t.Fatal(err)
		}
		// A socket timer alone cannot interrupt a callback blocked on local work.
		serverWire.SetDeadline(start.Add(100 * time.Millisecond))
		ctx := WithSetupDeadline(context.Background(), deadline)
		// Reapplying the helper must not grant another full setup period.
		ctx = WithSetupDeadline(ctx, deadline.Add(time.Minute))
		server := tls.Server(serverWire, config)
		serverDone := make(chan error, 1)
		go func() { serverDone <- server.HandshakeContext(ctx) }()
		client := tls.Client(clientWire, testNativeClient())
		clientDone := make(chan error, 1)
		go func() { clientDone <- client.Handshake() }()
		synctest.Wait()
		if !entered.Load() {
			t.Fatal("certificate callback was not reached")
		}
		time.Sleep(200 * time.Millisecond)
		select {
		case err := <-serverDone:
			t.Fatal("callback ended before its context deadline", err)
		default:
		}
		time.Sleep(800 * time.Millisecond)
		synctest.Wait()
		if err := <-serverDone; !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("callback outlived setup deadline", err)
		}
		serverWire.Close()
		if err := <-clientDone; err == nil {
			t.Fatal("stalled setup accepted")
		}
		if ctx.Err() != nil {
			t.Fatal("setup timer canceled reusable connection context")
		}
	})
}

func TestNativeHandshakeRejectsMissingOrExpiredSetupDeadline(t *testing.T) {
	for _, expired := range []bool{false, true} {
		t.Run(map[bool]string{false: "missing", true: "expired"}[expired], func(t *testing.T) {
			config, err := ConfigureTLS(&tls.Config{}, func() bool { return true }, func(context.Context, [32]byte) (*tls.Certificate, error) {
				t.Error("unbounded or expired setup reached quote generation")
				return nil, errors.New("unexpected issuer call")
			})
			if err != nil {
				t.Fatal(err)
			}
			clientWire, serverWire := net.Pipe()
			defer clientWire.Close()
			defer serverWire.Close()
			_ = clientWire.SetDeadline(time.Now().Add(3 * time.Second))
			_ = serverWire.SetDeadline(time.Now().Add(3 * time.Second))
			ctx := context.Background()
			if expired {
				ctx = WithSetupDeadline(ctx, time.Now().Add(-time.Second))
			}
			done := make(chan error, 1)
			go func() { done <- tls.Server(serverWire, config).HandshakeContext(ctx) }()
			if err := tls.Client(clientWire, testNativeClient()).Handshake(); err == nil {
				t.Fatal("client accepted invalid setup")
			}
			if err := <-done; err == nil || expired && !errors.Is(err, context.DeadlineExceeded) {
				t.Fatal("unexpected server setup result", err)
			}
		})
	}
}

func testTLSCertificate(t *testing.T) *tls.Certificate {
	t.Helper()
	key, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatal(err)
	}
	return testCertificateWithKey(t, key)
}

func testCertificateWithKey(t *testing.T, key crypto.Signer) *tls.Certificate {
	t.Helper()
	template := &x509.Certificate{SerialNumber: big.NewInt(1), DNSNames: []string{"gateway.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func testTLSExchange(serverConfig, clientConfig *tls.Config, wrapClient func(net.Conn) net.Conn) (tls.ConnectionState, error, error) {
	clientWire, serverWire := net.Pipe()
	defer clientWire.Close()
	defer serverWire.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if wrapClient != nil {
		clientWire = wrapClient(clientWire)
	}
	client, server := tls.Client(clientWire, clientConfig), tls.Server(serverWire, serverConfig)
	serverResult := make(chan error, 1)
	go func() { serverResult <- server.HandshakeContext(ctx) }()
	clientErr := client.HandshakeContext(ctx)
	if clientErr != nil {
		clientWire.Close()
	}
	serverErr := <-serverResult
	return client.ConnectionState(), clientErr, serverErr
}

func testNativeClient() *tls.Config {
	// These tests exercise server negotiation/callback order. Client evidence and
	// CertificateVerify validation are covered by the verifier transport tests.
	return &tls.Config{InsecureSkipVerify: true, ServerName: "gateway.test", MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, CurvePreferences: []tls.CurveID{tls.X25519MLKEM768}, NextProtos: []string{NativeALPN([32]byte{1}), "h2", "http/1.1"}}
}

func TestNativeALPNRejectsMalformedAmbiguousAndUnsupportedOffers(t *testing.T) {
	challenge := [32]byte{1, 2, 3}
	marker := NativeALPN(challenge)
	if len(marker) != 60 {
		t.Fatal(len(marker))
	}
	parsed, requested, err := parseNativeALPN([]string{marker, "h2"})
	if err != nil || !requested || parsed != challenge {
		t.Fatal(parsed, requested, err)
	}
	for _, protocols := range [][]string{
		{marker}, {marker, marker, "h2"}, {marker, NativeALPN([32]byte{2}), "h2"},
		{"stogas-attest-v2." + marker[len(NativeALPNPrefix):], "h2"},
		{marker + "=", "h2"}, {marker[:len(marker)-1], "h2"},
		{NativeALPNPrefix + strings.Repeat("/", 43), "h2"},
		{marker[:len(marker)-1] + "B", "h2"},
	} {
		if _, requested, err := parseNativeALPN(protocols); !requested || !errors.Is(err, ErrAttestationALPN) {
			t.Fatal(protocols, requested, err)
		}
	}
	if _, requested, err := parseNativeALPN([]string{"h2", "http/1.1"}); err != nil || requested {
		t.Fatal(requested, err)
	}
}

func TestNativeTLSIsStrictAndOrdinaryTLSKeepsItsCertificate(t *testing.T) {
	ordinaryKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ordinary, native := testCertificateWithKey(t, ordinaryKey), testTLSCertificate(t)
	var issued atomic.Int64
	var allowed atomic.Bool
	allowed.Store(true)
	base := &tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{*ordinary}, NextProtos: []string{"h2", "http/1.1"}}
	config, err := ConfigureTLS(base, allowed.Load, func(_ context.Context, nonce [32]byte) (*tls.Certificate, error) {
		if nonce != [32]byte{1} {
			t.Error("wrong challenge")
		}
		issued.Add(1)
		return native, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"hybrid", "classical", "tls12", "ordinary12", "ordinary13", "paused", "bad-marker"} {
		t.Run(name, func(t *testing.T) {
			before := issued.Load()
			client := testNativeClient()
			success, expectIssue, wantCertificate := false, false, native
			switch name {
			case "hybrid":
				success, expectIssue = true, true
			case "classical":
				client.CurvePreferences = []tls.CurveID{tls.X25519}
			case "tls12":
				client.MinVersion, client.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
				client.CurvePreferences = []tls.CurveID{tls.X25519}
			case "ordinary12", "ordinary13":
				client.NextProtos = []string{"h2"}
				client.CurvePreferences = []tls.CurveID{tls.X25519}
				success, wantCertificate = true, ordinary
				if name == "ordinary12" {
					client.MinVersion, client.MaxVersion = tls.VersionTLS12, tls.VersionTLS12
				}
			case "paused":
				allowed.Store(false)
				defer allowed.Store(true)
			case "bad-marker":
				client.NextProtos[0] += "="
			}
			state, clientErr, serverErr := testTLSExchange(config, client, nil)
			if success {
				if clientErr != nil || serverErr != nil {
					t.Fatal(clientErr, serverErr)
				}
				if state.NegotiatedProtocol != "h2" || !bytes.Equal(state.PeerCertificates[0].Raw, wantCertificate.Certificate[0]) {
					t.Fatal("wrong ALPN or certificate")
				}
				if expectIssue && (state.Version != tls.VersionTLS13 || state.CurveID != tls.X25519MLKEM768 || state.DidResume) {
					t.Fatal("native security policy not enforced")
				}
			} else if clientErr == nil || serverErr == nil {
				t.Fatal("invalid setup accepted", clientErr, serverErr)
			}
			wantCalls := before
			if expectIssue {
				wantCalls++
			}
			if issued.Load() != wantCalls {
				t.Fatal("quote issuer ran before required checks", issued.Load(), wantCalls)
			}
		})
	}
	if base.GetConfigForClient != nil || base.SessionTicketsDisabled || len(base.Certificates) != 1 {
		t.Fatal("mutated shared base TLS config")
	}
}

type corruptKeyShareConn struct {
	net.Conn
	changed bool
}

func (c *corruptKeyShareConn) Write(encoded []byte) (int, error) {
	if !c.changed {
		encoded = append([]byte(nil), encoded...)
		// Go writes ClientHello in one handshake record. Keep framing valid but
		// replace the first ML-KEM encoded coefficient with a noncanonical value.
		i := 5 + 4 + 2 + 32
		if len(encoded) > i {
			i += 1 + int(encoded[i])
			if len(encoded) >= i+2 {
				i += 2 + int(binary.BigEndian.Uint16(encoded[i:]))
			}
			if len(encoded) > i {
				i += 1 + int(encoded[i])
			}
			i += 2
			for i+4 <= len(encoded) {
				kind, n := binary.BigEndian.Uint16(encoded[i:]), int(binary.BigEndian.Uint16(encoded[i+2:]))
				i += 4
				if i+n > len(encoded) {
					break
				}
				if kind == 51 && n >= 8 && binary.BigEndian.Uint16(encoded[i+2:]) == uint16(tls.X25519MLKEM768) {
					encoded[i+6], encoded[i+7] = 255, 255
					c.changed = true
					break
				}
				i += n
			}
		}
	}
	return c.Conn.Write(encoded)
}

func TestNativeTLSRejectsInvalidHybridShareBeforeCertificateWork(t *testing.T) {
	var issued atomic.Int64
	config, err := ConfigureTLS(&tls.Config{}, func() bool { return true }, func(context.Context, [32]byte) (*tls.Certificate, error) {
		issued.Add(1)
		return nil, errors.New("issuer must not run")
	})
	if err != nil {
		t.Fatal(err)
	}
	var corrupt *corruptKeyShareConn
	_, clientErr, serverErr := testTLSExchange(config, testNativeClient(), func(c net.Conn) net.Conn { corrupt = &corruptKeyShareConn{Conn: c}; return corrupt })
	if corrupt == nil || !corrupt.changed || clientErr == nil || serverErr == nil || issued.Load() != 0 {
		t.Fatal("invalid share reached issuer", clientErr, serverErr, issued.Load())
	}
}

func TestNativeTLSRejectsMissingMLDSA65BeforeCertificateWork(t *testing.T) {
	var issued atomic.Int64
	config, err := ConfigureTLS(&tls.Config{}, func() bool { return true }, func(context.Context, [32]byte) (*tls.Certificate, error) {
		issued.Add(1)
		return nil, errors.New("issuer must not run")
	})
	if err != nil {
		t.Fatal(err)
	}
	hello := captureClientHello(t)
	i := 5 + 4 + 2 + 32
	i += 1 + int(hello[i])
	i += 2 + int(binary.BigEndian.Uint16(hello[i:]))
	i += 1 + int(hello[i]) + 2
	changed := false
	for i+4 <= len(hello) {
		kind, n := binary.BigEndian.Uint16(hello[i:]), int(binary.BigEndian.Uint16(hello[i+2:]))
		i += 4
		if i+n > len(hello) {
			t.Fatal("invalid captured ClientHello")
		}
		if kind == 13 {
			for j := i + 2; j+2 <= i+n; j += 2 {
				if binary.BigEndian.Uint16(hello[j:]) == uint16(tls.MLDSA65) {
					binary.BigEndian.PutUint16(hello[j:], 0xfefe)
					changed = true
				}
			}
		}
		i += n
	}
	if !changed {
		t.Fatal("Go did not advertise ML-DSA-65")
	}
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	done := make(chan error, 1)
	go func() { done <- tls.Server(server, config).HandshakeContext(ctx) }()
	if _, err := client.Write(hello); err != nil {
		t.Fatal(err)
	}
	if record := readTLSRecord(t, client); record[0] != 21 {
		t.Fatal("missing signature scheme did not produce a TLS alert")
	}
	if err := <-done; err == nil || issued.Load() != 0 {
		t.Fatal("unsupported signature reached quote generation", err, issued.Load())
	}
}

func TestNativeTLSDoesNotReuseSignerOrSessionTickets(t *testing.T) {
	var issued atomic.Int64
	config, err := ConfigureTLS(&tls.Config{}, func() bool { return true }, func(context.Context, [32]byte) (*tls.Certificate, error) {
		issued.Add(1)
		return testTLSCertificate(t), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	client := testNativeClient()
	client.ClientSessionCache = tls.NewLRUClientSessionCache(2)
	first, clientErr, serverErr := testTLSExchange(config, client, nil)
	if clientErr != nil || serverErr != nil {
		t.Fatal(clientErr, serverErr)
	}
	second, clientErr, serverErr := testTLSExchange(config, client, nil)
	if clientErr != nil || serverErr != nil {
		t.Fatal(clientErr, serverErr)
	}
	if issued.Load() != 2 || second.DidResume || bytes.Equal(first.PeerCertificates[0].RawSubjectPublicKeyInfo, second.PeerCertificates[0].RawSubjectPublicKeyInfo) {
		t.Fatal("reused native identity")
	}
}

// These helpers keep a real Go ClientHello's framing and algorithms, changing
// only key_share to force the server's RFC 8446 HelloRetryRequest path.
func readTLSRecord(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	header := make([]byte, 5)
	if _, err := io.ReadFull(conn, header); err != nil {
		t.Fatal(err)
	}
	record := append(header, make([]byte, int(binary.BigEndian.Uint16(header[3:])))...)
	if _, err := io.ReadFull(conn, record[5:]); err != nil {
		t.Fatal(err)
	}
	return record
}

func captureClientHello(t *testing.T) []byte {
	t.Helper()
	a, b := net.Pipe()
	defer b.Close()
	_ = b.SetDeadline(time.Now().Add(3 * time.Second))
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer a.Close()
		_ = tls.Client(a, testNativeClient()).Handshake()
	}()
	hello := readTLSRecord(t, b)
	b.Close()
	<-done
	return hello
}

func withoutKeyShare(t *testing.T, hello []byte) []byte {
	t.Helper()
	i := 5 + 4 + 2 + 32
	i += 1 + int(hello[i])
	i += 2 + int(binary.BigEndian.Uint16(hello[i:]))
	i += 1 + int(hello[i])
	extensionLength := i
	i += 2
	for i+4 <= len(hello) {
		n := int(binary.BigEndian.Uint16(hello[i+2:]))
		if binary.BigEndian.Uint16(hello[i:]) == 51 {
			result := append([]byte(nil), hello[:i+2]...)
			result = append(result, 0, 2, 0, 0) // extension length two; empty shares vector
			result = append(result, hello[i+4+n:]...)
			binary.BigEndian.PutUint16(result[extensionLength:], uint16(len(result)-extensionLength-2))
			binary.BigEndian.PutUint16(result[3:], uint16(len(result)-5))
			size := len(result) - 9
			result[6], result[7], result[8] = byte(size>>16), byte(size>>8), byte(size)
			return result
		}
		i += 4 + n
	}
	t.Fatal("ClientHello did not contain key_share")
	return nil
}

func TestNativeTLSHelloRetryRequestKeepsChallengeAndDefersIssuance(t *testing.T) {
	certificate := testTLSCertificate(t)
	issued := make(chan [32]byte, 1)
	config, err := ConfigureTLS(&tls.Config{}, func() bool { return true }, func(_ context.Context, nonce [32]byte) (*tls.Certificate, error) {
		issued <- nonce
		return certificate, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	hello := captureClientHello(t)
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	_ = client.SetDeadline(time.Now().Add(3 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- tls.Server(server, config).HandshakeContext(ctx) }()
	if _, err := client.Write(withoutKeyShare(t, hello)); err != nil {
		t.Fatal(err)
	}
	retry := readTLSRecord(t, client)
	if retry[0] != 22 || retry[5] != 2 {
		t.Fatal("expected HelloRetryRequest")
	}
	if record := readTLSRecord(t, client); record[0] != 20 {
		t.Fatal("expected compatibility CCS")
	}
	select {
	case <-issued:
		t.Fatal("generated evidence before retry key exchange")
	default:
	}
	// Only the initial record may carry the TLS 1.0 compatibility version.
	hello[1], hello[2] = 3, 3
	if _, err := client.Write(hello); err != nil {
		t.Fatal(err)
	}
	select {
	case nonce := <-issued:
		if nonce != [32]byte{1} {
			t.Fatal("HRR changed challenge")
		}
	case <-ctx.Done():
		t.Fatal("valid retry did not reach certificate selection")
	}
	client.Close() // The test stops before client Finished; issuer ordering is the assertion.
	if err := <-done; err == nil {
		t.Fatal("accepted missing client Finished")
	}
}
