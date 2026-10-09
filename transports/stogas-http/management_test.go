package stogashttp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	ref "github.com/StogasAI/verifier/go/reference"
	stogas "github.com/maximhq/bifrost/transports/stogas"
	confidentialruntime "github.com/maximhq/bifrost/transports/stogas/confidential/runtime"
)

func TestPrivateDrainRequiresActuatorAndExactGuest(t *testing.T) {
	now := time.Now()
	observer := diagnosticsTestCertificate(t, nil, now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageClientAuth)
	actuator := diagnosticsTestCertificate(t, nil, now.Add(-time.Hour), now.Add(time.Hour), x509.ExtKeyUsageClientAuth)
	pin := func(cert tls.Certificate) string {
		digest := sha256.Sum256(cert.Leaf.RawSubjectPublicKeyInfo)
		return hex.EncodeToString(digest[:])
	}
	nodeID := ref.SNPNodeID([32]byte{9})
	s := &Server{config: stogas.Config{DiagnosticsClientSPKISHA256: pin(observer), DrainClientSPKISHA256: pin(actuator)}, secure: &confidentialruntime.Runtime{}, sessionNodeID: nodeID, requests: newRequestDrain()}
	if err := s.routes(); err != nil {
		t.Fatal(err)
	}
	config, err := s.diagnosticsTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	fixture := httptest.NewTLSServer(http.NotFoundHandler())
	config.GetCertificate, config.Certificates = nil, fixture.TLS.Certificates
	roots := x509.NewCertPool()
	roots.AddCert(fixture.Certificate())
	fixture.Close()
	endpoint := httptest.NewUnstartedServer(s.diagnosticsServer.Handler)
	endpoint.TLS = config
	endpoint.StartTLS()
	defer endpoint.Close()
	for _, test := range []struct {
		name, body  string
		certificate tls.Certificate
		status      int
	}{
		{"observer", `{"node_id":"` + nodeID + `"}`, observer, http.StatusForbidden},
		{"previous guest", `{"node_id":"` + ref.SNPNodeID([32]byte{8}) + `"}`, actuator, http.StatusConflict},
		{"trailing", `{"node_id":"` + nodeID + `"} {}`, actuator, http.StatusBadRequest},
		{"unknown command", `{"node_id":"` + nodeID + `","resume":true}`, actuator, http.StatusBadRequest},
		{"oversized", strings.Repeat(" ", 1025), actuator, http.StatusBadRequest},
		{"authorized", `{"node_id":"` + nodeID + `"}`, actuator, http.StatusAccepted},
		{"repeated", `{"node_id":"` + nodeID + `"}`, actuator, http.StatusAccepted},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com", Certificates: []tls.Certificate{test.certificate}}}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: time.Second}
			response, err := client.Post(endpoint.URL+"/drain", "application/json", strings.NewReader(test.body))
			if err != nil {
				t.Fatal(err)
			}
			_, _ = io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != test.status {
				t.Fatalf("status %d, want %d", response.StatusCode, test.status)
			}
			if s.requests.diagnostics().Draining != (test.status == http.StatusAccepted) {
				t.Fatal("incorrect admission state")
			}
			response, err = client.Get(endpoint.URL + "/diagnostics/v1")
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusOK {
				t.Fatal("management unavailable after drain")
			}
		})
	}
	if s.requests.begin() {
		t.Fatal("terminal drain reopened work")
	}
}

func TestPublicDrainFinishesStreamAndLeavesPrivateDiagnostics(t *testing.T) {
	entered, finish := make(chan struct{}), make(chan struct{})
	public := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("start"))
		w.(http.Flusher).Flush()
		close(entered)
		<-finish
		_, _ = w.Write([]byte("end"))
	}))
	public.EnableHTTP2 = true
	public.StartTLS()
	defer public.Close()
	s := &Server{server: public.Config, requests: newRequestDrain()}
	private := httptest.NewServer(requestHandler(s.diagnostics))
	defer private.Close()
	response, err := public.Client().Get(public.URL)
	if err != nil {
		t.Fatal(err)
	}
	<-entered
	drained := make(chan struct{})
	go func() { s.drainPublic(); close(drained) }()
	deadline, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	for !s.requests.diagnostics().Draining {
		select {
		case <-deadline.Done():
			t.Fatal("drain never started")
		case <-time.After(time.Millisecond):
		}
	}
	if s.requests.begin() {
		t.Fatal("drain still admitted work")
	}
	select {
	case <-drained:
		t.Fatal("drain finished before admitted stream")
	default:
	}
	close(finish)
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil || !bytes.Equal(body, []byte("startend")) {
		t.Fatal("drain cut the stream", err)
	}
	select {
	case <-drained:
	case <-deadline.Done():
		t.Fatal("public drain did not finish")
	}
	status, err := private.Client().Get(private.URL)
	if err != nil {
		t.Fatal(err)
	}
	status.Body.Close()
	if status.StatusCode != http.StatusOK {
		t.Fatal("drain closed diagnostics")
	}
}
