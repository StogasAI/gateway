package exporter

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// A receiver must offer TLS 1.2 or later, which OpenTelemetry collectors and log receivers do by
// default: earlier versions are deprecated (RFC 8996).
func TestDeliveryNeedsTLS12OrLater(t *testing.T) {
	for _, tc := range []struct {
		version uint16
		want    bool
	}{{tls.VersionTLS11, false}, {tls.VersionTLS12, true}, {tls.VersionTLS13, true}} {
		t.Run(fmt.Sprint(tls.VersionName(tc.version)), func(t *testing.T) {
			var received atomic.Int32
			receiver := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				received.Add(1)
				w.WriteHeader(http.StatusOK)
			}))
			receiver.TLS = &tls.Config{MinVersion: tls.VersionTLS10, MaxVersion: tc.version}
			receiver.StartTLS()
			defer receiver.Close()
			e := New(context.Background(), testOptions(true, 16<<20))
			defer e.Close()
			roots := x509.NewCertPool()
			roots.AddCert(receiver.Certificate())
			e.client.transport.TLSClientConfig.RootCAs = roots
			e.Start(testConfig(receiver.URL), "id", "", Trace{}).Finish("id", "success", testRecord("id"), testMetadata())
			await(t, func() bool { return e.Diagnostics().PendingDeliveries == 0 })
			if delivered := e.Diagnostics().Delivered == 1; delivered != tc.want || (received.Load() == 1) != tc.want {
				t.Fatalf("delivery over %s: %+v, %d received", tls.VersionName(tc.version), e.Diagnostics(), received.Load())
			}
		})
	}
}
