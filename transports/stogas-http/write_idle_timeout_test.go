package stogashttp

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/billing"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

func TestResponseWritesBoundChunksAndClearDeadlines(t *testing.T) {
	recorder := &deadlineRecordingWriter{ResponseRecorder: httptest.NewRecorder()}
	limit := time.Now().Add(time.Second)
	writer := &responseWriter{writer: recorder, control: http.NewResponseController(recorder), deadline: limit, idle: time.Minute}
	data := make([]byte, (128<<10)+1)
	if n, err := writer.Write(data); err != nil || n != len(data) {
		t.Fatalf("write = %d, %v", n, err)
	}
	if len(recorder.deadlines) != 6 || recorder.maxWrite != 64<<10 {
		t.Fatalf("deadlines=%v max write=%d", recorder.deadlines, recorder.maxWrite)
	}
	for i, deadline := range recorder.deadlines {
		if i%2 == 0 && !deadline.Equal(limit) || i%2 != 0 && !deadline.IsZero() {
			t.Fatalf("deadline %d = %s", i, deadline)
		}
	}
	// An unsupported writer cannot silently remove the write bound.
	unsupported := httptest.NewRecorder()
	writer = &responseWriter{writer: unsupported, control: http.NewResponseController(unsupported), idle: time.Minute}
	if _, err := writer.Write([]byte("private")); !errors.Is(err, http.ErrNotSupported) || unsupported.Body.Len() != 0 {
		t.Fatalf("unsupported writer = %v, %s", err, unsupported.Body)
	}
}

func TestRequestContextSetsAbsoluteDownstreamDeliveryLimit(t *testing.T) {
	ctx := newTestRequest(t)
	_, _, cancel, err := newRequestContext(ctx, time.Now(), testResolution(), apiCredential{Raw: "sk-test"}, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	remaining := time.Until(ctx.deliveryDeadline)
	if remaining <= billing.GatewayRequestLifetime || remaining > billing.GatewayRequestLifetime+downstreamWriteIdleTimeout+time.Second {
		t.Fatalf("delivery deadline = %s", remaining)
	}
}

// A client grants no flow-control credit to stream 1 but continues reading the
// connection. The stream deadline must reset only stream 1, including while
// other streams keep connection-level byte progress healthy.
func TestHTTP2StalledStreamDeadlinePreservesOtherStreams(t *testing.T) {
	stalled := make(chan error, 1)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writer := &responseWriter{writer: w, control: http.NewResponseController(w), idle: 100 * time.Millisecond}
		if r.URL.Path == "/stalled" {
			_, err := writer.Write(make([]byte, 64<<10))
			stalled <- err
			return
		}
		_, _ = writer.Write([]byte("healthy"))
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	conn, err := tls.Dial("tcp", server.Listener.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if conn.ConnectionState().NegotiatedProtocol != "h2" {
		t.Fatal("HTTP/2 was not negotiated")
	}
	if _, err := io.WriteString(conn, http2.ClientPreface); err != nil {
		t.Fatal(err)
	}
	framer := http2.NewFramer(conn, conn)
	if err := framer.WriteSettings(http2.Setting{ID: http2.SettingInitialWindowSize, Val: 0}); err != nil {
		t.Fatal(err)
	}
	send := func(id uint32, path string, credit bool) {
		t.Helper()
		var block bytes.Buffer
		encoder := hpack.NewEncoder(&block)
		for _, field := range []hpack.HeaderField{{Name: ":method", Value: "GET"}, {Name: ":scheme", Value: "https"}, {Name: ":authority", Value: "gateway.test"}, {Name: ":path", Value: path}} {
			if err := encoder.WriteField(field); err != nil {
				t.Fatal(err)
			}
		}
		if err := framer.WriteHeaders(http2.HeadersFrameParam{StreamID: id, BlockFragment: block.Bytes(), EndHeaders: true, EndStream: true}); err != nil {
			t.Fatal(err)
		}
		if credit {
			if err := framer.WriteWindowUpdate(id, 1024); err != nil {
				t.Fatal(err)
			}
		}
	}
	send(1, "/stalled", false)
	send(3, "/healthy", true)
	healthy, reset := false, false
	for !healthy || !reset {
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		switch frame := frame.(type) {
		case *http2.SettingsFrame:
			if !frame.IsAck() {
				if err := framer.WriteSettingsAck(); err != nil {
					t.Fatal(err)
				}
			}
		case *http2.DataFrame:
			if frame.StreamID == 3 && string(frame.Data()) == "healthy" {
				healthy = true
			}
		case *http2.RSTStreamFrame:
			if frame.StreamID == 1 {
				reset = true
			} else {
				t.Fatalf("healthy stream reset: %v", frame)
			}
		case *http2.GoAwayFrame:
			t.Fatalf("connection closed instead of one stream: %v", frame)
		}
	}
	select {
	case err := <-stalled:
		if err == nil {
			t.Fatal("stalled stream succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("stalled handler did not return")
	}
	send(5, "/healthy", true)
	for {
		frame, err := framer.ReadFrame()
		if err != nil {
			t.Fatal(err)
		}
		if data, ok := frame.(*http2.DataFrame); ok && data.StreamID == 5 && string(data.Data()) == "healthy" {
			break
		}
	}
}

type deadlineRecordingWriter struct {
	*httptest.ResponseRecorder
	deadlines []time.Time
	maxWrite  int
}

func (w *deadlineRecordingWriter) Write(p []byte) (int, error) {
	w.maxWrite = max(w.maxWrite, len(p))
	return w.ResponseRecorder.Write(p)
}
func (w *deadlineRecordingWriter) SetWriteDeadline(deadline time.Time) error {
	w.deadlines = append(w.deadlines, deadline)
	return nil
}
