package stogashttp

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"
	"github.com/maximhq/bifrost/core/providers/utils"
	"github.com/maximhq/bifrost/transports/stogas/providerio"
	"github.com/valyala/fasthttp"
)

func encodeProviderFixture(t *testing.T, data []byte, coding string) []byte {
	t.Helper()
	for _, name := range strings.Split(coding, ",") {
		var output bytes.Buffer
		var writer io.WriteCloser
		switch strings.TrimSpace(name) {
		case "":
			continue
		case "gzip":
			writer = gzip.NewWriter(&output)
		case "deflate":
			writer = zlib.NewWriter(&output)
		case "br":
			writer = brotli.NewWriter(&output)
		case "zstd":
			var err error
			writer, err = zstd.NewWriter(&output, zstd.WithEncoderConcurrency(1), zstd.WithWindowSize(1<<20))
			if err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatal("unknown fixture encoding")
		}
		if _, err := writer.Write(data); err != nil {
			t.Fatal(err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		data = output.Bytes()
	}
	return data
}

func TestProviderResponseAdmissionBeforeBufferingAndDecompression(t *testing.T) {
	content := []byte(`{"content":"` + strings.Repeat("private-output-", 75_000) + `"}`)
	for _, coding := range []string{"", "gzip", "deflate", "br", "zstd", "gzip, br"} {
		encoded := encodeProviderFixture(t, content, coding)
		for _, streaming := range []bool{false, true} {
			name := coding + "/unary"
			if streaming {
				name = coding + "/stream"
			}
			t.Run(name, func(t *testing.T) {
				var calls atomic.Int32
				provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					calls.Add(1)
					if r.URL.Path == "/small" {
						_, _ = io.WriteString(w, `{"content":"recovered"}`)
						return
					}
					w.Header().Set("Content-Type", "application/json")
					if coding != "" {
						w.Header().Set("Content-Encoding", coding)
					}
					_, _ = w.Write(encoded)
				}))
				defer provider.Close()
				client := &fasthttp.Client{Transport: providerio.NewTransport(2<<20, false), StreamResponseBody: streaming, MaxConnsPerHost: 1, ReadTimeout: time.Second}
				defer client.CloseIdleConnections()
				for index, limit := range []int64{minimumRequestWeightBytes, 128 << 20, minimumRequestWeightBytes} {
					admission := &requestMemoryAdmission{budget: limit}
					lease, ok := admission.acquire(0)
					if !ok {
						t.Fatal("initial request admission")
					}
					ctx := providerio.WithBudget(t.Context(), lease)
					request, response := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
					request.Header.SetMethod(http.MethodPost)
					path := "/large"
					if index == 2 {
						path = "/small"
					}
					request.SetRequestURI(provider.URL + path)
					err := utils.DoRequestWithContext(ctx, client, request, response)
					var data []byte
					if err == nil {
						if streaming {
							data, err = io.ReadAll(response.BodyStream())
						} else {
							data = append([]byte(nil), response.Body()...)
						}
					}
					if index == 0 {
						if !errors.Is(err, providerio.ErrCapacity) {
							t.Fatalf("capacity failure=%v", err)
						}
						if admission.diagnostics().ProviderResponseCapacityFailures != 1 {
							t.Fatal("provider response capacity failure was not counted")
						}
					} else {
						want := content
						if index == 2 {
							want = []byte(`{"content":"recovered"}`)
						}
						if err != nil || !bytes.Equal(data, want) {
							t.Fatalf("response bytes=%d, error=%v", len(data), err)
						}
						if len(response.Header.Peek("Content-Encoding")) != 0 {
							t.Fatal("decoded response kept coding header")
						}
						if admission.diagnostics().ProviderResponseCapacityFailures != 0 {
							t.Fatal("successful provider response counted a capacity failure")
						}
					}
					fasthttp.ReleaseRequest(request)
					fasthttp.ReleaseResponse(response)
					if admission.streamStateReserved.Load() != 0 {
						t.Fatal("closed response retained decoder scratch")
					}
					if admission.peakReserved.Load() > limit {
						t.Fatal("provider exceeded aggregate admission")
					}
					if admission.reserved.Load() == 0 {
						t.Fatal("socket close released live response ownership")
					}
					lease.release()
					if admission.reserved.Load() != 0 {
						t.Fatal("request retained provider admission")
					}
				}
				if calls.Load() != 3 {
					t.Fatalf("provider call replay: %d", calls.Load())
				}
			})
		}
	}
}

func TestProviderResponseRejectsDenseStructureAndExpandedSize(t *testing.T) {
	for _, tc := range []struct {
		name, content, coding string
		budget                int64
		maximum               int
		want                  error
	}{
		{"dense JSON", `{"items":[` + strings.Repeat(`{},`, 39_999) + `{}]}`, "", 2 << 20, 2 << 20, providerio.ErrCapacity},
		{"dense SSE after quoted comment", ": keepalive \"\n\ndata: {\"choices\":[" + strings.Repeat(`{},`, 39_999) + `{}]}`, "", 2 << 20, 2 << 20, providerio.ErrCapacity},
		{"dense SSE after quoted CRLF comment", ": keepalive \"\r\n\r\ndata: {\"choices\":[" + strings.Repeat(`{},`, 39_999) + `{}]}`, "", 2 << 20, 2 << 20, providerio.ErrCapacity},
		{"gzip expansion", `{"content":"` + strings.Repeat("x", 1<<20) + `"}`, "gzip", 128 << 20, 512 << 10, providerio.ErrTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded := encodeProviderFixture(t, []byte(tc.content), tc.coding)
			streaming := strings.HasPrefix(tc.content, ":")
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if streaming {
					w.Header().Set("Content-Type", "text/event-stream")
				}
				if tc.coding != "" {
					w.Header().Set("Content-Encoding", tc.coding)
				}
				_, _ = w.Write(encoded)
			}))
			defer provider.Close()
			admission := &requestMemoryAdmission{budget: tc.budget}
			lease, _ := admission.acquire(0)
			defer lease.release()
			client := &fasthttp.Client{Transport: providerio.NewTransport(tc.maximum, false), StreamResponseBody: streaming, ReadTimeout: time.Second}
			defer client.CloseIdleConnections()
			request, response := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
			defer fasthttp.ReleaseRequest(request)
			defer fasthttp.ReleaseResponse(response)
			request.SetRequestURI(provider.URL)
			err := utils.DoRequestWithContext(providerio.WithBudget(t.Context(), lease), client, request, response)
			if err == nil && streaming {
				_, err = io.Copy(io.Discard, response.BodyStream())
			}
			if !errors.Is(err, tc.want) || !streaming && len(response.Body()) != 0 {
				t.Fatalf("response admission error=%v, want %v", err, tc.want)
			}
			if admission.peakReserved.Load() > tc.budget {
				t.Fatal("admission exceeded budget")
			}
		})
	}
}

func TestProviderResponseCancellationJoinsBlockedRead(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "first\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer provider.Close()
	admission := &requestMemoryAdmission{budget: minimumRequestWeightBytes}
	lease, _ := admission.acquire(0)
	defer lease.release()
	ctx, cancel := context.WithCancel(providerio.WithBudget(t.Context(), lease))
	defer cancel()
	client := &fasthttp.Client{Transport: providerio.NewTransport(1<<20, false), StreamResponseBody: true}
	defer client.CloseIdleConnections()
	request, response := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(request)
	defer fasthttp.ReleaseResponse(response)
	request.SetRequestURI(provider.URL)
	if err := utils.DoRequestWithContext(ctx, client, request, response); err != nil {
		t.Fatal(err)
	}
	first := make([]byte, 6)
	if _, err := io.ReadFull(response.BodyStream(), first); err != nil {
		t.Fatal(err)
	}
	finished := make(chan error, 1)
	go func() { _, err := io.ReadAll(response.BodyStream()); finished <- err }()
	cancel()
	select {
	case err := <-finished:
		if err == nil {
			t.Fatal("canceled body reported success")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation left the provider socket blocked")
	}
}

func TestProviderResponseRejectsTruncatedHTTPWithoutReplay(t *testing.T) {
	for _, chunked := range []bool{false, true} {
		t.Run(fmt.Sprint("chunked=", chunked), func(t *testing.T) {
			var calls atomic.Int32
			provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				defer conn.Close()
				body := `{"content":"valid JSON with incomplete framing"}`
				if chunked {
					_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n%x\r\n%s\r\n", len(body), body)
				} else {
					_, _ = fmt.Fprintf(conn, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body)+1, body)
				}
			}))
			defer provider.Close()
			admission := &requestMemoryAdmission{budget: minimumRequestWeightBytes}
			lease, _ := admission.acquire(0)
			defer lease.release()
			client := &fasthttp.Client{Transport: providerio.NewTransport(1<<20, false), ReadTimeout: time.Second}
			defer client.CloseIdleConnections()
			request, response := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
			defer fasthttp.ReleaseRequest(request)
			defer fasthttp.ReleaseResponse(response)
			request.SetRequestURI(provider.URL)
			request.Header.SetMethod(http.MethodPost)
			err := utils.DoRequestWithContext(providerio.WithBudget(t.Context(), lease), client, request, response)
			if !errors.Is(err, io.ErrUnexpectedEOF) || len(response.Body()) != 0 {
				t.Fatalf("truncated response admitted: %v", err)
			}
			if calls.Load() != 1 {
				t.Fatal("truncated inference was replayed")
			}
		})
	}
}

func TestUploadRetainsOnlyNecessaryCapacity(t *testing.T) {
	for _, sizeHint := range []int64{-1, 590_412} {
		admission := &requestMemoryAdmission{budget: 16 << 20}
		lease, _ := admission.acquire(0)
		input := strings.Repeat("x", 590_412)
		body, err := readAdmittedBody(strings.NewReader(input), 128<<20, lease, 0, sizeHint)
		if err != nil || string(body) != input || cap(body) != len(input) {
			t.Fatalf("hint=%d: body=%d/%d, error=%v", sizeHint, len(body), cap(body), err)
		}
		if got := admission.reserved.Load(); got != int64(len(input))*requestBodyReservationFactor {
			t.Fatalf("hint=%d: retained reservation=%d", sizeHint, got)
		}
		lease.release()
	}
}
