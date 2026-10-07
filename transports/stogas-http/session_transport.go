package stogashttp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/confidential/channel"
)

const sessionPath = "/v1/session"
const sessionContentType = "application/vnd.stogas.session"
const sessionNodeHeader = "Stogas-Node-ID"
const sessionSetupBudget = 15 * time.Second

// Part of the existing request reservation, retained through the final encrypted write.
const sessionAdapterRetainedBytes = 2*channel.MaxRecordBytes + (2*int(requestBodyReservationFactor)+1)*serverReadBufferSize

type sessionRequestMetadata struct {
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
}

type sessionResponseMetadata struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Closing bool              `json:"closing,omitempty"`
}

// The ordinary request pipeline owns authorization, buffering and provider work.
// This adapter only authenticates the first record, then replaces the body and
// response writer. Its reservation is the same lease passed to that pipeline.
func (s *Server) sessionTransport(next requestHandler) requestHandler {
	return func(ctx *requestContext) {
		if ctx.request.URL.Path != sessionPath {
			next(ctx)
			return
		}
		if ctx.request.Method != http.MethodPost || ctx.request.URL.RawQuery != "" ||
			len(ctx.request.Header.Values("Content-Type")) != 1 || !isContentType(ctx.request.Header.Get("Content-Type"), sessionContentType) ||
			len(ctx.request.Header.Values("Content-Encoding")) != 0 {
			closeUnreadRequest(ctx)
			ctx.writer.WriteHeader(http.StatusBadRequest)
			return
		}
		if s.sessions == nil {
			closeUnreadRequest(ctx)
			ctx.writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		outerBody := ctx.request.Body
		// net/http owns closing the outer body after this handler returns.
		setupDeadline := time.Now().Add(sessionSetupBudget)
		readDeadline := time.Now().Add(serverReadTimeout)
		control := http.NewResponseController(ctx.writer)
		if err := control.SetReadDeadline(setupDeadline); err != nil {
			ctx.writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		lease, ok := s.memory.acquire(0)
		if !ok {
			closeUnreadRequest(ctx)
			s.writeRequestMemoryCapacity(ctx)
			return
		}
		ctx.memory = lease
		releaseTransport, retained := lease.retain(sessionAdapterRetainedBytes)
		if !retained {
			lease.release()
			ctx.writer.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		defer releaseTransport()
		defer func() {
			if !lease.transferred {
				clear(ctx.body)
				ctx.body = nil
				lease.release()
			}
		}()
		var prefix [6]byte
		if _, err := io.ReadFull(outerBody, prefix[:]); err != nil {
			ctx.writer.WriteHeader(http.StatusBadRequest)
			return
		}
		input := io.MultiReader(bytes.NewReader(prefix[:]), outerBody)
		if string(prefix[:]) == channel.ClientSetupHeader {
			if !s.admitIP(ctx, true) {
				return
			}
			s.openSession(ctx, input, setupDeadline)
			return
		}
		if err := control.SetReadDeadline(readDeadline); err != nil {
			ctx.writer.WriteHeader(http.StatusInternalServerError)
			return
		}
		owners := ctx.request.Header.Values(sessionNodeHeader)
		if len(owners) != 1 || owners[0] != s.sessionNodeID {
			closeUnreadRequest(ctx)
			ctx.writer.WriteHeader(http.StatusMisdirectedRequest)
			return
		}
		// Bound read-ahead while amortizing HTTP/2 body bookkeeping across small
		// records. Only ciphertext is buffered; authentication still precedes use.
		incoming, encoded, err := channel.Accept(s.sessions, bufio.NewReaderSize(input, serverReadBufferSize))
		if err != nil {
			closeUnreadRequest(ctx)
			if errors.Is(err, channel.ErrSessionCapacity) {
				ctx.writer.Header().Set("Retry-After", "1")
				ctx.writer.WriteHeader(http.StatusServiceUnavailable)
				return
			}
			ctx.writer.WriteHeader(http.StatusBadRequest)
			return
		}
		defer incoming.Close()
		writer := newSessionResponse(ctx.writer, incoming, ctx.request.ProtoMajor < 2)
		ctx.writer = writer
		if err := writer.acknowledge(); err != nil {
			panic(http.ErrAbortHandler)
		}
		metadata, err := parseSessionMetadata(encoded)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
		} else if metadata.Method == http.MethodDelete && metadata.Path == sessionPath {
			var extra [1]byte
			if n, err := incoming.Read(extra[:]); n != 0 || !errors.Is(err, io.EOF) {
				writer.WriteHeader(http.StatusBadRequest)
			} else {
				s.sessions.Remove(incoming.ID)
				writer.WriteHeader(http.StatusNoContent)
			}
		} else if !s.admissionReady() {
			s.requireAdmission(ctx)
		} else {
			inner := ctx.request.Clone(ctx.request.Context())
			inner.Method, inner.URL, inner.RequestURI = metadata.Method, &url.URL{Path: metadata.Path}, metadata.Path
			inner.Header = make(http.Header, len(metadata.Headers))
			for name, value := range metadata.Headers {
				inner.Header.Set(name, value)
			}
			inner.Body, inner.ContentLength, inner.TransferEncoding = io.NopCloser(incoming), -1, nil
			ctx.encrypted = true
			ctx.request = inner
			next(ctx)
		}
		if ctx.request.ProtoMajor < 2 && !incoming.Consumed() {
			s.idleConnections.retireAfterReply(ctx.request.Context())
		}
		if err := writer.finish(); err != nil {
			panic(http.ErrAbortHandler)
		}
	}
}

func (s *Server) openSession(ctx *requestContext, input io.Reader, deadline time.Time) {
	if len(ctx.request.Header.Values(sessionNodeHeader)) != 0 {
		closeUnreadRequest(ctx)
		ctx.writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	if !s.requireAdmission(ctx) {
		return
	}
	setupContext, cancel := context.WithDeadline(ctx.request.Context(), deadline)
	defer cancel()
	control := http.NewResponseController(ctx.writer)
	if err := control.SetReadDeadline(deadline); err != nil {
		ctx.writer.WriteHeader(http.StatusInternalServerError)
		return
	}
	defer control.SetReadDeadline(time.Time{})
	var hello [channel.ClientSetupBytes + 1]byte
	n, err := io.ReadFull(input, hello[:])
	if n != channel.ClientSetupBytes || !errors.Is(err, io.ErrUnexpectedEOF) {
		closeUnreadRequest(ctx)
		ctx.writer.WriteHeader(http.StatusBadRequest)
		return
	}
	id, response, err := s.sessions.Open(setupContext, hello[:n])
	if err != nil {
		ctx.writer.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	ctx.writer.Header().Set("Content-Type", sessionContentType)
	ctx.writer.Header().Set("Cache-Control", "no-store")
	ctx.deliveryDeadline = deadline
	if _, err := boundedResponse(ctx).Write(response); err != nil {
		s.sessions.Remove(id)
	}
}

func parseSessionMetadata(encoded []byte) (sessionRequestMetadata, error) {
	var metadata sessionRequestMetadata
	if len(encoded) > serverReadBufferSize {
		return metadata, channel.ErrRecord
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return metadata, channel.ErrRecord
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return metadata, channel.ErrRecord
	}
	if !(metadata.Method == http.MethodPost && isGatewayRequestPath(metadata.Path)) && !(metadata.Method == http.MethodDelete && metadata.Path == sessionPath) {
		return metadata, channel.ErrRecord
	}
	seen := make(map[string]bool, len(metadata.Headers))
	for name, value := range metadata.Headers {
		name = strings.ToLower(name)
		if seen[name] || !validHTTPFieldName(name) || !validSessionHeaderValue(value) {
			return metadata, channel.ErrRecord
		}
		seen[name] = true
		switch name {
		case "host", "connection", "content-length", "transfer-encoding", "te", "trailer", "upgrade", "expect", "stogas-node-id", "forwarded", "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto":
			return metadata, channel.ErrRecord
		}
	}
	return metadata, nil
}

func validSessionHeaderValue(value string) bool {
	for _, character := range []byte(value) {
		if character == 127 || (character < 32 && character != '\t') {
			return false
		}
	}
	return true
}

type sessionResponse struct {
	outer   http.ResponseWriter
	stream  *channel.Outgoing
	header  http.Header
	status  int
	started bool
	closing bool
	err     error
	input   *channel.Incoming
	http1   bool
}

func newSessionResponse(outer http.ResponseWriter, input *channel.Incoming, http1 bool) *sessionResponse {
	return &sessionResponse{outer: outer, stream: channel.NewOutgoing(input.State, outer), header: make(http.Header), input: input, http1: http1}
}
func (w *sessionResponse) Header() http.Header         { return w.header }
func (w *sessionResponse) Unwrap() http.ResponseWriter { return w.outer }
func (w *sessionResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}

// A receipt authenticates the request start without committing its inner HTTP
// status. HTTP/1 must allow the client to finish uploading after this flush.
func (w *sessionResponse) acknowledge() error {
	if w.http1 {
		if err := http.NewResponseController(w.outer).EnableFullDuplex(); err != nil {
			return err
		}
	}
	w.outer.Header().Set("Content-Type", sessionContentType)
	w.outer.Header().Set("Cache-Control", "no-store")
	return w.flushRecord(w.stream.Keepalive)
}

func (w *sessionResponse) start() error {
	if w.err != nil || w.started {
		return w.err
	}
	w.started = true
	if w.status == 0 {
		w.status = http.StatusOK
	}
	headers := make(map[string]string)
	for _, name := range []string{"Content-Type", "Cache-Control", "Retry-After"} {
		if value := w.header.Get(name); value != "" {
			headers[name] = value
		}
	}
	encoded, err := json.Marshal(sessionResponseMetadata{Status: w.status, Headers: headers, Closing: w.closing})
	if err != nil || len(encoded) > serverReadBufferSize {
		w.err = channel.ErrRecord
		return w.err
	}
	w.err = w.stream.Metadata(encoded)
	return w.err
}
func (w *sessionResponse) Write(data []byte) (int, error) {
	if err := w.start(); err != nil {
		return 0, err
	}
	return w.stream.Write(data)
}
func (w *sessionResponse) FlushError() error {
	if err := w.start(); err != nil {
		return err
	}
	w.err = http.NewResponseController(w.outer).Flush()
	return w.err
}
func (w *sessionResponse) finish() error {
	if w.http1 && !w.input.Consumed() {
		// Full-duplex HTTP/1 otherwise drains the unfinished body after this
		// handler returns. Stop abandoned uploads without delaying the error
		// response. The connection owner retires this socket after net/http
		// flushes the response; an expired read can cancel its shared context.
		if err := http.NewResponseController(w.outer).SetReadDeadline(time.Now()); err != nil {
			return err
		}
	}
	return w.flushRecord(func() error {
		if err := w.start(); err != nil {
			return err
		}
		return w.stream.Finish()
	})
}

func (w *sessionResponse) flushRecord(write func() error) error {
	if w.err != nil {
		return w.err
	}
	control := http.NewResponseController(w.outer)
	if w.err = control.SetWriteDeadline(time.Now().Add(downstreamWriteIdleTimeout)); w.err != nil {
		return w.err
	}
	w.err = write()
	if w.err == nil {
		w.err = control.Flush()
	}
	if w.err == nil {
		w.err = control.SetWriteDeadline(time.Time{})
	}
	return w.err
}
