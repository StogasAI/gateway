package stogashttp

import (
	"context"
	"io"
	"net/http"
	"time"
)

// Only the HTTP handler writes a response. Each pending bounded write and flush
// has a deadline on its response stream; quiet provider time has none.
type responseWriter struct {
	writer   http.ResponseWriter
	control  *http.ResponseController
	deadline time.Time
	idle     time.Duration
}

func (w *responseWriter) Write(data []byte) (int, error) {
	written := 0
	for len(data) > 0 {
		deadline := time.Now().Add(w.idle)
		if !w.deadline.IsZero() && w.deadline.Before(deadline) {
			deadline = w.deadline
		}
		if err := w.control.SetWriteDeadline(deadline); err != nil {
			return written, err
		}
		n, err := w.writer.Write(data[:min(len(data), 64<<10)])
		written += n
		data = data[n:]
		if err == nil && n == 0 {
			err = io.ErrShortWrite
		}
		if err == nil {
			err = w.control.Flush()
		}
		if err != nil {
			return written, err
		}
		if err := w.control.SetWriteDeadline(time.Time{}); err != nil {
			return written, err
		}
	}
	return written, nil
}

func boundedResponse(ctx *requestContext) *responseWriter {
	return &responseWriter{writer: ctx.writer, control: http.NewResponseController(ctx.writer), deadline: ctx.deliveryDeadline, idle: downstreamWriteIdleTimeout}
}

func (s *Server) writeResponse(ctx *requestContext, status int, contentType string, data []byte) {
	ctx.writer.Header().Set("Content-Type", contentType)
	ctx.writer.WriteHeader(status)
	_, _ = boundedResponse(ctx).Write(data)
}

func (s *Server) writeStream(ctx *requestContext, source io.ReadCloser) {
	stop := context.AfterFunc(ctx.request.Context(), func() { _ = source.Close() })
	defer stop()
	defer source.Close()
	_, _ = io.Copy(boundedResponse(ctx), source)
}
