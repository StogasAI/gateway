package stogashttp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"time"
)

// Both management roles pass mTLS, but only the separate actuator key may drain.
// Targeting the complete enrolled node ID prevents a reused address from receiving
// an operation intended for its previous guest.
func (s *Server) drain(ctx *requestContext) {
	pin, err := hex.DecodeString(s.config.DrainClientSPKISHA256)
	if err != nil || len(pin) != sha256.Size || ctx.request.TLS == nil ||
		verifyDiagnosticsClient(*ctx.request.TLS, [sha256.Size]byte(pin), time.Now()) != nil {
		s.writeJSON(ctx, http.StatusForbidden, map[string]string{"error": "forbidden"})
		return
	}
	var command struct {
		NodeID string `json:"node_id"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(ctx.writer, ctx.request.Body, 1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&command); err != nil {
		s.writeJSON(ctx, http.StatusBadRequest, map[string]string{"error": "invalid_command"})
		return
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF || ctx.request.URL.RawQuery != "" {
		s.writeJSON(ctx, http.StatusBadRequest, map[string]string{"error": "invalid_command"})
		return
	}
	if s.secure == nil || s.sessionNodeID == "" || command.NodeID != s.sessionNodeID {
		s.writeJSON(ctx, http.StatusConflict, map[string]string{"error": "node_mismatch"})
		return
	}
	// Close admission before acknowledging. Duplicate commands are harmless.
	s.requests.start()
	s.secure.Drain()
	s.writeJSON(ctx, http.StatusAccepted, map[string]string{"node_id": s.sessionNodeID, "status": "draining"})
}

// Operator drain leaves private diagnostics and readiness alive until the host
// stops this instance. Admitted provider work still owns its normal deadline.
func (s *Server) drainPublic() {
	s.requests.start()
	ctx, cancel := context.WithTimeout(context.Background(), guestShutdownHardCap)
	defer cancel()
	if err := s.server.Shutdown(ctx); err != nil {
		_ = s.server.Close()
		if s.logger != nil {
			s.logger.Warn("public drain deadline reached")
		}
	}
}
