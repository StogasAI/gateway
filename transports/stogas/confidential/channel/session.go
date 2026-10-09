package channel

import (
	verifier "github.com/StogasAI/verifier/go"
	"sync"
	"time"
)

const (
	ReplayWindow       = 256
	SkippedKeyLifetime = time.Minute
)

// Replay and malformed first-record failures share the core's closed error code.
var ErrReplay = ErrRecord

// ServerSession owns the shared Rust session; Go owns only its store lifecycle.
type ServerSession struct {
	core *verifier.ChannelSession
	id   [32]byte
}

func (s *ServerSession) AcceptStart(number uint64, encoded []byte) (*ServerRequest, []byte, error) {
	incoming, outgoing, metadata, err := s.core.AcceptStart(number, encoded)
	if err != nil {
		return nil, nil, err
	}
	return &ServerRequest{incoming: incoming, outgoing: outgoing}, metadata, nil
}
func (s *ServerSession) expire(now time.Time) { s.core.Expire(now) }
func (s *ServerSession) Close()               { s.core.Close() }

// The separate Rust owners allow upload and response streaming concurrently.
// Store adds one release callback for the lifetime of the admitted exchange.
type ServerRequest struct {
	incoming *verifier.ChannelReader
	outgoing *verifier.ChannelWriter
	once     sync.Once
	release  func()
}

func (r *ServerRequest) Open(encoded []byte) (Kind, []byte, error) {
	kind, content, err := r.incoming.Open(encoded)
	return Kind(kind), content, err
}
func (r *ServerRequest) Complete() error { return r.incoming.Complete() }
func (r *ServerRequest) Seal(kind Kind, plaintext []byte) ([]byte, error) {
	return r.outgoing.Seal(byte(kind), plaintext)
}
func (r *ServerRequest) Close() {
	r.once.Do(func() {
		r.incoming.Close()
		r.outgoing.Close()
		if r.release != nil {
			r.release()
		}
	})
}
