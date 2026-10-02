package channel

import (
	"errors"
	"io"
)

// Incoming owns one request's record states and one bounded receive buffer.
// The HTTP adapter reserves its memory before Accept and calls Close only after
// both the body reader and response producer have finished.
type Incoming struct {
	State    *ServerRequest
	ID       [32]byte
	input    io.Reader
	buffer   [MaxRecordBytes]byte
	used     int
	content  []byte
	terminal error
}

// Accept reads and authenticates only the dispatch prefix and first credential
// record. Metadata borrows the receive buffer until the first Read or Close.
// A rejected start never creates a response cipher, including duplicate starts.
func Accept(store *Store, input io.Reader) (*Incoming, []byte, error) {
	var prefix [RequestPrefixBytes]byte
	if _, err := io.ReadFull(input, prefix[:]); err != nil {
		return nil, nil, err
	}
	id, number, err := ParseRequestPrefix(prefix[:])
	if err != nil {
		return nil, nil, err
	}
	r := &Incoming{ID: id, input: input}
	encoded, err := r.record()
	if err != nil {
		return nil, nil, err
	}
	state, metadata, err := store.AcceptStart(id, number, encoded)
	if err != nil {
		clear(r.buffer[:])
		return nil, nil, err
	}
	r.State = state
	return r, metadata, nil
}

// Read returns only authenticated body bytes. EOF is successful only after an
// authenticated Finished record AND outer EOF. The application must read through
// EOF before dispatching provider work; early authorization rejection may stop.
func (r *Incoming) Read(output []byte) (int, error) {
	if len(output) == 0 {
		return 0, nil
	}
	if r.terminal != nil {
		return 0, r.terminal
	}
	if len(r.content) == 0 {
		clear(r.buffer[:r.used])
		encoded, err := r.record()
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			err = ErrTruncated
		}
		if err != nil {
			return 0, r.fail(err)
		}
		kind, content, err := r.State.Open(encoded)
		if err != nil {
			return 0, r.fail(err)
		}
		if kind == Finished {
			if err := r.State.Complete(); err != nil {
				return 0, r.fail(err)
			}
			var extra [1]byte
			count, err := io.ReadFull(r.input, extra[:])
			if count != 0 {
				return 0, r.fail(ErrRecord)
			}
			if !errors.Is(err, io.EOF) {
				return 0, r.fail(err)
			}
			return 0, r.fail(io.EOF)
		}
		if kind != Data {
			return 0, r.fail(ErrRecord)
		}
		r.content = content
	}
	n := copy(output, r.content)
	clear(r.content[:n])
	r.content = r.content[n:]
	return n, nil
}

func (r *Incoming) record() ([]byte, error) {
	if _, err := io.ReadFull(r.input, r.buffer[:4]); err != nil {
		return nil, err
	}
	size, err := RecordSize(r.buffer[:4])
	if err != nil {
		return nil, err
	}
	r.used = size
	if _, err := io.ReadFull(r.input, r.buffer[4:size]); err != nil {
		return nil, err
	}
	return r.buffer[:size], nil
}

func (r *Incoming) fail(err error) error {
	r.terminal = err
	clear(r.buffer[:])
	r.content = nil
	return err
}

func (r *Incoming) Close() {
	r.fail(ErrClosed)
	r.State.Close()
}

// Consumed reports authenticated completion followed by outer EOF.
func (r *Incoming) Consumed() bool { return errors.Is(r.terminal, io.EOF) }

// Outgoing has one response owner. It writes bounded binary records directly to
// the outer response; no base64, entire-response buffer or response replay cache.
type Outgoing struct {
	state  *ServerRequest
	output io.Writer
	err    error
}

func NewOutgoing(state *ServerRequest, output io.Writer) *Outgoing {
	return &Outgoing{state: state, output: output}
}

func (w *Outgoing) Metadata(encoded []byte) error { return w.record(Metadata, encoded) }
func (w *Outgoing) Keepalive() error              { return w.record(Keepalive, nil) }
func (w *Outgoing) Finish() error                 { return w.record(Finished, nil) }

func (w *Outgoing) Write(data []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	written := 0
	for len(data) != 0 {
		size := min(len(data), MaxRecordPlaintext)
		if err := w.record(Data, data[:size]); err != nil {
			return written, err
		}
		written += size
		data = data[size:]
	}
	return written, nil
}

func (w *Outgoing) record(kind Kind, plaintext []byte) error {
	if w.err != nil {
		return w.err
	}
	encoded, err := w.state.Seal(kind, plaintext)
	if err == nil {
		var n int
		n, err = w.output.Write(encoded)
		if err == nil && n != len(encoded) {
			err = io.ErrShortWrite
		}
	}
	clear(encoded)
	w.err = err
	return err
}
