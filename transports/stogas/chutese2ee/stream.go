package chutese2ee

import (
	"bufio"
	"bytes"
	"crypto/mlkem"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/maximhq/bifrost/transports/stogas/providerio"
)

type streamReader struct {
	source       *bufio.Reader
	closer       io.Closer
	responseKey  *mlkem.DecapsulationKey768
	pending      bytes.Buffer
	initialized  bool
	authDone     bool
	done         bool
	onError      func()
	errorOnce    sync.Once
	admit        func([]byte) error
	observeUsage func()
	usageSeen    bool

	// Core closes the stream from its own goroutine while a read waits on the network. mu keeps
	// that close from retiring the key while a line is decrypted, and a read that the close
	// interrupts is not a protocol failure.
	mu        sync.Mutex
	streamKey []byte
	closed    bool
}

func newStreamReader(source io.Reader, responseKey *mlkem.DecapsulationKey768, onError func()) *streamReader {
	reader := &streamReader{source: bufio.NewReaderSize(source, 64*1024), responseKey: responseKey, onError: onError}
	if closer, ok := source.(io.Closer); ok {
		reader.closer = closer
	}
	return reader
}

func (r *streamReader) Read(target []byte) (int, error) {
	if len(target) == 0 {
		return 0, nil
	}
	if r.isClosed() {
		return 0, io.ErrClosedPipe
	}
	for r.pending.Len() == 0 {
		if r.done {
			_ = r.Close()
			return 0, io.EOF
		}
		line, err := r.readLine()
		if err == nil {
			err = r.process(line)
		} else if errors.Is(err, io.EOF) {
			err = fmt.Errorf("%w: encrypted stream ended before authenticated [DONE]", ErrInvalidE2EEResponse)
		}
		if err != nil {
			if r.isClosed() {
				return 0, io.ErrClosedPipe
			}
			return 0, r.fail(err)
		}
	}
	return r.pending.Read(target)
}

// process handles one line while Close waits, so the stream key outlives each use.
func (r *streamReader) process(line []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return io.ErrClosedPipe
	}
	return r.processLine(line)
}

func (r *streamReader) isClosed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closed
}

func (r *streamReader) fail(err error) error {
	r.errorOnce.Do(func() {
		if r.onError != nil && !errors.Is(err, providerio.ErrCapacity) {
			r.onError()
		}
	})
	_ = r.Close()
	return err
}

func (r *streamReader) Close() error {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	r.closed = true
	clear(r.streamKey)
	r.mu.Unlock()
	// Closing the connection ends a read that waits on it.
	if r.closer != nil {
		return r.closer.Close()
	}
	return nil
}

func (r *streamReader) readLine() ([]byte, error) {
	line := make([]byte, 0, 64*1024)
	for {
		fragment, err := r.source.ReadSlice('\n')
		if len(line)+len(fragment) > maxEncryptedSSELine {
			return nil, fmt.Errorf("%w: encrypted stream event is too large", ErrInvalidE2EEResponse)
		}
		line = append(line, fragment...)
		switch {
		case err == nil:
			return bytes.TrimRight(line, "\r\n"), nil
		case errors.Is(err, bufio.ErrBufferFull):
			continue
		case errors.Is(err, io.EOF) && len(line) == 0:
			return nil, io.EOF
		case errors.Is(err, io.EOF):
			return bytes.TrimRight(line, "\r\n"), nil
		default:
			return nil, err
		}
	}
}

func (r *streamReader) processLine(line []byte) error {
	if len(line) == 0 {
		return nil
	}
	if !bytes.HasPrefix(line, []byte("data:")) {
		return fmt.Errorf("%w: unexpected encrypted stream field", ErrInvalidE2EEResponse)
	}
	raw := strings.TrimSpace(string(line[len("data:"):]))
	if raw == "[DONE]" {
		if !r.initialized {
			return fmt.Errorf("%w: stream ended before initialization", ErrInvalidE2EEResponse)
		}
		if !r.authDone {
			return fmt.Errorf("%w: outer completion preceded authenticated completion", ErrInvalidE2EEResponse)
		}
		r.pending.WriteString("data: [DONE]\n\n")
		r.done = true
		return nil
	}
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal([]byte(raw), &envelope); err != nil || len(envelope) != 1 {
		return fmt.Errorf("%w: invalid encrypted stream envelope", ErrInvalidE2EEResponse)
	}
	if encoded, ok := envelope["e2e_init"]; ok {
		var initialization string
		if json.Unmarshal(encoded, &initialization) != nil || initialization == "" {
			return fmt.Errorf("%w: invalid stream initialization", ErrInvalidE2EEResponse)
		}
		if r.initialized {
			return fmt.Errorf("%w: duplicate stream initialization", ErrInvalidE2EEResponse)
		}
		key, err := deriveStreamKey(r.responseKey, initialization)
		if err != nil {
			return err
		}
		r.streamKey = key
		r.initialized = true
		return nil
	}
	if encoded, ok := envelope["e2e"]; ok {
		var encryptedEvent string
		if json.Unmarshal(encoded, &encryptedEvent) != nil || encryptedEvent == "" {
			return fmt.Errorf("%w: invalid encrypted stream event", ErrInvalidE2EEResponse)
		}
		if !r.initialized {
			return fmt.Errorf("%w: encrypted data preceded stream initialization", ErrInvalidE2EEResponse)
		}
		plaintext, err := decryptStreamEvent(r.streamKey, encryptedEvent)
		if err != nil {
			return err
		}
		defer clear(plaintext)
		if r.admit != nil {
			if err := r.admit(plaintext); err != nil {
				return err
			}
		}
		if isDecryptedCompletionMarker(plaintext) {
			if r.authDone {
				return fmt.Errorf("%w: duplicate authenticated completion", ErrInvalidE2EEResponse)
			}
			r.authDone = true
			r.pending.WriteString("data: [DONE]\n\n")
			r.done = true
			return nil
		}
		normalized, object, err := normalizeDecryptedSSEEvent(plaintext)
		if err != nil {
			return fmt.Errorf("%w: invalid decrypted stream event: %v", ErrInvalidE2EEResponse, err)
		}
		if len(normalized) == 0 {
			return nil
		}
		if !r.usageSeen && r.observeUsage != nil && reportsUsageWithOutput(object) {
			r.usageSeen = true
			r.observeUsage()
		}
		r.pending.Write(normalized)
		r.pending.WriteString("\n\n")
		return nil
	}
	if _, ok := envelope["usage"]; ok {
		return fmt.Errorf("%w: plaintext usage passthrough is forbidden", ErrInvalidE2EEResponse)
	}
	if _, ok := envelope["e2e_error"]; ok {
		return fmt.Errorf("%w: plaintext stream errors are forbidden", ErrInvalidE2EEResponse)
	}
	return fmt.Errorf("%w: unknown encrypted stream envelope", ErrInvalidE2EEResponse)
}

func isDecryptedCompletionMarker(event []byte) bool {
	event = bytes.TrimSpace(event)
	if !bytes.HasPrefix(event, []byte("data:")) {
		return false
	}
	return bytes.Equal(bytes.TrimSpace(event[len("data:"):]), []byte("[DONE]"))
}

// normalizeDecryptedSSEEvent returns the event and its payload's fields.
func normalizeDecryptedSSEEvent(event []byte) ([]byte, map[string]json.RawMessage, error) {
	if len(event) == 0 || len(event) > maxEncryptedSSELine {
		return nil, nil, errors.New("event size is invalid")
	}
	event = bytes.TrimRight(event, "\r\n")
	if len(event) == 0 {
		return nil, nil, nil
	}
	if !bytes.HasPrefix(event, []byte("data:")) {
		if bytes.Equal(bytes.TrimSpace(event), []byte("[DONE]")) {
			return nil, nil, errors.New("encrypted completion marker")
		}
		if json.Valid(bytes.TrimSpace(event)) {
			return nil, nil, errors.New("unframed JSON event")
		}
		return nil, nil, fmt.Errorf("missing data field (length=%d first_byte=0x%02x)", len(event), event[0])
	}
	if bytes.ContainsAny(event, "\r\n") {
		return nil, nil, errors.New("event contains an internal line break")
	}
	payload := bytes.TrimSpace(event[len("data:"):])
	if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
		return nil, nil, errors.New("event payload is empty or a completion marker")
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(payload, &object) != nil || object == nil {
		return nil, nil, errors.New("event payload is not a JSON object")
	}
	return event, object, nil
}

// reportsUsageWithOutput reports a chunk that carries output and the usage so far.
func reportsUsageWithOutput(object map[string]json.RawMessage) bool {
	var choices []json.RawMessage
	var usage struct {
		Prompt     *int64 `json:"prompt_tokens"`
		Completion *int64 `json:"completion_tokens"`
	}
	return json.Unmarshal(object["choices"], &choices) == nil && len(choices) > 0 &&
		json.Unmarshal(object["usage"], &usage) == nil && usage.Prompt != nil && usage.Completion != nil
}
