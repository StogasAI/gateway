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
)

type streamReader struct {
	source      *bufio.Reader
	closer      io.Closer
	responseKey *mlkem.DecapsulationKey768
	streamKey   []byte
	pending     bytes.Buffer
	initialized bool
	done        bool
	closed      bool
	onError     func()
	errorOnce   sync.Once
}

func newStreamReader(source io.Reader, responseKey *mlkem.DecapsulationKey768, onError func()) io.ReadCloser {
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
	if r.closed {
		return 0, io.ErrClosedPipe
	}
	for r.pending.Len() == 0 {
		if r.done {
			_ = r.Close()
			return 0, io.EOF
		}
		line, err := r.readLine()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return 0, r.fail(fmt.Errorf("%w: encrypted stream ended before [DONE]", ErrInvalidE2EEResponse))
			}
			return 0, r.fail(err)
		}
		if err := r.processLine(line); err != nil {
			return 0, r.fail(err)
		}
	}
	return r.pending.Read(target)
}

func (r *streamReader) fail(err error) error {
	r.errorOnce.Do(func() {
		if r.onError != nil {
			r.onError()
		}
	})
	_ = r.Close()
	return err
}

func (r *streamReader) Close() error {
	if r.closed {
		return nil
	}
	r.closed = true
	clear(r.streamKey)
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
		if isDecryptedCompletionMarker(plaintext) {
			r.pending.WriteString("data: [DONE]\n\n")
			r.done = true
			return nil
		}
		normalized, err := normalizeDecryptedSSEEvent(plaintext)
		if err != nil {
			return fmt.Errorf("%w: invalid decrypted stream event: %v", ErrInvalidE2EEResponse, err)
		}
		if len(normalized) == 0 {
			return nil
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

func validDecryptedSSEEvent(event []byte) bool {
	normalized, err := normalizeDecryptedSSEEvent(event)
	return err == nil && len(normalized) > 0
}

func normalizeDecryptedSSEEvent(event []byte) ([]byte, error) {
	if len(event) == 0 || len(event) > maxEncryptedSSELine {
		return nil, errors.New("event size is invalid")
	}
	event = bytes.TrimRight(event, "\r\n")
	if len(event) == 0 {
		return nil, nil
	}
	if !bytes.HasPrefix(event, []byte("data:")) {
		if bytes.Equal(bytes.TrimSpace(event), []byte("[DONE]")) {
			return nil, errors.New("encrypted completion marker")
		}
		if json.Valid(bytes.TrimSpace(event)) {
			return nil, errors.New("unframed JSON event")
		}
		return nil, fmt.Errorf("missing data field (length=%d first_byte=0x%02x)", len(event), event[0])
	}
	if bytes.ContainsAny(event, "\r\n") {
		return nil, errors.New("event contains an internal line break")
	}
	payload := bytes.TrimSpace(event[len("data:"):])
	if len(payload) == 0 || bytes.Equal(payload, []byte("[DONE]")) {
		return nil, errors.New("event payload is empty or a completion marker")
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(payload, &object) != nil || object == nil {
		return nil, errors.New("event payload is not a JSON object")
	}
	return event, nil
}
