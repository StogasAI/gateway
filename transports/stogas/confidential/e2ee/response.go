package e2ee

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
)

type ResponseReader struct {
	source       io.Reader
	session      *Session
	metadata     ResponseMetadata
	pending      bytes.Buffer
	sequence     uint64
	started      bool
	sourceDone   bool
	finalSent    bool
	sourceClosed bool
	emptyReads   int
	bodyBytes    int
	baseNonce    [responseNonceSize]byte
}

func (s *Session) EncodeResponse(metadata ResponseMetadata, body []byte) ([]byte, error) {
	reader, err := s.NewResponseReader(bytes.NewReader(body), metadata)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(reader)
}

func (s *Session) NewResponseReader(source io.Reader, metadata ResponseMetadata) (*ResponseReader, error) {
	var responseNonce [responseNonceSize]byte
	if _, err := io.ReadFull(rand.Reader, responseNonce[:]); err != nil {
		return nil, errors.New("generate E2EE response nonce")
	}
	return s.newResponseReaderWithNonce(source, metadata, responseNonce)
}

func (s *Session) newResponseReaderWithNonce(source io.Reader, metadata ResponseMetadata, responseNonce [responseNonceSize]byte) (*ResponseReader, error) {
	if s == nil || s.responseAEAD == nil {
		return nil, errors.New("E2EE response session is unavailable")
	}
	if source == nil {
		source = bytes.NewReader(nil)
	}
	if err := validateResponseMetadata(metadata); err != nil {
		return nil, err
	}
	if !s.responseStarted.CompareAndSwap(false, true) {
		return nil, errors.New("E2EE response session is single-use")
	}
	return &ResponseReader{
		source:    source,
		session:   s,
		metadata:  metadata,
		baseNonce: responseNonce,
	}, nil
}

func (r *ResponseReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for r.pending.Len() == 0 {
		if !r.started {
			r.started = true
			r.pending.Write(responseMagic)
			r.pending.Write(r.baseNonce[:])
			metadata, err := json.Marshal(r.metadata)
			if err != nil {
				return 0, err
			}
			if len(metadata) > maxResponseMetadata {
				return 0, errors.New("E2EE response metadata is too large")
			}
			if err := r.appendRecord(metadata); err != nil {
				return 0, err
			}
			continue
		}
		if !r.sourceDone {
			chunk := make([]byte, maxResponseRecordSize)
			n, err := r.source.Read(chunk)
			if n > 0 {
				r.emptyReads = 0
				if n > MaxResponseBodySize-r.bodyBytes {
					return 0, errors.New("E2EE response body is too large")
				}
				r.bodyBytes += n
				if recordErr := r.appendRecord(chunk[:n]); recordErr != nil {
					return 0, recordErr
				}
			} else if err == nil {
				r.emptyReads++
				if r.emptyReads >= 100 {
					return 0, io.ErrNoProgress
				}
			}
			if errors.Is(err, io.EOF) {
				r.sourceDone = true
			} else if err != nil {
				return 0, err
			}
			if n > 0 {
				continue
			}
			if !r.sourceDone {
				continue
			}
		}
		if !r.finalSent {
			r.finalSent = true
			if err := r.appendRecord(nil); err != nil {
				return 0, err
			}
			continue
		}
		return 0, io.EOF
	}
	return r.pending.Read(p)
}

func (r *ResponseReader) Close() error {
	if r.sourceClosed {
		return nil
	}
	r.sourceClosed = true
	if closer, ok := r.source.(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func (r *ResponseReader) appendRecord(plaintext []byte) error {
	if r.sequence == math.MaxUint64 {
		return errors.New("E2EE response sequence exhausted")
	}
	if len(plaintext) > maxResponseRecordSize {
		return errors.New("E2EE response record is too large")
	}
	aad := r.session.responseAAD(r.sequence)
	nonce := responseNonceFor(r.baseNonce, r.sequence)
	ciphertext := r.session.responseAEAD.Seal(nil, nonce[:], plaintext, aad)
	if len(ciphertext) > int(^uint32(0)) {
		return errors.New("E2EE response record is too large")
	}
	_ = binary.Write(&r.pending, binary.BigEndian, uint32(len(ciphertext)))
	r.pending.Write(ciphertext)
	r.sequence++
	return nil
}

func (s *Session) DecodeResponse(data []byte) (*DecodedResponse, error) {
	if s == nil || s.responseAEAD == nil {
		return nil, errors.New("E2EE response session is unavailable")
	}
	preambleSize := len(responseMagic) + responseNonceSize
	if len(data) < preambleSize || !bytes.Equal(data[:len(responseMagic)], responseMagic) {
		return nil, errors.New("invalid E2EE response magic")
	}
	var baseNonce [responseNonceSize]byte
	copy(baseNonce[:], data[len(responseMagic):preambleSize])
	reader := bytes.NewReader(data[preambleSize:])
	var result DecodedResponse
	sequence := uint64(0)
	metadataSeen := false
	for reader.Len() > 0 {
		consumed := len(data) - reader.Len()
		if consumed > MaxResponseWireSize-4 {
			return nil, errors.New("E2EE response is too large")
		}
		var ciphertextLength uint32
		if err := binary.Read(reader, binary.BigEndian, &ciphertextLength); err != nil {
			return nil, errors.New("truncated E2EE response record")
		}
		remainingWireBytes := MaxResponseWireSize - (len(data) - reader.Len())
		if uint64(ciphertextLength) > uint64(remainingWireBytes) {
			return nil, errors.New("E2EE response is too large")
		}
		if int64(ciphertextLength) > int64(reader.Len()) || ciphertextLength < uint32(s.responseAEAD.Overhead()) {
			return nil, errors.New("invalid E2EE response record length")
		}
		maxCiphertextLength := maxResponseRecordSize + s.responseAEAD.Overhead()
		if sequence == 0 {
			maxCiphertextLength = maxResponseMetadata + s.responseAEAD.Overhead()
		}
		if ciphertextLength > uint32(maxCiphertextLength) {
			return nil, errors.New("E2EE response record is too large")
		}
		ciphertext := make([]byte, ciphertextLength)
		if _, err := io.ReadFull(reader, ciphertext); err != nil {
			return nil, errors.New("truncated E2EE response record")
		}
		nonce := responseNonceFor(baseNonce, sequence)
		plaintext, err := s.responseAEAD.Open(nil, nonce[:], ciphertext, s.responseAAD(sequence))
		if err != nil {
			return nil, errors.New("E2EE response record authentication failed")
		}
		if sequence == 0 {
			if len(plaintext) > maxResponseMetadata {
				return nil, errors.New("E2EE response metadata is too large")
			}
			metadata, err := decodeResponseMetadata(plaintext)
			if err != nil {
				return nil, err
			}
			result.Metadata = metadata
			metadataSeen = true
		} else if len(plaintext) > 0 {
			if !metadataSeen {
				return nil, errors.New("invalid E2EE response body position")
			}
			if len(plaintext) > MaxResponseBodySize-len(result.Body) {
				return nil, errors.New("E2EE response body is too large")
			}
			result.Body = append(result.Body, plaintext...)
		} else {
			if !metadataSeen {
				return nil, errors.New("invalid E2EE response final record")
			}
			return &result, nil
		}
		sequence++
	}
	return nil, errors.New("truncated E2EE response")
}

func decodeResponseMetadata(data []byte) (ResponseMetadata, error) {
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return ResponseMetadata{}, errors.New("invalid E2EE response metadata")
	}
	var metadata ResponseMetadata
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&metadata); err != nil {
		return ResponseMetadata{}, errors.New("invalid E2EE response metadata")
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return ResponseMetadata{}, errors.New("invalid E2EE response metadata")
	}
	if err := validateResponseMetadata(metadata); err != nil {
		return ResponseMetadata{}, err
	}
	return metadata, nil
}

func (s *Session) responseAAD(sequence uint64) []byte {
	aad := make([]byte, 0, sha256.Size+len("stogas.e2ee.response.record.v1")+1+8)
	aad = append(aad, []byte("stogas.e2ee.response.record.v1")...)
	aad = append(aad, 0)
	aad = append(aad, s.transcriptHash[:]...)
	var encodedSequence [8]byte
	binary.BigEndian.PutUint64(encodedSequence[:], sequence)
	aad = append(aad, encodedSequence[:]...)
	return aad
}

func responseNonceFor(base [12]byte, sequence uint64) [12]byte {
	nonce := base
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(sequence >> (8 * i))
	}
	return nonce
}

func validateResponseMetadata(metadata ResponseMetadata) error {
	if metadata.StatusCode < 200 || metadata.StatusCode > 599 {
		return errors.New("invalid inner HTTP status")
	}
	if !validContentType(metadata.ContentType) {
		return errors.New("invalid inner Content-Type")
	}
	if len(metadata.Headers) > 32 {
		return errors.New("too many inner response headers")
	}
	seen := make(map[string]struct{}, len(metadata.Headers))
	for key, value := range metadata.Headers {
		normalized := strings.ToLower(key)
		if len(key) > 128 ||
			len(value) > 16*1024 ||
			!validHTTPFieldName(key) ||
			!validHTTPFieldValue(value, true) {
			return fmt.Errorf("invalid inner response header")
		}
		if _, duplicate := seen[normalized]; duplicate {
			return fmt.Errorf("duplicate inner response header")
		}
		seen[normalized] = struct{}{}
	}
	return nil
}
