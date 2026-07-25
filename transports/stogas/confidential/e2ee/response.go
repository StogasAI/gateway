package e2ee

import (
	"bytes"
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
}

func (s *Session) EncodeResponse(metadata ResponseMetadata, body []byte) ([]byte, error) {
	reader, err := s.NewResponseReader(bytes.NewReader(body), metadata)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(reader)
}

func (s *Session) NewResponseReader(source io.Reader, metadata ResponseMetadata) (*ResponseReader, error) {
	if s == nil || s.responseAEAD == nil {
		return nil, errors.New("E2EE response session is unavailable")
	}
	if source == nil {
		source = bytes.NewReader(nil)
	}
	if err := validateResponseMetadata(metadata); err != nil {
		return nil, err
	}
	return &ResponseReader{source: source, session: s, metadata: metadata}, nil
}

func (r *ResponseReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for r.pending.Len() == 0 {
		if !r.started {
			r.started = true
			r.pending.Write(responseMagic)
			metadata, err := json.Marshal(r.metadata)
			if err != nil {
				return 0, err
			}
			if err := r.appendFrame(responseFrameMetadata, metadata); err != nil {
				return 0, err
			}
			continue
		}
		if !r.sourceDone {
			chunk := make([]byte, maxResponseFrameSize)
			n, err := r.source.Read(chunk)
			if n > 0 {
				r.emptyReads = 0
				if frameErr := r.appendFrame(responseFrameData, chunk[:n]); frameErr != nil {
					return 0, frameErr
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
			if err := r.appendFrame(responseFrameFinal, nil); err != nil {
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

func (r *ResponseReader) appendFrame(frameType byte, plaintext []byte) error {
	if r.sequence == math.MaxUint64 {
		return errors.New("E2EE response sequence exhausted")
	}
	aad := r.session.responseAAD(frameType, r.sequence)
	nonce := r.session.responseNonceFor(r.sequence)
	ciphertext := r.session.responseAEAD.Seal(nil, nonce[:], plaintext, aad)
	if len(ciphertext) > int(^uint32(0)) {
		return errors.New("E2EE response frame is too large")
	}
	r.pending.WriteByte(frameType)
	_ = binary.Write(&r.pending, binary.BigEndian, r.sequence)
	_ = binary.Write(&r.pending, binary.BigEndian, uint32(len(ciphertext)))
	r.pending.Write(ciphertext)
	r.sequence++
	return nil
}

func (s *Session) DecodeResponse(data []byte) (*DecodedResponse, error) {
	if s == nil || s.responseAEAD == nil {
		return nil, errors.New("E2EE response session is unavailable")
	}
	if len(data) < len(responseMagic) || !bytes.Equal(data[:len(responseMagic)], responseMagic) {
		return nil, errors.New("invalid E2EE response magic")
	}
	reader := bytes.NewReader(data[len(responseMagic):])
	var result DecodedResponse
	sequence := uint64(0)
	metadataSeen := false
	finalSeen := false
	for reader.Len() > 0 {
		frameType, err := reader.ReadByte()
		if err != nil {
			return nil, err
		}
		var frameSequence uint64
		var ciphertextLength uint32
		if err := binary.Read(reader, binary.BigEndian, &frameSequence); err != nil {
			return nil, errors.New("truncated E2EE response frame")
		}
		if err := binary.Read(reader, binary.BigEndian, &ciphertextLength); err != nil {
			return nil, errors.New("truncated E2EE response frame")
		}
		if frameSequence != sequence {
			return nil, errors.New("non-contiguous E2EE response sequence")
		}
		if int64(ciphertextLength) > int64(reader.Len()) || ciphertextLength < uint32(s.responseAEAD.Overhead()) {
			return nil, errors.New("invalid E2EE response frame length")
		}
		maxCiphertextLength := maxResponseFrameSize + s.responseAEAD.Overhead()
		if frameType == responseFrameMetadata {
			maxCiphertextLength = maxResponseMetadata + s.responseAEAD.Overhead()
		}
		if ciphertextLength > uint32(maxCiphertextLength) {
			return nil, errors.New("E2EE response frame is too large")
		}
		ciphertext := make([]byte, ciphertextLength)
		if _, err := io.ReadFull(reader, ciphertext); err != nil {
			return nil, errors.New("truncated E2EE response frame")
		}
		nonce := s.responseNonceFor(sequence)
		plaintext, err := s.responseAEAD.Open(nil, nonce[:], ciphertext, s.responseAAD(frameType, sequence))
		if err != nil {
			return nil, errors.New("E2EE response authentication failed")
		}
		switch frameType {
		case responseFrameMetadata:
			if metadataSeen || sequence != 0 {
				return nil, errors.New("invalid E2EE response metadata position")
			}
			if len(plaintext) > maxResponseMetadata {
				return nil, errors.New("E2EE response metadata is too large")
			}
			metadata, err := decodeResponseMetadata(plaintext)
			if err != nil {
				return nil, err
			}
			result.Metadata = metadata
			metadataSeen = true
		case responseFrameData:
			if !metadataSeen || finalSeen {
				return nil, errors.New("invalid E2EE response data position")
			}
			result.Body = append(result.Body, plaintext...)
		case responseFrameFinal:
			if !metadataSeen || finalSeen || len(plaintext) != 0 {
				return nil, errors.New("invalid E2EE response final frame")
			}
			finalSeen = true
			if reader.Len() != 0 {
				return nil, errors.New("data follows E2EE response final frame")
			}
		default:
			return nil, errors.New("unknown E2EE response frame type")
		}
		sequence++
	}
	if !metadataSeen || !finalSeen {
		return nil, errors.New("truncated E2EE response")
	}
	return &result, nil
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

func (s *Session) responseAAD(frameType byte, sequence uint64) []byte {
	aad := make([]byte, 0, sha256.Size+len("stogas.e2ee.response.frame.v1")+1+8)
	aad = append(aad, []byte("stogas.e2ee.response.frame.v1")...)
	aad = append(aad, 0)
	aad = append(aad, s.transcriptHash[:]...)
	aad = append(aad, frameType)
	var encodedSequence [8]byte
	binary.BigEndian.PutUint64(encodedSequence[:], sequence)
	aad = append(aad, encodedSequence[:]...)
	return aad
}

func (s *Session) responseNonceFor(sequence uint64) [12]byte {
	nonce := s.responseNonce
	for i := 0; i < 8; i++ {
		nonce[len(nonce)-1-i] ^= byte(sequence >> (8 * i))
	}
	return nonce
}

func validateResponseMetadata(metadata ResponseMetadata) error {
	if metadata.StatusCode < 100 || metadata.StatusCode > 599 {
		return errors.New("invalid inner HTTP status")
	}
	if metadata.ContentType == "" || len(metadata.ContentType) > 256 {
		return errors.New("invalid inner Content-Type")
	}
	if len(metadata.Headers) > 32 {
		return errors.New("too many inner response headers")
	}
	for key, value := range metadata.Headers {
		if key == "" ||
			len(key) > 128 ||
			len(value) > 16*1024 ||
			strings.ContainsAny(key, "\x00\r\n:") ||
			strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("invalid inner response header")
		}
	}
	return nil
}
