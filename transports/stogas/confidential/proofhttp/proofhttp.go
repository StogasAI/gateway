package proofhttp

import (
	"bytes"
	"context"
	"crypto/mldsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"hash"

	"github.com/maximhq/bifrost/transports/stogas/confidential/attest"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
)

const SSECommentPrefix = "stogas "

type Service struct {
	signer *mldsa.PrivateKey
	boot   [32]byte
	nodeID string
}

type Input = proof.Input
type Output struct {
	JSON   []byte
	Object proof.Object
}

// New binds the signer to the immutable boot already appraised by the runtime.
// This local consistency check does not replace hardware or log verification.
func New(document []byte, signer *mldsa.PrivateKey) (*Service, error) {
	if len(document) > attest.MaxSessionEvidenceBytes || signer == nil || signer.PublicKey().Parameters() != mldsa.MLDSA65() {
		return nil, errors.New("invalid receipt identity")
	}
	var record attest.BootRecord
	if err := json.Unmarshal(document, &record); err != nil {
		return nil, err
	}
	canonical, err := record.Document()
	if err != nil || !bytes.Equal(canonical, document) {
		return nil, errors.New("receipt boot is not canonical")
	}
	public, err := base64.RawURLEncoding.DecodeString(record.ReportData.SigningPublicKey)
	if err != nil || !bytes.Equal(public, signer.PublicKey().Bytes()) {
		return nil, errors.New("receipt signer differs from boot")
	}
	report, err := base64.RawURLEncoding.DecodeString(record.Report)
	if err != nil {
		return nil, err
	}
	return &Service{signer: signer, boot: sha256.Sum256(document), nodeID: attest.SNPNodeID([32]byte(report[0x140:0x160]))}, nil
}

func (s *Service) Build(ctx context.Context, input Input) (*Output, error) {
	if s == nil {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if input.RequestDigest == nil || len(input.ResponseBody) == 0 {
		return nil, errors.New("receipt content is empty")
	}
	return s.output(input.Metadata, *input.RequestDigest, sha256.Sum256(input.ResponseBody))
}

func (s *Service) output(metadata proof.Metadata, request, response [32]byte) (*Output, error) {
	if s.nodeID == "" || !proof.ValidMetadata(metadata) {
		return nil, errors.New("receipt metadata or identity is invalid")
	}
	object := proof.Object{Metadata: metadata, NodeID: s.nodeID}
	receipt, err := proof.SignReceipt(s.signer, s.boot, request, response, object)
	if err != nil {
		return nil, err
	}
	object.Receipt = receipt
	encoded, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}
	if len(encoded) > proof.MaxObjectBytes {
		return nil, errors.New("response metadata exceeds its encoded size limit")
	}
	return &Output{JSON: encoded, Object: object}, nil
}

// Stream belongs to one response writer. It retains digests, never request bodies.
type Stream struct {
	request  [32]byte
	response hash.Hash
	metadata proof.Metadata
	finished bool
}

func (s *Service) NewStream(ctx context.Context, input Input) (*Stream, error) {
	if s == nil {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s.nodeID == "" || s.signer == nil || input.RequestDigest == nil || !proof.ValidCatalog(input.Metadata.Catalog) {
		return nil, errors.New("receipt context is incomplete")
	}
	return &Stream{request: *input.RequestDigest, response: sha256.New(), metadata: input.Metadata}, nil
}

func (s *Stream) WriteSentChunk(chunk []byte) {
	if s != nil && !s.finished {
		_, _ = s.response.Write(chunk)
	}
}
func (s *Stream) SetMetadata(metadata proof.Metadata) {
	if s != nil && !s.finished {
		s.metadata = metadata
	}
}
func (s *Service) FinishStream(ctx context.Context, stream *Stream) (*Output, error) {
	if s == nil || stream == nil {
		return nil, nil
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if stream.finished {
		return nil, errors.New("receipt stream is already finished")
	}
	stream.finished = true
	return s.output(stream.metadata, stream.request, [32]byte(stream.response.Sum(nil)))
}

// Close is called after all admitted requests finish.
func (s *Service) Close() {
	if s != nil {
		s.signer = nil
	}
}
