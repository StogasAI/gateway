package proofhttp

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"hash"

	verifier "github.com/StogasAI/verifier/go"
	"github.com/maximhq/bifrost/transports/stogas/confidential/proof"
)

const SSECommentPrefix = "stogas "

type Service struct {
	keys   *verifier.NodeKeys
	boot   [32]byte
	nodeID string
}

type Input = proof.Input
type Output struct {
	JSON   []byte
	Object proof.Object
}

// New binds receipts to the logged boot that commits these keys, after the
// runtime has verified it and taken its node identity from that verification.
func New(bootSHA256 [32]byte, nodeID string, keys *verifier.NodeKeys) (*Service, error) {
	if keys == nil || nodeID == "" {
		return nil, errors.New("invalid receipt identity")
	}
	return &Service{keys: keys, boot: bootSHA256, nodeID: nodeID}, nil
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
	unsigned, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}
	receipt, err := s.keys.SignReceipt(s.boot, request, response, unsigned)
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(receipt, &object.Receipt); err != nil {
		return nil, err
	}
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
	if s.nodeID == "" || s.keys == nil || input.RequestDigest == nil || !proof.ValidCatalog(input.Metadata.Catalog) {
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
		s.keys = nil
	}
}
