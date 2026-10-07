// Package providerio admits provider response storage before buffering and
// decoding. Reservations belong to the inference lifecycle, not the socket.
package providerio

import (
	"context"
	"errors"
	"io"
)

var ErrCapacity = errors.New("request memory capacity exhausted")

// Budget keeps response bytes and decoded structure charged until their last
// request owner finishes. Temporary decoder state has a separate lifetime.
type Budget interface {
	ReserveResponse(bytes, values int64) bool
	ReserveTemporary(bytes int64) (release func(), ok bool)
}

type budgetKey struct{}

func WithBudget(ctx context.Context, budget Budget) context.Context {
	return context.WithValue(ctx, budgetKey{}, budget)
}

func budgetFrom(ctx context.Context) Budget {
	budget, _ := ctx.Value(budgetKey{}).(Budget)
	return budget
}

// reader admits a bounded lookahead before a consumer grows its own buffer.
// The byte charge is monotonic across the response, including retained stream
// state. The lookahead is a high-water mark, not a charge per read call.
type reader struct {
	source         io.Reader
	budget         Budget
	limit          int64
	total          int64
	charged        int64
	structure      structureCounter
	countStructure bool
}

func (r *reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	p = p[:min(len(p), 16<<10)]
	remaining := r.limit - r.total
	if remaining <= 0 {
		var extra [1]byte
		n, err := r.source.Read(extra[:])
		if n != 0 {
			return 0, ErrTooLarge
		}
		return 0, err
	}
	p = p[:min(int64(len(p)), remaining)]
	next := max(r.charged, r.total+int64(len(p)))
	if r.budget != nil && !r.budget.ReserveResponse(next-r.charged, 0) {
		return 0, ErrCapacity
	}
	r.charged = next
	n, err := r.source.Read(p)
	r.total += int64(n)
	if r.countStructure && r.budget != nil {
		if !r.budget.ReserveResponse(0, r.structure.add(p[:n])) {
			clear(p[:n])
			return 0, ErrCapacity
		}
	}
	return n, err
}

// Count JSON containers, strings (including member names) and primitive runs
// without allocating a parse tree. This also conservatively counts SSE field
// names and comments. Syntax validation remains the provider codec's job.
type structureCounter struct{ quoted, escaped, primitive bool }

func (s *structureCounter) add(data []byte) (values int64) {
	for _, c := range data {
		// JSON strings cannot contain literal line breaks. SSE comments and
		// fields can contain unmatched quotes; they must not hide structure
		// in the next event's independently parsed JSON.
		if c == '\n' || c == '\r' {
			*s = structureCounter{}
			continue
		}
		if s.quoted {
			if s.escaped {
				s.escaped = false
			} else if c == '\\' {
				s.escaped = true
			} else if c == '"' {
				s.quoted = false
			}
			continue
		}
		switch c {
		case '"':
			values++
			s.quoted = true
			s.primitive = false
		case '{', '[':
			values++
			s.primitive = false
		case '}', ']', ',', ':', ' ', '\t', '\r', '\n':
			s.primitive = false
		default:
			if !s.primitive {
				values++
				s.primitive = true
			}
		}
	}
	return values
}

// AdmitDecrypted admits structure hidden by an encrypted provider envelope.
// Its bytes are already covered by the larger admitted encrypted envelope.
func AdmitDecrypted(ctx context.Context, data []byte) error {
	if budget := budgetFrom(ctx); budget != nil {
		var counter structureCounter
		if !budget.ReserveResponse(0, counter.add(data)) {
			return ErrCapacity
		}
	}
	return nil
}
