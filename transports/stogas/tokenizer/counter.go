// Package tokenizer estimates ordinary text counts with pinned public
// vocabularies and a separate, unofficial Claude count reconstruction.
// It does not estimate a provider's hidden framing, images, or tool overhead.
package tokenizer

import (
	"encoding/binary"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Split oversized pretokens into bounded BPE segments. This counts the entire
// input without input-sized merge scratch space or byte-sized reservations.
// Counts near an artificial boundary can differ from unsplit BPE; this is an
// estimate, not a byte upper bound or an exact provider tokenizer.
const maxMergePieceBytes = 16 << 10

// Set by the offline generator when vocabulary membership alone does not
// prove that the model's merge rules emit this whole string as one token.
const noWholeTokenShortcut uint32 = 1 << 31

type Counter struct {
	name          string
	ranks         map[string]uint32
	pairRanks     [1 << 16]uint32 // rank + 1; zero means absent
	maxTokenBytes int
}

func (c *Counter) Count(text string) (int, error) {
	return c.CountAtMost(text, 0)
}

// CountAtMost stops once the count reaches limit. Nonpositive limits count all
// text. Use only when the result is itself capped, not to sample a prompt.
func (c *Counter) CountAtMost(text string, limit int) (int, error) {
	if !utf8.ValidString(text) {
		return 0, fmt.Errorf("tokenizer input is not valid UTF-8")
	}
	text = c.normalize(text)
	var scratch mergeHeap
	// Request-local memoization helps repeated multi-token words without
	// retaining customer text across calls. Collisions only cause a miss;
	// equality of the complete piece is always checked before reusing a count.
	var recent [256]struct {
		text  string
		count int
	}
	count := 0
	for len(text) > 0 {
		end := c.piece(text)
		if end == 0 {
			return 0, fmt.Errorf("tokenizer could not split input")
		}
		piece := text[:end]
		// Preserve the upstream whitespace lookahead. An interior
		// whitespace run leaves its last rune for the following pretoken,
		// unless the earlier newline alternative already consumed the run.
		last, width := utf8.DecodeLastRuneInString(piece)
		if c.name != "gemma" && end < len(text) && end > width && last != '\r' && last != '\n' && unicode.IsSpace(last) && strings.TrimSpace(piece) == "" {
			end -= width
			piece = text[:end]
		}
		for len(piece) > 0 {
			partEnd := min(len(piece), maxMergePieceBytes)
			if c.name == "gemma" {
				for partEnd < len(piece) && !utf8.RuneStart(piece[partEnd]) {
					partEnd--
				}
			}
			part := piece[:partEnd]
			piece = piece[len(part):]
			// BPE operates on bytes, including partial UTF-8 sequences at these
			// artificial boundaries. The complete input was validated above.
			pieceCount := 0
			if rank, ok := c.ranks[part]; ok && rank&noWholeTokenShortcut == 0 {
				pieceCount = 1
			} else if len(part) >= 16 {
				hash := binary.LittleEndian.Uint64([]byte(part[:8])) ^ binary.LittleEndian.Uint64([]byte(part[len(part)-8:])) ^ uint64(len(part))
				entry := &recent[(hash*0x9e3779b97f4a7c15)>>56]
				if entry.text != part {
					entry.text = part
					entry.count = c.mergePiece(part, &scratch)
				}
				pieceCount = entry.count
			} else {
				pieceCount = c.mergePiece(part, &scratch)
			}
			count += pieceCount
			if limit > 0 && count >= limit {
				return limit, nil
			}
		}
		text = text[end:]
	}
	return count, nil
}

func (c *Counter) mergePiece(part string, scratch *mergeHeap) int {
	if c.name == "gemma" {
		return c.mergeGemma(part, scratch)
	}
	return c.mergeCount(part, scratch)
}
