// Package tokenizer estimates text for financial holds with one fixed formula.
// It has no model vocabulary or provider selection. Message/tool framing and
// opaque provider reasoning are accounted for separately by the caller.
package tokenizer

import (
	"errors"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// The universal text estimate uses fixed coefficients, scaled by 10,000 so
// rounding is exact. Non-ASCII UTF-8 bytes have one weight; Unicode processing
// is needed only to measure normalization growth. No input is rewritten.
var estimateByteWeights = func() [256]int64 {
	var weights [256]int64
	for b := range weights {
		switch {
		case b >= utf8.RuneSelf:
			weights[b] = 6705
		case b >= 'a' && b <= 'z', b == ' ', b == '\t', b == '\v', b == '\f', b == '\r', b == '\n':
			weights[b] = 4763
		case b >= '0' && b <= '9':
			weights[b] = 6001
		case b < 32 || b == 127:
			weights[b] = 5677
		default: // ASCII uppercase and punctuation.
			weights[b] = 9763
		}
	}
	return weights
}()

var errInvalidEstimateText = errors.New("token estimate input is not valid UTF-8")

// Estimate returns a provider-independent estimate for one text field. Empty
// fields contribute zero; each nonempty field includes a 6.5897-token intercept.
// Message/tool framing and opaque provider reasoning are the caller's concern.
// This empirical estimate is not an exact tokenizer or a provider usage bound.
func Estimate(text string) (int, error) {
	return EstimateAtMost(text, 0)
}

// EstimateAtMost returns min(Estimate(text), limit). A nonpositive limit means
// no cap. Normalization can be skipped once the byte contribution reaches the
// cap because both normalization-growth contributions are nonnegative.
func EstimateAtMost(text string, limit int) (int, error) {
	if text == "" {
		return 0, nil
	}
	var highBits byte
	score := int64(65897)
	for i := 0; i < len(text); i++ {
		score += estimateByteWeights[text[i]]
		highBits |= text[i]
	}
	if highBits >= utf8.RuneSelf {
		if !utf8.ValidString(text) {
			return 0, errInvalidEstimateText
		}
		if limit > 0 && (score+9999)/10000 >= int64(limit) {
			return limit, nil
		}
		nfcBytes := max(len(text), normalizedByteLength(text, norm.NFC))
		nfkcBytes := max(nfcBytes, normalizedByteLength(text, norm.NFKC))
		score += 19105*int64(nfcBytes-len(text)) + 3231*int64(nfkcBytes-nfcBytes)
	}
	estimate := int((score + 9999) / 10000)
	if limit > 0 {
		return min(estimate, limit), nil
	}
	return estimate, nil
}

// Iter uses bounded normalization segments, including stream-safe handling of
// long combining sequences, instead of allocating an input-sized copy.
func normalizedByteLength(text string, form norm.Form) int {
	if form.QuickSpanString(text) == len(text) {
		return len(text)
	}
	var iter norm.Iter
	iter.InitString(form, text)
	size := 0
	for !iter.Done() {
		size += len(iter.Next())
	}
	return size
}
