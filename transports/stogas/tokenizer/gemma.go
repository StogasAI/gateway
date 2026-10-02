package tokenizer

import (
	"math"
	"unicode/utf8"
)

// Gemma starts from vocabulary runes, not raw bytes. Unknown runes contribute
// their UTF-8 byte fallback count and cannot be merged with adjacent text.
func (c *Counter) mergeGemma(piece string, h *mergeHeap) int {
	n := len(piece)
	if cap(h.nodes) < n {
		h.nodes = make([]mergeNode, n)
		h.items = make([]int32, n)
	}
	h.nodes = h.nodes[:n]
	h.items = h.items[:0]
	count := 0
	prev := int32(-1)
	for i := 0; i < n; {
		_, width := utf8.DecodeRuneInString(piece[i:])
		_, known := c.ranks[piece[i:i+width]]
		rank := uint32(math.MaxUint32)
		if known {
			count++
		} else {
			count += width
		}
		h.nodes[i] = mergeNode{prev: prev, next: int32(i + width), heapIndex: int32(len(h.items)), rank: rank}
		h.items = append(h.items, int32(i))
		prev = int32(i)
		i += width
	}
	update := func(index int32) {
		right := h.nodes[index].next
		rank := uint32(math.MaxUint32)
		if int(right) < n {
			_, leftOK := c.ranks[piece[index:right]]
			_, rightOK := c.ranks[piece[right:h.nodes[right].next]]
			if leftOK && rightOK {
				rank = c.rank(piece[index:h.nodes[right].next])
			}
		}
		h.nodes[index].rank = rank
	}
	for _, index := range h.items {
		update(index)
	}
	for i := len(h.items)/2 - 1; i >= 0; i-- {
		h.down(i)
	}
	for h.nodes[h.items[0]].rank != math.MaxUint32 {
		left := h.items[0]
		right := h.nodes[left].next
		h.remove(int(h.nodes[right].heapIndex))
		next := h.nodes[right].next
		h.nodes[left].next = next
		if int(next) < n {
			h.nodes[next].prev = left
		}
		update(left)
		h.fix(int(h.nodes[left].heapIndex))
		if prev := h.nodes[left].prev; prev >= 0 {
			update(prev)
			h.fix(int(h.nodes[prev].heapIndex))
		}
		count--
	}
	return count
}
