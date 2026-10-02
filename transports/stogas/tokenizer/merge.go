package tokenizer

import "math"

// Small pieces use a stack-backed merge list. Larger pieces use an indexed
// heap, so each merge updates at most two neighbours in O(log n) time. Stable
// rank ties select the leftmost pair, as in tiktoken. Neither path retains text.
const smallPieceBytes = 64

type mergePart struct {
	offset int
	rank   uint32
}
type mergeNode struct {
	prev, next, heapIndex int32
	rank                  uint32
}
type mergeHeap struct {
	nodes []mergeNode
	items []int32
}

func (c *Counter) rank(text string) uint32 {
	// Most initial merge candidates contain two bytes. A fixed table avoids
	// hashing each pair; absent entries wrap back to MaxUint32.
	if len(text) == 2 {
		return c.pairRanks[uint16(text[0])<<8|uint16(text[1])] - 1
	}
	if len(text) <= c.maxTokenBytes {
		if rank, ok := c.ranks[text]; ok {
			return rank &^ noWholeTokenShortcut
		}
	}
	return math.MaxUint32
}

func (c *Counter) mergeCount(piece string, scratch *mergeHeap) int {
	if len(piece) <= smallPieceBytes {
		return c.mergeSmall(piece)
	}
	n := len(piece)
	if cap(scratch.nodes) < n {
		scratch.nodes = make([]mergeNode, n)
		scratch.items = make([]int32, n)
	}
	scratch.nodes, scratch.items = scratch.nodes[:n], scratch.items[:n]
	for i := range n {
		rank := uint32(math.MaxUint32)
		if i+1 < n {
			rank = c.rank(piece[i : i+2])
		}
		scratch.nodes[i] = mergeNode{prev: int32(i - 1), next: int32(i + 1), heapIndex: int32(i), rank: rank}
		scratch.items[i] = int32(i)
	}
	for i := n/2 - 1; i >= 0; i-- {
		scratch.down(i)
	}
	count := n
	for scratch.nodes[scratch.items[0]].rank != math.MaxUint32 {
		left := scratch.items[0]
		right := scratch.nodes[left].next
		scratch.remove(int(scratch.nodes[right].heapIndex))
		next := scratch.nodes[right].next
		scratch.nodes[left].next = next
		if int(next) < n {
			scratch.nodes[next].prev = left
		}
		update := func(index int32) {
			end := scratch.nodes[index].next
			rank := uint32(math.MaxUint32)
			if int(end) < n {
				rank = c.rank(piece[index:scratch.nodes[end].next])
			}
			scratch.nodes[index].rank = rank
			scratch.fix(int(scratch.nodes[index].heapIndex))
		}
		update(left)
		if prev := scratch.nodes[left].prev; prev >= 0 {
			update(prev)
		}
		count--
	}
	return count
}

func (c *Counter) mergeSmall(piece string) int {
	var storage [smallPieceBytes + 1]mergePart
	parts := storage[:len(piece)+1]
	for i := range parts {
		parts[i] = mergePart{offset: i, rank: math.MaxUint32}
		if i+2 <= len(piece) {
			parts[i].rank = c.rank(piece[i : i+2])
		}
	}
	for {
		index, rank := -1, uint32(math.MaxUint32)
		for i := range len(parts) - 1 {
			if parts[i].rank < rank {
				index, rank = i, parts[i].rank
			}
		}
		if index < 0 {
			return len(parts) - 1
		}
		parts[index].rank = math.MaxUint32
		if index+3 < len(parts) {
			parts[index].rank = c.rank(piece[parts[index].offset:parts[index+3].offset])
		}
		if index > 0 {
			parts[index-1].rank = c.rank(piece[parts[index-1].offset:parts[index+2].offset])
		}
		copy(parts[index+1:], parts[index+2:])
		parts = parts[:len(parts)-1]
	}
}

func (h *mergeHeap) less(i, j int) bool {
	a, b := h.items[i], h.items[j]
	return h.nodes[a].rank < h.nodes[b].rank || h.nodes[a].rank == h.nodes[b].rank && a < b
}
func (h *mergeHeap) swap(i, j int) {
	h.items[i], h.items[j] = h.items[j], h.items[i]
	h.nodes[h.items[i]].heapIndex, h.nodes[h.items[j]].heapIndex = int32(i), int32(j)
}
func (h *mergeHeap) down(i int) {
	for {
		child := i*2 + 1
		if child >= len(h.items) {
			return
		}
		if child+1 < len(h.items) && h.less(child+1, child) {
			child++
		}
		if !h.less(child, i) {
			return
		}
		h.swap(i, child)
		i = child
	}
}
func (h *mergeHeap) fix(i int) {
	if i > 0 && h.less(i, (i-1)/2) {
		for i > 0 && h.less(i, (i-1)/2) {
			parent := (i - 1) / 2
			h.swap(i, parent)
			i = parent
		}
	} else {
		h.down(i)
	}
}
func (h *mergeHeap) remove(i int) {
	last := len(h.items) - 1
	if i != last {
		h.swap(i, last)
	}
	h.items = h.items[:last]
	if i < last {
		h.fix(i)
	}
}
