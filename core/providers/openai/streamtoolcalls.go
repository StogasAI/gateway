package openai

import "github.com/maximhq/bifrost/core/schemas"

// streamToolCalls numbers apart the tool calls of a Chat Completions stream whose server streams
// several calls at one index, as Gemma 4's on Google Cloud does at index 0: the first delta of each
// call names the function under its own ID, and the arguments follow in deltas with neither. A
// client joins deltas by index, as the API defines, so it would get such calls as one call with
// their arguments run together. A delta that names a function under an ID other than the one at
// its index starts a new call at the next free index, and the later deltas at that index follow
// it there. The indexes of a server that numbers its calls apart stay as they are.
type streamToolCalls struct {
	calls map[streamToolCallKey]streamToolCall
	next  map[int]uint16 // per choice, the index above every index that the client has seen
}

type streamToolCallKey struct {
	choice int
	index  uint16 // as the server sent it
}

type streamToolCall struct {
	id    string
	index uint16 // as the client sees it
}

func (s *streamToolCalls) renumber(choices []schemas.BifrostResponseChoice) {
	for i := range choices {
		stream := choices[i].ChatStreamResponseChoice
		if stream == nil || stream.Delta == nil {
			continue
		}
		choice := choices[i].Index
		for j := range stream.Delta.ToolCalls {
			if s.calls == nil {
				s.calls, s.next = map[streamToolCallKey]streamToolCall{}, map[int]uint16{}
			}
			call := &stream.Delta.ToolCalls[j]
			key := streamToolCallKey{choice, call.Index}
			id, name := "", ""
			if call.ID != nil {
				id = *call.ID
			}
			if call.Function.Name != nil {
				name = *call.Function.Name
			}
			current, known := s.calls[key]
			switch {
			case !known:
				current = streamToolCall{id: id, index: max(call.Index, s.next[choice])}
			case id != "" && current.id == "":
				current.id = id
			case id != "" && id != current.id && name != "":
				current = streamToolCall{id: id, index: s.next[choice]}
			}
			s.calls[key] = current
			s.next[choice] = max(s.next[choice], current.index+1)
			call.Index = current.index
		}
	}
}
