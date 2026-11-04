package stogas

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"

	"github.com/maximhq/bifrost/core/schemas"
)

// A bridged request reaches a deployment that takes only Chat Completions, whose provider replies
// with Chat Completions. Its client, which called Responses, gets the reply as Responses: the
// reasoning, the text and refusal, and each tool call become output items, in the order in which
// the model wrote them. The converted reply must then pass the checks of a provider's Responses
// reply, which also give it the echo of the request. Those checks run on a state of their own:
// the request's state keeps the provider's reply, from which the gateway bills and logs.

// maxBridgedIDBase bounds the part of a reply's ID that the IDs of its items repeat.
const maxBridgedIDBase = 64

// bridgedReply holds what the output of one converted reply shares: the state on which the
// Responses checks check it, and the IDs of the reply and its items.
type bridgedReply struct {
	checks *State
	id     string
	base   string
}

func newBridgedReply(state *State, id string) bridgedReply {
	base := id
	if len(base) > maxBridgedIDBase {
		sum := sha256.Sum256([]byte(id))
		base = hex.EncodeToString(sum[:16])
	}
	return bridgedReply{
		checks: &State{Pair: Pair{Resolution: state.Resolution, Adapter: state.Adapter}},
		id:     id,
		base:   base,
	}
}

// itemID names the reply's item at index, as OpenAI's prefixes name its kind.
func (r bridgedReply) itemID(kind schemas.ResponsesMessageType, index int) string {
	prefix := "msg_"
	switch kind {
	case schemas.ResponsesMessageTypeReasoning:
		prefix = "rs_"
	case schemas.ResponsesMessageTypeFunctionCall:
		prefix = "fc_"
	}
	return prefix + r.base + "_" + strconv.Itoa(index)
}

// bridgedText is a text or a refusal of a message.
type bridgedText struct {
	refusal bool
	text    string
}

func (r bridgedReply) reasoningItem(index int, status, text string) schemas.ResponsesMessage {
	kind := schemas.ResponsesMessageTypeReasoning
	return schemas.ResponsesMessage{
		ID:     schemas.Ptr(r.itemID(kind, index)),
		Type:   &kind,
		Status: &status,
		Content: &schemas.ResponsesMessageContent{ContentBlocks: []schemas.ResponsesMessageContentBlock{
			reasoningBlock(text),
		}},
		ResponsesReasoning: &schemas.ResponsesReasoning{Summary: []schemas.ResponsesReasoningSummary{}},
	}
}

func (r bridgedReply) messageItem(index int, status string, texts []bridgedText) schemas.ResponsesMessage {
	kind := schemas.ResponsesMessageTypeMessage
	blocks := make([]schemas.ResponsesMessageContentBlock, 0, len(texts))
	for _, text := range texts {
		blocks = append(blocks, messageBlock(text))
	}
	return schemas.ResponsesMessage{
		ID:      schemas.Ptr(r.itemID(kind, index)),
		Type:    &kind,
		Role:    schemas.Ptr(schemas.ResponsesInputMessageRoleAssistant),
		Status:  &status,
		Content: &schemas.ResponsesMessageContent{ContentBlocks: blocks},
	}
}

func (r bridgedReply) callItem(index int, status, callID, name, arguments string) schemas.ResponsesMessage {
	kind := schemas.ResponsesMessageTypeFunctionCall
	return schemas.ResponsesMessage{
		ID:     schemas.Ptr(r.itemID(kind, index)),
		Type:   &kind,
		Status: &status,
		ResponsesToolMessage: &schemas.ResponsesToolMessage{
			CallID:    &callID,
			Name:      &name,
			Arguments: &arguments,
		},
	}
}

func reasoningBlock(text string) schemas.ResponsesMessageContentBlock {
	return schemas.ResponsesMessageContentBlock{Type: schemas.ResponsesOutputMessageContentTypeReasoning, Text: &text}
}

func messageBlock(text bridgedText) schemas.ResponsesMessageContentBlock {
	if text.refusal {
		return schemas.ResponsesMessageContentBlock{
			Type:                                 schemas.ResponsesOutputMessageContentTypeRefusal,
			ResponsesOutputMessageContentRefusal: &schemas.ResponsesOutputMessageContentRefusal{Refusal: text.text},
		}
	}
	return schemas.ResponsesMessageContentBlock{
		Type: schemas.ResponsesOutputMessageContentTypeText,
		Text: schemas.Ptr(text.text),
		ResponsesOutputMessageContentText: &schemas.ResponsesOutputMessageContentText{
			Annotations: []schemas.ResponsesOutputMessageContentTextAnnotation{},
			LogProbs:    []schemas.ResponsesOutputMessageContentTextLogProb{},
		},
	}
}

// bridgedStatus is the status of a reply that ended for reason, and why it is incomplete. A
// refusal completes the reply, as on OpenAI's Responses.
func bridgedStatus(reason string) (string, *schemas.ResponsesResponseIncompleteDetails, error) {
	switch reason {
	case string(schemas.BifrostFinishReasonStop), string(schemas.BifrostFinishReasonToolCalls), "refusal":
		return schemas.ResponsesResponseStatusCompleted, nil, nil
	case string(schemas.BifrostFinishReasonLength):
		return schemas.ResponsesResponseStatusIncomplete,
			&schemas.ResponsesResponseIncompleteDetails{Reason: schemas.ResponsesResponseIncompleteReasonMaxOutputTokens}, nil
	case "content_filter":
		return schemas.ResponsesResponseStatusIncomplete,
			&schemas.ResponsesResponseIncompleteDetails{Reason: schemas.ResponsesResponseIncompleteReasonContentFilter}, nil
	default:
		return "", nil, ErrProviderResponseMalformed
	}
}

// bridgedReasoning is the reasoning text that reasoning details carry. Bridged providers return
// reasoning as text. A summary, or an encrypted or signed reasoning, has no form that a bridged
// request could send back.
func bridgedReasoning(details []schemas.ChatReasoningDetails) (string, error) {
	var text strings.Builder
	for _, detail := range details {
		if detail.Type != schemas.BifrostReasoningDetailsTypeText || detail.Text == nil || detail.Signature != nil {
			return "", ErrProviderResponseMalformed
		}
		text.WriteString(*detail.Text)
	}
	return text.String(), nil
}

// completedAt is when a reply that its provider created at created completed: now, unless the
// provider's clock is ahead of the gateway's.
func completedAt(created int) *int {
	return schemas.Ptr(max(int(time.Now().Unix()), created))
}

// BridgedResponse returns the reply that the client of a unary request gets: for a bridged
// request, the provider's Chat Completions reply as Responses, and otherwise the reply itself.
func BridgedResponse(state *State, response *schemas.BifrostResponse) (*schemas.BifrostResponse, error) {
	if state == nil || !state.Resolution.Bridged() || response == nil {
		return response, nil
	}
	chat := response.ChatResponse
	if chat == nil || len(chat.Choices) != 1 || chat.Choices[0].FinishReason == nil ||
		chat.Choices[0].ChatNonStreamResponseChoice == nil || chat.Choices[0].ChatNonStreamResponseChoice.Message == nil {
		return nil, ErrProviderResponseMalformed
	}
	status, incomplete, err := bridgedStatus(*chat.Choices[0].FinishReason)
	if err != nil {
		return nil, err
	}
	message := chat.Choices[0].ChatNonStreamResponseChoice.Message
	assistant := &schemas.ChatAssistantMessage{}
	if message.ChatAssistantMessage != nil {
		assistant = message.ChatAssistantMessage
	}
	reply := newBridgedReply(state, chat.ID)
	output := make([]schemas.ResponsesMessage, 0, 2+len(assistant.ToolCalls))
	reasoning, err := bridgedReasoning(assistant.ReasoningDetails)
	if err != nil {
		return nil, err
	}
	if reasoning != "" {
		output = append(output, reply.reasoningItem(len(output), schemas.ResponsesResponseStatusCompleted, reasoning))
	}
	texts := chatReplyTexts(message.Content, assistant.Refusal)
	if len(texts) > 0 {
		output = append(output, reply.messageItem(len(output), schemas.ResponsesResponseStatusCompleted, texts))
	}
	for _, call := range assistant.ToolCalls {
		if call.ID == nil || call.Function.Name == nil {
			return nil, ErrProviderResponseMalformed
		}
		output = append(output, reply.callItem(len(output), schemas.ResponsesResponseStatusCompleted,
			*call.ID, *call.Function.Name, call.Function.Arguments))
	}
	// A reply cut short leaves its last item incomplete. Calls end a reply only when it completes.
	if status == schemas.ResponsesResponseStatusIncomplete && len(output) > 0 {
		output[len(output)-1].Status = schemas.Ptr(schemas.ResponsesResponseStatusIncomplete)
	}
	converted := &schemas.BifrostResponsesResponse{
		ID:                schemas.Ptr(reply.id),
		Object:            "response",
		CreatedAt:         chat.Created,
		Model:             chat.Model,
		Status:            &status,
		IncompleteDetails: incomplete,
		Output:            output,
		ServiceTier:       chat.ServiceTier,
		Speed:             chat.Speed,
		InferenceGeo:      chat.InferenceGeo,
	}
	if chat.Usage != nil {
		converted.Usage = chat.Usage.ToResponsesResponseUsage()
	}
	if status == schemas.ResponsesResponseStatusCompleted {
		converted.CompletedAt = completedAt(chat.Created)
	}
	if err := validateProviderResponsesResponse(reply.checks, converted); err != nil {
		return nil, err
	}
	return &schemas.BifrostResponse{ResponsesResponse: converted}, nil
}

// chatReplyTexts are the parts of a reply's message: its text and refusal, with adjacent text of
// one kind joined and empty text left out.
func chatReplyTexts(content *schemas.ChatMessageContent, refusal *string) []bridgedText {
	var texts []bridgedText
	add := func(isRefusal bool, text string) {
		if text == "" {
			return
		}
		if last := len(texts) - 1; last >= 0 && texts[last].refusal == isRefusal {
			texts[last].text += text
			return
		}
		texts = append(texts, bridgedText{refusal: isRefusal, text: text})
	}
	if content != nil {
		if content.ContentStr != nil {
			add(false, *content.ContentStr)
		}
		for _, block := range content.ContentBlocks {
			switch {
			case block.Type == schemas.ChatContentBlockTypeText && block.Text != nil:
				add(false, *block.Text)
			case block.Type == schemas.ChatContentBlockTypeRefusal && block.Refusal != nil:
				add(true, *block.Refusal)
			}
		}
	}
	if refusal != nil {
		add(true, *refusal)
	}
	return texts
}

// BridgedStream converts the Chat Completions stream of a bridged request into the Responses
// events that its client gets. A reply's reasoning and message stay open until the provider ends
// it, so that text that a model writes between or after its calls joins the message that precedes
// them, as in a unary reply. A client can then send the reply back with each call's result after
// the calls, which the Responses checks require.
type BridgedStream struct {
	state   *State
	reply   bridgedReply
	started bool
	ended   bool
	// sequence numbers the next event.
	sequence int
	// The response that the events describe.
	createdAt    int
	model        string
	serviceTier  *schemas.BifrostServiceTier
	speed        *string
	inferenceGeo *string
	status       string
	incomplete   *schemas.ResponsesResponseIncompleteDetails
	usage        *schemas.BifrostLLMUsage
	// items are the output items in their order. reasoning and message are the open items that
	// take the next text of their kind, and calls holds the call items by the index of their Chat
	// Completions call.
	items     []*bridgedItem
	reasoning *bridgedItem
	message   *bridgedItem
	calls     map[uint16]*bridgedItem
	events    []*schemas.BifrostResponsesStreamResponse
}

// bridgedItem is an output item of a stream: its parts, or the name and arguments of its call.
// A reasoning item has one part. Every part but a message's last one is done.
type bridgedItem struct {
	index     int
	kind      schemas.ResponsesMessageType
	status    string
	done      bool
	parts     []*bridgedPart
	callID    string
	name      string
	arguments strings.Builder
}

type bridgedPart struct {
	refusal bool
	text    strings.Builder
}

// NewBridgedStream returns the converter of a bridged request's stream, or nil for any other
// request.
func NewBridgedStream(state *State) *BridgedStream {
	if state == nil || !state.Resolution.Bridged() {
		return nil
	}
	return &BridgedStream{state: state, calls: map[uint16]*bridgedItem{}}
}

// Convert returns the events of a chunk that the request's state took. The chunk that completes
// the provider's stream with its usage ends the events with response.completed or
// response.incomplete.
func (s *BridgedStream) Convert(chunk *schemas.BifrostChatResponse) ([]*schemas.BifrostResponsesStreamResponse, error) {
	if s == nil || chunk == nil {
		return nil, nil
	}
	if s.ended {
		return nil, ErrProviderResponseMalformed
	}
	s.events = nil
	if !s.started {
		s.started = true
		s.reply = newBridgedReply(s.state, chunk.ID)
		s.createdAt, s.model = chunk.Created, chunk.Model
	}
	if chunk.ServiceTier != nil {
		s.serviceTier = chunk.ServiceTier
	}
	if chunk.Speed != nil {
		s.speed = chunk.Speed
	}
	if chunk.InferenceGeo != nil {
		s.inferenceGeo = chunk.InferenceGeo
	}
	if s.sequence == 0 {
		s.emit(&schemas.BifrostResponsesStreamResponse{
			Type: schemas.ResponsesStreamResponseTypeCreated, Response: s.response(schemas.ResponsesResponseStatusInProgress),
		})
		s.emit(&schemas.BifrostResponsesStreamResponse{
			Type: schemas.ResponsesStreamResponseTypeInProgress, Response: s.response(schemas.ResponsesResponseStatusInProgress),
		})
	}
	if chunk.Usage != nil {
		s.usage = chunk.Usage
	}
	for _, choice := range chunk.Choices {
		if choice.ChatStreamResponseChoice == nil || choice.ChatStreamResponseChoice.Delta == nil {
			return nil, ErrProviderResponseMalformed
		}
		delta := choice.ChatStreamResponseChoice.Delta
		reasoning, err := bridgedReasoning(delta.ReasoningDetails)
		if err != nil {
			return nil, err
		}
		if reasoning != "" {
			s.writeReasoning(reasoning)
		}
		if delta.Content != nil && *delta.Content != "" {
			s.writeText(false, *delta.Content)
		}
		if delta.Refusal != nil && *delta.Refusal != "" {
			s.writeText(true, *delta.Refusal)
		}
		for _, call := range delta.ToolCalls {
			if err := s.writeCall(call); err != nil {
				return nil, err
			}
		}
		if choice.FinishReason != nil {
			if err := s.finish(*choice.FinishReason); err != nil {
				return nil, err
			}
		}
	}
	if s.state.chatStreamFinished && s.state.chatStreamUsageEnded {
		s.complete()
	}
	events := s.events
	s.events = nil
	for _, event := range events {
		if err := validateProviderResponsesStream(s.reply.checks, event); err != nil {
			return nil, err
		}
	}
	return events, nil
}

func (s *BridgedStream) emit(event *schemas.BifrostResponsesStreamResponse) {
	event.SequenceNumber = s.sequence
	s.sequence++
	s.events = append(s.events, event)
}

// response is the response that the stream describes, without output.
func (s *BridgedStream) response(status string) *schemas.BifrostResponsesResponse {
	return &schemas.BifrostResponsesResponse{
		ID:           schemas.Ptr(s.reply.id),
		Object:       "response",
		CreatedAt:    s.createdAt,
		Model:        s.model,
		Status:       &status,
		Output:       []schemas.ResponsesMessage{},
		ServiceTier:  s.serviceTier,
		Speed:        s.speed,
		InferenceGeo: s.inferenceGeo,
	}
}

// writeReasoning adds reasoning text. Reasoning ends when text begins, and reasoning that follows
// the text starts an item of its own.
func (s *BridgedStream) writeReasoning(text string) {
	item := s.reasoning
	if item == nil {
		s.end(s.message, schemas.ResponsesResponseStatusCompleted)
		s.message = nil
		item = s.open(schemas.ResponsesMessageTypeReasoning)
		s.reasoning = item
		s.openPart(item, false)
	}
	item.parts[0].text.WriteString(text)
	s.emit(&schemas.BifrostResponsesStreamResponse{
		Type:         schemas.ResponsesStreamResponseTypeReasoningSummaryTextDelta,
		OutputIndex:  schemas.Ptr(item.index),
		ContentIndex: schemas.Ptr(0),
		SummaryIndex: schemas.Ptr(0),
		ItemID:       schemas.Ptr(s.reply.itemID(item.kind, item.index)),
		Delta:        &text,
	})
}

// writeText adds text or refusal to the message. A change between them starts a part.
func (s *BridgedStream) writeText(refusal bool, text string) {
	item := s.message
	if item == nil {
		s.end(s.reasoning, schemas.ResponsesResponseStatusCompleted)
		s.reasoning = nil
		item = s.open(schemas.ResponsesMessageTypeMessage)
		s.message = item
	}
	if last := len(item.parts) - 1; last < 0 || item.parts[last].refusal != refusal {
		if last >= 0 {
			s.closePart(item, last)
		}
		s.openPart(item, refusal)
	}
	index := len(item.parts) - 1
	item.parts[index].text.WriteString(text)
	event := &schemas.BifrostResponsesStreamResponse{
		Type:         schemas.ResponsesStreamResponseTypeOutputTextDelta,
		OutputIndex:  schemas.Ptr(item.index),
		ContentIndex: schemas.Ptr(index),
		ItemID:       schemas.Ptr(s.reply.itemID(item.kind, item.index)),
		Delta:        &text,
	}
	if refusal {
		event.Type = schemas.ResponsesStreamResponseTypeRefusalDelta
	}
	s.emit(event)
}

// writeCall adds a call's delta. The first delta of a call names it.
func (s *BridgedStream) writeCall(call schemas.ChatAssistantMessageToolCall) error {
	item, exists := s.calls[call.Index]
	if !exists {
		if call.ID == nil || call.Function.Name == nil {
			return ErrProviderResponseMalformed
		}
		item = &bridgedItem{
			index: len(s.items), kind: schemas.ResponsesMessageTypeFunctionCall,
			callID: *call.ID, name: *call.Function.Name,
		}
		s.items = append(s.items, item)
		s.calls[call.Index] = item
		s.emit(&schemas.BifrostResponsesStreamResponse{
			Type:        schemas.ResponsesStreamResponseTypeOutputItemAdded,
			OutputIndex: schemas.Ptr(item.index),
			Item:        schemas.Ptr(s.reply.callItem(item.index, schemas.ResponsesResponseStatusInProgress, item.callID, item.name, "")),
		})
	} else if item.done {
		return ErrProviderResponseMalformed
	}
	if arguments := call.Function.Arguments; arguments != "" {
		item.arguments.WriteString(arguments)
		s.emit(&schemas.BifrostResponsesStreamResponse{
			Type:        schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDelta,
			OutputIndex: schemas.Ptr(item.index),
			ItemID:      schemas.Ptr(s.reply.itemID(item.kind, item.index)),
			Delta:       &arguments,
		})
	}
	return nil
}

// open adds a reasoning or message item.
func (s *BridgedStream) open(kind schemas.ResponsesMessageType) *bridgedItem {
	item := &bridgedItem{index: len(s.items), kind: kind}
	s.items = append(s.items, item)
	added := schemas.ResponsesMessage{
		ID:     schemas.Ptr(s.reply.itemID(kind, item.index)),
		Type:   schemas.Ptr(kind),
		Status: schemas.Ptr(schemas.ResponsesResponseStatusInProgress),
	}
	if kind == schemas.ResponsesMessageTypeReasoning {
		added.ResponsesReasoning = &schemas.ResponsesReasoning{Summary: []schemas.ResponsesReasoningSummary{}}
	} else {
		added.Role = schemas.Ptr(schemas.ResponsesInputMessageRoleAssistant)
		added.Content = &schemas.ResponsesMessageContent{ContentBlocks: []schemas.ResponsesMessageContentBlock{}}
	}
	s.emit(&schemas.BifrostResponsesStreamResponse{
		Type:        schemas.ResponsesStreamResponseTypeOutputItemAdded,
		OutputIndex: schemas.Ptr(item.index),
		Item:        &added,
	})
	return item
}

func (s *BridgedStream) openPart(item *bridgedItem, refusal bool) {
	item.parts = append(item.parts, &bridgedPart{refusal: refusal})
	part := reasoningBlock("")
	if item.kind == schemas.ResponsesMessageTypeMessage {
		part = messageBlock(bridgedText{refusal: refusal})
	}
	s.emit(&schemas.BifrostResponsesStreamResponse{
		Type:         schemas.ResponsesStreamResponseTypeContentPartAdded,
		OutputIndex:  schemas.Ptr(item.index),
		ContentIndex: schemas.Ptr(len(item.parts) - 1),
		ItemID:       schemas.Ptr(s.reply.itemID(item.kind, item.index)),
		Part:         &part,
	})
}

// closePart sends the part's text, then the part.
func (s *BridgedStream) closePart(item *bridgedItem, index int) {
	part := item.parts[index]
	text := part.text.String()
	reference := func(event *schemas.BifrostResponsesStreamResponse) *schemas.BifrostResponsesStreamResponse {
		event.OutputIndex = schemas.Ptr(item.index)
		event.ContentIndex = schemas.Ptr(index)
		event.ItemID = schemas.Ptr(s.reply.itemID(item.kind, item.index))
		return event
	}
	block := reasoningBlock(text)
	switch {
	case item.kind == schemas.ResponsesMessageTypeReasoning:
		s.emit(reference(&schemas.BifrostResponsesStreamResponse{
			Type: schemas.ResponsesStreamResponseTypeReasoningSummaryTextDone, SummaryIndex: schemas.Ptr(0), Text: &text,
		}))
	case part.refusal:
		block = messageBlock(bridgedText{refusal: true, text: text})
		s.emit(reference(&schemas.BifrostResponsesStreamResponse{
			Type: schemas.ResponsesStreamResponseTypeRefusalDone, Refusal: &text,
		}))
	default:
		block = messageBlock(bridgedText{text: text})
		s.emit(reference(&schemas.BifrostResponsesStreamResponse{
			Type: schemas.ResponsesStreamResponseTypeOutputTextDone, Text: &text,
		}))
	}
	s.emit(reference(&schemas.BifrostResponsesStreamResponse{
		Type: schemas.ResponsesStreamResponseTypeContentPartDone, Part: &block,
	}))
}

// end completes an open item: the text of its last part and the part, or the call's arguments,
// then the item. A call completes whatever ended the reply, which a call cannot leave incomplete.
func (s *BridgedStream) end(item *bridgedItem, status string) {
	if item == nil || item.done {
		return
	}
	if item.kind == schemas.ResponsesMessageTypeFunctionCall {
		arguments := item.arguments.String()
		s.emit(&schemas.BifrostResponsesStreamResponse{
			Type:        schemas.ResponsesStreamResponseTypeFunctionCallArgumentsDone,
			OutputIndex: schemas.Ptr(item.index),
			ItemID:      schemas.Ptr(s.reply.itemID(item.kind, item.index)),
			Arguments:   &arguments,
		})
		status = schemas.ResponsesResponseStatusCompleted
	} else {
		s.closePart(item, len(item.parts)-1)
	}
	item.done, item.status = true, status
	s.emit(&schemas.BifrostResponsesStreamResponse{
		Type:        schemas.ResponsesStreamResponseTypeOutputItemDone,
		OutputIndex: schemas.Ptr(item.index),
		Item:        schemas.Ptr(s.final(item)),
	})
}

// final is a done item as the reply returns it.
func (s *BridgedStream) final(item *bridgedItem) schemas.ResponsesMessage {
	switch item.kind {
	case schemas.ResponsesMessageTypeReasoning:
		return s.reply.reasoningItem(item.index, item.status, item.parts[0].text.String())
	case schemas.ResponsesMessageTypeFunctionCall:
		return s.reply.callItem(item.index, item.status, item.callID, item.name, item.arguments.String())
	default:
		texts := make([]bridgedText, 0, len(item.parts))
		for _, part := range item.parts {
			texts = append(texts, bridgedText{refusal: part.refusal, text: part.text.String()})
		}
		return s.reply.messageItem(item.index, item.status, texts)
	}
}

// finish completes the open items, in their order, when the provider gives the reason why the
// reply ended. A reply cut short leaves the item that it was writing incomplete.
func (s *BridgedStream) finish(reason string) error {
	status, incomplete, err := bridgedStatus(reason)
	if err != nil {
		return err
	}
	s.status, s.incomplete = status, incomplete
	for _, item := range s.items {
		s.end(item, status)
	}
	s.reasoning, s.message = nil, nil
	return nil
}

// complete ends the stream with the response and its usage.
func (s *BridgedStream) complete() {
	s.ended = true
	response := s.response(s.status)
	response.IncompleteDetails = s.incomplete
	response.Output = make([]schemas.ResponsesMessage, 0, len(s.items))
	for _, item := range s.items {
		response.Output = append(response.Output, s.final(item))
	}
	if s.usage != nil {
		response.Usage = s.usage.ToResponsesResponseUsage()
	}
	eventType := schemas.ResponsesStreamResponseTypeIncomplete
	if s.status == schemas.ResponsesResponseStatusCompleted {
		eventType = schemas.ResponsesStreamResponseTypeCompleted
		response.CompletedAt = completedAt(s.createdAt)
	}
	s.emit(&schemas.BifrostResponsesStreamResponse{Type: eventType, Response: response})
}
