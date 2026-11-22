package stogas

import (
	"math"

	"github.com/maximhq/bifrost/core/schemas"
	"github.com/maximhq/bifrost/transports/stogas/plugins"
	"github.com/maximhq/bifrost/transports/stogas/plugins/classification"
	"github.com/maximhq/bifrost/transports/stogas/policy"
)

// replyClassification reads the output text for the classifiers of the pair's policy as it
// arrives, in constant memory: the language classifier samples the start of the reply, and the
// hidden characters classifier counts all output text.
type replyClassification struct {
	sample classification.Sample
	hidden classification.Hidden
	// source is the text that the last piece continued. A piece of another text starts a new
	// line of the sample and a new run of hidden characters.
	source textSource
}

func (c *replyClassification) read(source textSource, text string, sample, count bool) {
	if text == "" {
		return
	}
	if source != c.source {
		c.sample.Break()
		c.hidden.Break()
		c.source = source
	}
	if sample {
		c.sample.Write(text)
	}
	if count {
		c.hidden.Write(text)
	}
}

// replyClassifiers reports which classifiers of the pair's policy read the output.
func (s *State) replyClassifiers() (language, hidden bool) {
	for _, name := range s.Resolution.Classifiers() {
		switch name {
		case policy.ClassifierLanguage:
			language = true
		case policy.ClassifierHiddenCharacters:
			hidden = true
		}
	}
	return language, hidden
}

func (s *State) classifyChatOutput(response *schemas.BifrostChatResponse) {
	language, hidden := s.replyClassifiers()
	if !language && !hidden || response == nil {
		return
	}
	for i := range response.Choices {
		chatOutputText(&response.Choices[i], func(source textSource, text string, reply bool) {
			s.reply.read(source, text, reply && language, hidden)
		})
	}
}

func (s *State) classifyResponsesOutput(response *schemas.BifrostResponsesResponse) {
	language, hidden := s.replyClassifiers()
	if !language && !hidden || response == nil {
		return
	}
	for i := range response.Output {
		responsesItemOutputText(i, &response.Output[i], func(source textSource, text string, reply bool) {
			s.reply.read(source, text, reply && language, hidden)
		})
	}
}

// classifyResponsesStream reads the deltas of a stream, which validation holds to every text of
// its items but a patch's path, which arrives with the call, and the text that a computer call
// types and the prompt that the model wrote for an image, which arrive when the call ends.
func (s *State) classifyResponsesStream(event *schemas.BifrostResponsesStreamResponse) {
	language, hidden := s.replyClassifiers()
	if !language && !hidden || event == nil || event.OutputIndex == nil {
		return
	}
	index := *event.OutputIndex
	if output, reply := responsesOutputDelta(event.Type); output {
		source := textSource{kind: responsesValue, item: index}
		switch {
		case reply && event.ContentIndex != nil:
			source = textSource{kind: responsesPart, item: index, part: *event.ContentIndex}
		case event.CommandIndex != nil:
			source.part = *event.CommandIndex
		}
		s.reply.read(source, stringValue(event.Delta), reply && language, hidden)
		return
	}
	item := event.Item
	if item == nil || item.Type == nil || item.ResponsesToolMessage == nil {
		return
	}
	switch {
	case event.Type == schemas.ResponsesStreamResponseTypeOutputItemAdded:
		if call := item.ResponsesApplyPatchCall; call != nil && call.Operation != nil {
			s.reply.read(textSource{kind: responsesPath, item: index}, call.Operation.Path, false, hidden)
		}
	case event.Type == schemas.ResponsesStreamResponseTypeOutputItemDone && *item.Type == schemas.ResponsesMessageTypeComputerCall:
		for i, action := range providerComputerActions(item.ResponsesToolMessage) {
			s.reply.read(textSource{kind: responsesValue, item: index, part: i}, stringValue(action.Text), false, hidden)
		}
	case event.Type == schemas.ResponsesStreamResponseTypeOutputItemDone && item.ResponsesImageGenerationCall != nil:
		s.reply.read(textSource{kind: responsesValue, item: index}, stringValue(item.ResponsesImageGenerationCall.RevisedPrompt), false, hidden)
	}
}

// pluginMetrics is the request record's plugin section: the pair's, with what the classifiers of
// its policy found in the input and the output.
func (s *State) pluginMetrics() plugins.Metrics {
	metrics := s.PluginMetrics
	classifiers := s.Resolution.Classifiers()
	if len(classifiers) == 0 {
		return metrics
	}
	language, hidden := s.Resolution.InputClassification()
	result := &plugins.ClassificationMetrics{}
	for _, name := range classifiers {
		switch name {
		case policy.ClassifierLanguage:
			result.Language = &plugins.LanguageMetrics{Input: language, Output: s.reply.sample.Language()}
		case policy.ClassifierHiddenCharacters:
			result.HiddenCharacters = &plugins.HiddenCharactersMetrics{
				Input:  uint32(min(hidden, math.MaxUint32)),
				Output: uint32(min(s.reply.hidden.Count(), math.MaxUint32)),
			}
		}
	}
	metrics.Classification = result
	return metrics
}
