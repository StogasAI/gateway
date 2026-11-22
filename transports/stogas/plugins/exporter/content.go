package exporter

import (
	"bytes"
	"encoding/json"
	"net/url"
	"time"

	"github.com/bytedance/sonic"
	"github.com/maximhq/bifrost/transports/stogas/inputfiles"
	"github.com/maximhq/bifrost/transports/stogas/rawjson"
)

// Input copies the processed request before its pooled storage is released,
// with each inline attachment replaced by its description. The transport has
// already removed policy and encryption credentials.
func (c *Capture) Input(body map[string]json.RawMessage, responses bool) {
	if !c.Active() {
		return
	}
	defer c.measure(time.Now())
	body, err := inputfiles.Describe(body, responses)
	if err != nil {
		c.engine.failed.Add(uint64(len(c.destinations)))
		c.Discard()
		return
	}
	if raw, ok := body["tools"]; ok && responses {
		if tools, ok := omitToolCredentials(raw); ok {
			body["tools"] = tools
		} else {
			delete(body, "tools")
		}
	}
	size := 2
	for key, value := range body {
		size += len(key)*6 + len(value) + 4
	}
	if !c.grow(size) {
		return
	}
	c.request = make([]byte, 0, size)
	c.request = append(c.request, '{')
	for key, value := range body {
		if len(c.request) > 1 {
			c.request = append(c.request, ',')
		}
		name, _ := json.Marshal(key)
		c.request = append(c.request, name...)
		c.request = append(c.request, ':')
		c.request = append(c.request, value...)
	}
	c.request = append(c.request, '}')
}

// Response and Event copy public JSON before response buffers are reused, with each generated
// image replaced by its description.
func (c *Capture) Response(body []byte) {
	if !c.Active() {
		return
	}
	defer c.measure(time.Now())
	body, err := describeGeneratedImages(body)
	if err != nil {
		c.engine.failed.Add(uint64(len(c.destinations)))
		c.Discard()
		return
	}
	if !c.grow(len(body)) {
		return
	}
	clear(c.response)
	c.response = make([]byte, len(body))
	copy(c.response, body)
}
func (c *Capture) Event(body []byte) {
	if !c.Active() {
		return
	}
	defer c.measure(time.Now())
	body, err := describeGeneratedImages(body)
	if err != nil {
		c.engine.failed.Add(uint64(len(c.destinations)))
		c.Discard()
		return
	}
	capacity := cap(c.events)
	next := capacity
	if len(c.events) == capacity {
		next = max(1, capacity*2)
	}
	if !c.grow(len(body) + (next-capacity)*24) {
		return
	}
	if next != capacity {
		events := make([][]byte, len(c.events), next)
		copy(events, c.events)
		c.events = events
	}
	owned := make([]byte, len(body))
	copy(owned, body)
	c.events = append(c.events, owned)
}

// Metadata retains the exact signed object independently of response framing.
func (c *Capture) Metadata(body []byte) {
	if !c.grow(len(body)) {
		return
	}
	clear(c.metadata)
	c.metadata = append([]byte(nil), body...)
}

// describeGeneratedImages replaces each image that image generation made with its description, as
// Input does for the files of a request: the result of each image generation call in a Responses
// response, a stream event's item or its response, and a stream event's partial image. It returns
// body itself when it holds none. The gateway encodes body, which spells each type plainly.
func describeGeneratedImages(body []byte) ([]byte, error) {
	if !bytes.Contains(body, []byte("image_generation_call")) {
		return body, nil
	}
	fields, err := rawjson.Object(body)
	if err != nil {
		return nil, err
	}
	partial := false
	if stringField(fields, "type") == "response.image_generation_call.partial_image" {
		if partial, err = describeImage(fields, "partial_image_b64"); err != nil {
			return nil, err
		}
	}
	// A buffered response holds its output, and a stream event its item or its response.
	output, err := describeOutput(fields)
	if err != nil {
		return nil, err
	}
	item, err := editMember(fields, "item", describeImageCall)
	if err != nil {
		return nil, err
	}
	response, err := editMember(fields, "response", describeOutput)
	if err != nil {
		return nil, err
	}
	if !partial && !output && !item && !response {
		return body, nil
	}
	return sonic.Marshal(fields)
}

// describeOutput describes the image of each image generation call in a response's output.
func describeOutput(response map[string]json.RawMessage) (bool, error) {
	items, err := rawjson.Array(response["output"])
	if err != nil {
		return false, nil
	}
	changed := false
	for index, raw := range items {
		item, err := rawjson.Object(raw)
		if err != nil {
			continue
		}
		described, err := describeImageCall(item)
		if err != nil {
			return false, err
		}
		if !described {
			continue
		}
		if items[index], err = sonic.Marshal(item); err != nil {
			return false, err
		}
		changed = true
	}
	if !changed {
		return false, nil
	}
	response["output"], err = sonic.Marshal(items)
	return err == nil, err
}

// describeImageCall describes the image of an image generation call. A call that failed or that
// max_tool_calls stopped has none.
func describeImageCall(item map[string]json.RawMessage) (bool, error) {
	if stringField(item, "type") != "image_generation_call" {
		return false, nil
	}
	return describeImage(item, "result")
}

// describeImage replaces the base64 image in fields[key] with its description.
func describeImage(fields map[string]json.RawMessage, key string) (bool, error) {
	data := stringField(fields, key)
	if data == "" {
		return false, nil
	}
	description, err := inputfiles.DescribeInline(data, "")
	if err != nil {
		return false, err
	}
	fields[key] = description
	return true, nil
}

// editMember applies edit to the object in fields[key], and re-encodes it when edit changed it.
func editMember(fields map[string]json.RawMessage, key string, edit func(map[string]json.RawMessage) (bool, error)) (bool, error) {
	object, err := rawjson.Object(fields[key])
	if err != nil || object == nil {
		return false, nil
	}
	changed, err := edit(object)
	if err != nil || !changed {
		return false, err
	}
	fields[key], err = sonic.Marshal(object)
	return err == nil, err
}

// stringField returns the string in fields[key], or "".
func stringField(fields map[string]json.RawMessage, key string) string {
	var value string
	_ = sonic.Unmarshal(fields[key], &value)
	return value
}

// omitToolCredentials replaces the authorization and header values of each tool, and keeps only
// the origin of its server URL, where servers also take tokens. A remote MCP tool carries them
// so that the provider can reach its server, and an export must not. It replaces the value of each
// domain secret of a container's network policy too. It reports false when it cannot read the
// tools, and the caller then leaves them out.
func omitToolCredentials(raw json.RawMessage) (json.RawMessage, bool) {
	var tools []map[string]json.RawMessage
	if json.Unmarshal(raw, &tools) != nil {
		return nil, false
	}
	omitted := json.RawMessage(`"[omitted]"`)
	changed := false
	for _, tool := range tools {
		if _, ok := tool["authorization"]; ok {
			tool["authorization"] = omitted
			changed = true
		}
		if value, ok := tool["server_url"]; ok {
			var serverURL string
			if json.Unmarshal(value, &serverURL) != nil {
				return nil, false
			}
			origin, err := json.Marshal(urlOrigin(serverURL))
			if err != nil {
				return nil, false
			}
			tool["server_url"] = origin
			changed = true
		}
		if value, ok := tool["headers"]; ok {
			var headers map[string]json.RawMessage
			if json.Unmarshal(value, &headers) != nil {
				return nil, false
			}
			for name := range headers {
				headers[name] = omitted
			}
			encoded, err := json.Marshal(headers)
			if err != nil {
				return nil, false
			}
			tool["headers"] = encoded
			changed = true
		}
		for _, key := range []string{"container", "environment"} {
			options, omittedSecrets, ok := omitDomainSecrets(tool[key])
			if !ok {
				return nil, false
			}
			if omittedSecrets {
				tool[key] = options
				changed = true
			}
		}
	}
	if !changed {
		return raw, true
	}
	encoded, err := json.Marshal(tools)
	if err != nil {
		return nil, false
	}
	return encoded, true
}

// omitDomainSecrets replaces the value of each domain secret in a container's options. It reports
// whether it replaced any, and false when it cannot read options that hold a network policy.
func omitDomainSecrets(raw json.RawMessage) (json.RawMessage, bool, bool) {
	var options map[string]json.RawMessage
	if json.Unmarshal(raw, &options) != nil || options["network_policy"] == nil {
		// A container's ID or a missing option holds no secret.
		return raw, false, true
	}
	var policy map[string]json.RawMessage
	if json.Unmarshal(options["network_policy"], &policy) != nil {
		return nil, false, false
	}
	if policy["domain_secrets"] == nil {
		return raw, false, true
	}
	var secrets []map[string]json.RawMessage
	if json.Unmarshal(policy["domain_secrets"], &secrets) != nil {
		return nil, false, false
	}
	for _, secret := range secrets {
		// The request checks take a null entry, which holds no secret.
		if secret != nil {
			secret["value"] = json.RawMessage(`"[omitted]"`)
		}
	}
	var err error
	if policy["domain_secrets"], err = json.Marshal(secrets); err != nil {
		return nil, false, false
	}
	if options["network_policy"], err = json.Marshal(policy); err != nil {
		return nil, false, false
	}
	encoded, err := json.Marshal(options)
	return encoded, err == nil, err == nil
}

// urlOrigin returns the scheme, host and port of a URL, or [omitted] when it has none.
func urlOrigin(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "[omitted]"
	}
	return parsed.Scheme + "://" + parsed.Host
}
