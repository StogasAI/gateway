package exporter

import (
	"context"
	"encoding/json"
	"reflect"
	"testing"
)

// An export describes each image that image generation made, as it describes the files of a
// request: in a buffered response, and in a stream's partial images, done items and completed
// response. A call that max_tool_calls stopped has no image, and other content stays as sent.
func TestCapturedResponsesDescribeGeneratedImages(t *testing.T) {
	const (
		image     = `{"size":5,"sha256":"2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"}`
		generated = `{"id":"ig_1","type":"image_generation_call","status":"completed","output_format":"webp","result":"aGVsbG8=","revised_prompt":"A red circle"}`
		described = `{"id":"ig_1","type":"image_generation_call","status":"completed","output_format":"webp","result":` + image + `,"revised_prompt":"A red circle"}`
		stopped   = `{"id":"ig_2","type":"image_generation_call","status":"generating"}`
		message   = `{"type":"message","role":"assistant","content":[{"type":"output_text","text":"aGVsbG8="}]}`
	)
	e := New(context.Background(), testOptions(true, 16<<20))
	defer e.Close()
	c := e.Start(testConfig("https://example.com/webhook"), "id", "", Trace{})
	defer c.Discard()
	c.Response([]byte(`{"id":"resp_1","output":[` + generated + `,` + stopped + `,` + message + `]}`))
	same(t, c.response, `{"id":"resp_1","output":[`+described+`,`+stopped+`,`+message+`]}`)

	for _, test := range []struct{ event, want string }{
		{`{"type":"response.output_item.added","output_index":0,"item":` + stopped + `}`, `{"type":"response.output_item.added","output_index":0,"item":` + stopped + `}`},
		{`{"type":"response.image_generation_call.partial_image","output_index":0,"partial_image_b64":"aGVsbG8=","partial_image_index":0,"output_format":"webp"}`,
			`{"type":"response.image_generation_call.partial_image","output_index":0,"partial_image_b64":` + image + `,"partial_image_index":0,"output_format":"webp"}`},
		{`{"type":"response.output_item.done","output_index":0,"item":` + generated + `}`, `{"type":"response.output_item.done","output_index":0,"item":` + described + `}`},
		{`{"type":"response.completed","response":{"output":[` + generated + `,` + message + `]}}`, `{"type":"response.completed","response":{"output":[` + described + `,` + message + `]}}`},
		{`{"type":"response.output_text.delta","output_index":1,"delta":"image_generation_call"}`, `{"type":"response.output_text.delta","output_index":1,"delta":"image_generation_call"}`},
	} {
		c.Event([]byte(test.event))
		same(t, c.events[len(c.events)-1], test.want)
	}

	// An image that is not base64 discards the capture, which no destination then gets.
	failed := e.Diagnostics().Failed
	c.Event([]byte(`{"type":"response.output_item.done","output_index":0,"item":{"type":"image_generation_call","result":"@@@@"}}`))
	if c.Active() || e.Diagnostics().Failed != failed+1 {
		t.Fatalf("capture active %v, diagnostics %+v", c.Active(), e.Diagnostics())
	}
}

// same fails unless got and want are the same JSON.
func same(t *testing.T, got []byte, want string) {
	t.Helper()
	var left, right any
	if err := json.Unmarshal(got, &left); err != nil {
		t.Fatalf("captured %s: %v", got, err)
	}
	if err := json.Unmarshal([]byte(want), &right); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(left, right) {
		t.Fatalf("captured %s, want %s", got, want)
	}
}
