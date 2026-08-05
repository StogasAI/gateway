package utils

import (
	"bytes"
	"context"
	"testing"

	"github.com/maximhq/bifrost/core/schemas"
)

func TestCheckContextAndGetRequestBodyUsesPreparedBodyWithoutConversion(t *testing.T) {
	prepared := []byte(`{"model":"wire-model","messages":[]}`)
	request := &schemas.BifrostChatRequest{Provider: schemas.OpenAI, Model: "request-model"}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, schemas.ChatCompletionRequest)
	if !SetPreparedRequestBody(ctx, schemas.ChatCompletionRequest, request.Provider, request.Model, prepared) {
		t.Fatal("failed to install prepared request")
	}
	converted := false

	body, bifrostErr := CheckContextAndGetRequestBody(ctx, request, func() (RequestBodyWithExtraParams, error) {
		converted = true
		return nil, nil
	})
	if bifrostErr != nil {
		t.Fatalf("CheckContextAndGetRequestBody returned error: %v", bifrostErr)
	}
	if converted {
		t.Fatal("prepared request invoked the provider converter")
	}
	if !bytes.Equal(body, prepared) {
		t.Fatalf("prepared body changed: got %q want %q", body, prepared)
	}
}

func TestCheckContextAndGetRequestBodyIgnoresEmptyPreparedBody(t *testing.T) {
	request := &schemas.BifrostChatRequest{Provider: schemas.OpenAI, Model: "request-model"}
	ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
	if SetPreparedRequestBody(ctx, schemas.ChatCompletionRequest, request.Provider, request.Model, nil) {
		t.Fatal("empty body was installed as prepared request")
	}
	converted := false

	_, bifrostErr := CheckContextAndGetRequestBody(ctx, request, func() (RequestBodyWithExtraParams, error) {
		converted = true
		return &testPreparedRequestBody{}, nil
	})
	if bifrostErr != nil {
		t.Fatalf("CheckContextAndGetRequestBody returned error: %v", bifrostErr)
	}
	if !converted {
		t.Fatal("empty prepared request body bypassed conversion")
	}
}

func TestCheckContextAndGetRequestBodyRejectsStalePreparedIdentity(t *testing.T) {
	for _, test := range []struct {
		name            string
		request         RequestBodyGetter
		httpRequestType schemas.RequestType
	}{
		{name: "provider", request: &schemas.BifrostChatRequest{Provider: schemas.Azure, Model: "request-model"}},
		{name: "model", request: &schemas.BifrostChatRequest{Provider: schemas.OpenAI, Model: "other-model"}},
		{name: "interface", request: &schemas.BifrostResponsesRequest{Provider: schemas.OpenAI, Model: "request-model"}},
		{name: "request type", request: &schemas.BifrostChatRequest{Provider: schemas.OpenAI, Model: "request-model"}, httpRequestType: schemas.ChatCompletionStreamRequest},
		{name: "missing request type", request: &schemas.BifrostChatRequest{Provider: schemas.OpenAI, Model: "request-model"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			ctx := schemas.NewBifrostContext(context.Background(), schemas.NoDeadline)
			SetPreparedRequestBody(ctx, schemas.ChatCompletionRequest, schemas.OpenAI, "request-model", []byte(`{"prepared":true}`))
			if test.httpRequestType != "" {
				ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, test.httpRequestType)
			} else if test.name != "missing request type" {
				ctx.SetValue(schemas.BifrostContextKeyHTTPRequestType, schemas.ChatCompletionRequest)
			}
			converted := false
			_, bifrostErr := CheckContextAndGetRequestBody(ctx, test.request, func() (RequestBodyWithExtraParams, error) {
				converted = true
				return &testPreparedRequestBody{}, nil
			})
			if bifrostErr != nil {
				t.Fatalf("CheckContextAndGetRequestBody returned error: %v", bifrostErr)
			}
			if !converted {
				t.Fatal("stale prepared identity bypassed conversion")
			}
		})
	}
}

type testPreparedRequestBody struct{}

func (*testPreparedRequestBody) GetExtraParams() map[string]interface{} { return nil }
