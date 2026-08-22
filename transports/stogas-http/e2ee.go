package stogashttp

import (
	"errors"
	"io"
	"strings"
	"time"

	"github.com/maximhq/bifrost/transports/stogas/catalog"
	"github.com/maximhq/bifrost/transports/stogas/confidential/e2ee"
	"github.com/valyala/fasthttp"
)

const e2eeSessionContextKey = "stogas.e2ee_session"

func (s *Server) openEncryptedInference(ctx *fasthttp.RequestCtx) (*e2ee.Session, bool) {
	if len(ctx.URI().QueryString()) != 0 {
		encrypted, err := e2ee.Inspect(ctx.Request.Body())
		if err != nil || encrypted {
			s.writeEncryptedRequestError(ctx)
		} else {
			s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
				"error": map[string]any{"message": "Query parameters are not supported", "type": "invalid_request_error"},
			})
		}
		return nil, false
	}
	if s.secure == nil || s.secure.Identity == nil || s.secure.Identity.HPKEPrivateKey == nil {
		encrypted, err := e2ee.Inspect(ctx.Request.Body())
		if err != nil {
			s.writeEncryptedRequestError(ctx)
			return nil, false
		}
		if !encrypted {
			return nil, true
		}
		s.writeError(ctx, fasthttp.StatusServiceUnavailable, map[string]any{
			"error": map[string]any{"message": "Encrypted inference is unavailable", "type": "service_unavailable"},
		})
		return nil, false
	}
	inner, session, err := e2ee.OpenRequest(
		ctx.Request.Body(),
		string(ctx.Method()),
		string(ctx.Path()),
		s.secure.Identity.HPKEPrivateKey,
		time.Now().UTC(),
	)
	if err != nil {
		if errors.Is(err, e2ee.ErrNotEnvelope) {
			return nil, true
		}
		if errors.Is(err, e2ee.ErrRecipientNotFound) {
			s.writeError(ctx, fasthttp.StatusMisdirectedRequest, map[string]any{
				"error": map[string]any{"message": "Encrypted request is not addressed to this node", "type": "invalid_request_error"},
			})
			return nil, false
		}
		s.writeEncryptedRequestError(ctx)
		return nil, false
	}

	clearInferenceCredentials(ctx)
	clearUpstreamCredentialHeaders(ctx)
	ctx.Request.Header.Set("Authorization", "Bearer "+inner.APIKey)
	ctx.Request.Header.SetContentType("application/json")
	ctx.Request.Header.Del(fasthttp.HeaderContentEncoding)
	ctx.Request.Header.Del(fasthttp.HeaderContentLength)
	if inner.Accept != "" {
		ctx.Request.Header.Set("Accept", inner.Accept)
	} else {
		ctx.Request.Header.Del("Accept")
	}
	if inner.ExtraFields {
		ctx.Request.Header.Set(stogasHeaderExtraFields, "true")
	} else {
		ctx.Request.Header.Del(stogasHeaderExtraFields)
	}
	if inner.UpstreamCredential != nil {
		ctx.Request.Header.Set("X-Stogas-Upstream-API-Key", inner.UpstreamCredential.APIKey)
		ctx.Request.Header.Set("X-Stogas-Upstream-Provider", inner.UpstreamCredential.Provider)
	}
	ctx.Request.SetBodyRaw(append([]byte(nil), inner.Body...))
	ctx.SetUserValue(e2eeSessionContextKey, session)
	return session, true
}

func clearInferenceCredentials(ctx *fasthttp.RequestCtx) {
	for _, route := range []catalog.Route{catalog.RouteChat, catalog.RouteResponses} {
		for _, header := range catalog.AuthHeaderNames(route) {
			ctx.Request.Header.Del(header)
		}
	}
}

func clearUpstreamCredentialHeaders(ctx *fasthttp.RequestCtx) {
	ctx.Request.Header.Del("X-Stogas-Upstream-API-Key")
	ctx.Request.Header.Del("X-Stogas-Upstream-Provider")
}

func (s *Server) writeEncryptedRequestError(ctx *fasthttp.RequestCtx) {
	s.writeError(ctx, fasthttp.StatusBadRequest, map[string]any{
		"error": map[string]any{"message": "Invalid encrypted request", "type": "invalid_request_error"},
	})
}

func encryptedSession(ctx *fasthttp.RequestCtx) *e2ee.Session {
	session, _ := ctx.UserValue(e2eeSessionContextKey).(*e2ee.Session)
	return session
}

func (s *Server) sealBufferedEncryptedResponse(ctx *fasthttp.RequestCtx, session *e2ee.Session) {
	if session == nil || ctx.Response.IsBodyStream() {
		return
	}
	metadata := encryptedResponseMetadata(ctx)
	encoded, err := session.EncodeResponse(metadata, ctx.Response.Body())
	if err != nil {
		ctx.Response.Reset()
		ctx.SetStatusCode(fasthttp.StatusInternalServerError)
		ctx.SetContentType(e2ee.ResponseContentType)
		ctx.Response.Header.Set("Cache-Control", "no-store")
		ctx.Response.Header.Set("X-Stogas-E2EE", "1")
		return
	}
	prepareEncryptedOuterResponse(ctx)
	ctx.Response.SetBodyRaw(encoded)
}

func (s *Server) sealStreamingEncryptedResponse(ctx *fasthttp.RequestCtx, session *e2ee.Session, source io.Reader) error {
	metadata := encryptedResponseMetadata(ctx)
	reader, err := session.NewResponseReader(source, metadata)
	if err != nil {
		return err
	}
	prepareEncryptedOuterResponse(ctx)
	ctx.Response.SetBodyStream(reader, -1)
	return nil
}

func encryptedResponseMetadata(ctx *fasthttp.RequestCtx) e2ee.ResponseMetadata {
	headers := make(map[string]string)
	for key, value := range ctx.Response.Header.All() {
		name := strings.TrimSpace(string(key))
		normalized := strings.ToLower(name)
		if normalized == "cache-control" ||
			strings.HasPrefix(normalized, "x-stogas-") ||
			isSafeProviderResponseHeader(normalized) {
			headers[name] = string(value)
		}
	}
	if len(headers) == 0 {
		headers = nil
	}
	contentType := strings.TrimSpace(string(ctx.Response.Header.ContentType()))
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	return e2ee.ResponseMetadata{
		StatusCode:  ctx.Response.StatusCode(),
		ContentType: contentType,
		Headers:     headers,
	}
}

func prepareEncryptedOuterResponse(ctx *fasthttp.RequestCtx) {
	var remove []string
	for key := range ctx.Response.Header.All() {
		normalized := strings.ToLower(strings.TrimSpace(string(key)))
		if normalized == "cache-control" ||
			normalized == "connection" ||
			normalized == "content-encoding" ||
			strings.HasPrefix(normalized, "x-stogas-") ||
			isSafeProviderResponseHeader(normalized) {
			remove = append(remove, string(key))
		}
	}
	for _, header := range remove {
		ctx.Response.Header.Del(header)
	}
	ctx.SetStatusCode(fasthttp.StatusOK)
	ctx.SetContentType(e2ee.ResponseContentType)
	ctx.Response.Header.Set("Cache-Control", "no-store")
	ctx.Response.Header.Set("X-Stogas-E2EE", "1")
	ctx.Response.Header.Del(fasthttp.HeaderContentLength)
}
