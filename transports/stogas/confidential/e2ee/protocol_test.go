package e2ee

import (
	"bytes"
	"crypto/hpke"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

const (
	testRequestID  = "018f4f70-7c88-7b9a-baf8-31a93d2cf613"
	testBundleHash = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
)

func (s *Session) encodeResponseWithNonce(metadata ResponseMetadata, body []byte, responseNonce [responseNonceSize]byte) ([]byte, error) {
	reader, err := s.newResponseReaderWithNonce(bytes.NewReader(body), metadata, responseNonce)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(reader)
}

func TestRequestRoundTripForEveryRecipient(t *testing.T) {
	keys := make([]hpke.PrivateKey, 3)
	recipients := make([]PublicRecipient, 3)
	for i := range keys {
		keys[i] = generateXWingKey(t)
		recipients[i] = PublicRecipient{PublicKey: keys[i].PublicKey().Bytes()}
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	inner := testInnerRequest()
	body, clientSession, err := SealRequestWithID("POST", "/v1/responses", testRequestID, now.Add(time.Minute), testBundleHash, recipients, inner)
	if err != nil {
		t.Fatal(err)
	}
	seenResponseNonces := make(map[[responseNonceSize]byte]struct{}, len(keys))
	seenResponses := make(map[string]struct{}, len(keys))

	for _, key := range keys {
		opened, serverSession, err := OpenRequest(body, "POST", "/v1/responses", key, now)
		if err != nil {
			t.Fatal(err)
		}
		if opened.APIKey != inner.APIKey || !bytes.Equal(opened.Body, inner.Body) {
			t.Fatalf("opened request = %#v, want %#v", opened, inner)
		}
		response, err := serverSession.EncodeResponse(ResponseMetadata{
			StatusCode:  200,
			ContentType: "application/json",
			Headers:     map[string]string{"X-Stogas-Processed-Hash": strings.Repeat("a", 64)},
		}, []byte(`{"ok":true}`))
		if err != nil {
			t.Fatal(err)
		}
		if len(response) < len(responseMagic)+responseNonceSize || !bytes.Equal(response[:len(responseMagic)], responseMagic) {
			t.Fatal("response is missing its versioned nonce preamble")
		}
		var responseNonce [responseNonceSize]byte
		copy(responseNonce[:], response[len(responseMagic):len(responseMagic)+responseNonceSize])
		if _, duplicate := seenResponseNonces[responseNonce]; duplicate {
			t.Fatal("two recipients reused an E2EE response nonce")
		}
		seenResponseNonces[responseNonce] = struct{}{}
		if _, duplicate := seenResponses[string(response)]; duplicate {
			t.Fatal("two recipients produced the same encrypted response")
		}
		seenResponses[string(response)] = struct{}{}
		decoded, err := clientSession.DecodeResponse(response)
		if err != nil {
			t.Fatal(err)
		}
		if decoded.Metadata.StatusCode != 200 || string(decoded.Body) != `{"ok":true}` {
			t.Fatalf("decoded response = %#v", decoded)
		}
	}
}

func TestRustClientInteropVector(t *testing.T) {
	type interopFixture struct {
		Schema            string           `json:"schema"`
		NowUnixMS         int64            `json:"now_unix_ms"`
		NodePrivateKeyHex string           `json:"node_private_key_hex"`
		Request           json.RawMessage  `json:"request"`
		ExpectedInner     InnerRequest     `json:"expected_inner"`
		ResponseMetadata  ResponseMetadata `json:"response_metadata"`
		ResponseBody      string           `json:"response_body_base64"`
		Response          string           `json:"response_base64"`
	}
	fixtureJSON, err := os.ReadFile("testdata/rust-go-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture interopFixture
	if err := json.Unmarshal(fixtureJSON, &fixture); err != nil {
		t.Fatal(err)
	}
	if fixture.Schema != "stogas.e2ee.interop.v1" {
		t.Fatalf("fixture schema = %q", fixture.Schema)
	}
	privateKeyBytes, err := hex.DecodeString(fixture.NodePrivateKeyHex)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := hpke.MLKEM768X25519().NewPrivateKey(privateKeyBytes)
	if err != nil {
		t.Fatal(err)
	}
	inner, session, err := OpenRequest(
		fixture.Request,
		"POST",
		"/v1/responses",
		privateKey,
		time.UnixMilli(fixture.NowUnixMS).UTC(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if inner.APIKey != fixture.ExpectedInner.APIKey ||
		inner.Accept != fixture.ExpectedInner.Accept ||
		inner.ExtraFields != fixture.ExpectedInner.ExtraFields ||
		!jsonEqual(inner.Body, fixture.ExpectedInner.Body) {
		t.Fatalf("opened Rust request = %#v, want %#v", inner, fixture.ExpectedInner)
	}
	responseBody, err := base64.RawURLEncoding.DecodeString(fixture.ResponseBody)
	if err != nil {
		t.Fatal(err)
	}
	expectedResponse, err := base64.RawURLEncoding.DecodeString(fixture.Response)
	if err != nil {
		t.Fatal(err)
	}
	if len(expectedResponse) < len(responseMagic)+responseNonceSize {
		t.Fatal("interop response is missing its nonce")
	}
	var responseNonce [responseNonceSize]byte
	copy(responseNonce[:], expectedResponse[len(responseMagic):len(responseMagic)+responseNonceSize])
	response, err := session.encodeResponseWithNonce(fixture.ResponseMetadata, responseBody, responseNonce)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(response, expectedResponse) {
		t.Fatal("Go response framing differs from the Rust client vector")
	}
}

func TestOpenRequestRejectsWrongRecipient(t *testing.T) {
	intended := generateXWingKey(t)
	other := generateXWingKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	body, _, err := SealRequestWithID(
		"POST",
		"/v1/chat/completions",
		testRequestID,
		now.Add(time.Minute),
		testBundleHash,
		[]PublicRecipient{{PublicKey: intended.PublicKey().Bytes()}},
		testInnerRequest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := OpenRequest(body, "POST", "/v1/chat/completions", other, now); !errors.Is(err, ErrRecipientNotFound) {
		t.Fatalf("OpenRequest error = %v, want ErrRecipientNotFound", err)
	}
}

func TestOpenRequestRejectsExpiredAndOverlongAcceptanceWindows(t *testing.T) {
	key := generateXWingKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	for _, test := range []struct {
		name      string
		expiresAt time.Time
		openAt    time.Time
	}{
		{name: "expired", expiresAt: now, openAt: now.Add(ClockSkewAllowance + time.Millisecond)},
		{name: "too far", expiresAt: now.Add(MaxAcceptanceWindow + ClockSkewAllowance + time.Millisecond), openAt: now},
	} {
		t.Run(test.name, func(t *testing.T) {
			body, _, err := SealRequestWithID(
				"POST",
				"/v1/chat/completions",
				testRequestID,
				test.expiresAt,
				testBundleHash,
				[]PublicRecipient{{PublicKey: key.PublicKey().Bytes()}},
				testInnerRequest(),
			)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := OpenRequest(body, "POST", "/v1/chat/completions", key, test.openAt); !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("OpenRequest error = %v, want ErrInvalidEnvelope", err)
			}
		})
	}
}

func TestSealRequestRejectsInvalidClientInputs(t *testing.T) {
	key := generateXWingKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	valid := testInnerRequest()
	tooManyRecipients := make([]PublicRecipient, MaxRecipients+1)
	for i := range tooManyRecipients {
		tooManyRecipients[i] = PublicRecipient{PublicKey: generateXWingKey(t).PublicKey().Bytes()}
	}
	tests := []struct {
		name       string
		method     string
		path       string
		requestID  string
		bundleHash string
		recipients []PublicRecipient
		inner      InnerRequest
	}{
		{name: "method", method: "GET", path: "/v1/responses", requestID: testRequestID, bundleHash: testBundleHash, recipients: []PublicRecipient{{PublicKey: key.PublicKey().Bytes()}}, inner: valid},
		{name: "path", method: "POST", path: "/v1/unknown", requestID: testRequestID, bundleHash: testBundleHash, recipients: []PublicRecipient{{PublicKey: key.PublicKey().Bytes()}}, inner: valid},
		{name: "request id", method: "POST", path: "/v1/responses", requestID: "not-a-uuid", bundleHash: testBundleHash, recipients: []PublicRecipient{{PublicKey: key.PublicKey().Bytes()}}, inner: valid},
		{name: "noncanonical request id", method: "POST", path: "/v1/responses", requestID: strings.ToUpper(testRequestID), bundleHash: testBundleHash, recipients: []PublicRecipient{{PublicKey: key.PublicKey().Bytes()}}, inner: valid},
		{name: "bundle hash", method: "POST", path: "/v1/responses", requestID: testRequestID, bundleHash: strings.ToUpper(testBundleHash), recipients: []PublicRecipient{{PublicKey: key.PublicKey().Bytes()}}, inner: valid},
		{name: "no recipients", method: "POST", path: "/v1/responses", requestID: testRequestID, bundleHash: testBundleHash, inner: valid},
		{name: "too many recipients", method: "POST", path: "/v1/responses", requestID: testRequestID, bundleHash: testBundleHash, recipients: tooManyRecipients, inner: valid},
		{name: "duplicate recipient", method: "POST", path: "/v1/responses", requestID: testRequestID, bundleHash: testBundleHash, recipients: []PublicRecipient{{PublicKey: key.PublicKey().Bytes()}, {PublicKey: key.PublicKey().Bytes()}}, inner: valid},
		{name: "invalid recipient", method: "POST", path: "/v1/responses", requestID: testRequestID, bundleHash: testBundleHash, recipients: []PublicRecipient{{PublicKey: []byte("invalid")}}, inner: valid},
		{name: "missing api key", method: "POST", path: "/v1/responses", requestID: testRequestID, bundleHash: testBundleHash, recipients: []PublicRecipient{{PublicKey: key.PublicKey().Bytes()}}, inner: InnerRequest{Body: valid.Body}},
		{name: "api key injection", method: "POST", path: "/v1/responses", requestID: testRequestID, bundleHash: testBundleHash, recipients: []PublicRecipient{{PublicKey: key.PublicKey().Bytes()}}, inner: InnerRequest{APIKey: "sk-test\r\nX-Evil: yes", Body: valid.Body}},
		{name: "api key whitespace", method: "POST", path: "/v1/responses", requestID: testRequestID, bundleHash: testBundleHash, recipients: []PublicRecipient{{PublicKey: key.PublicKey().Bytes()}}, inner: InnerRequest{APIKey: "sk-test two", Body: valid.Body}},
		{name: "api key non-ascii", method: "POST", path: "/v1/responses", requestID: testRequestID, bundleHash: testBundleHash, recipients: []PublicRecipient{{PublicKey: key.PublicKey().Bytes()}}, inner: InnerRequest{APIKey: "sk-test-é", Body: valid.Body}},
		{name: "accept injection", method: "POST", path: "/v1/responses", requestID: testRequestID, bundleHash: testBundleHash, recipients: []PublicRecipient{{PublicKey: key.PublicKey().Bytes()}}, inner: InnerRequest{APIKey: valid.APIKey, Accept: "application/json\r\nX-Evil: yes", Body: valid.Body}},
		{name: "accept control", method: "POST", path: "/v1/responses", requestID: testRequestID, bundleHash: testBundleHash, recipients: []PublicRecipient{{PublicKey: key.PublicKey().Bytes()}}, inner: InnerRequest{APIKey: valid.APIKey, Accept: "application/json\x01", Body: valid.Body}},
		{name: "accept surrounding whitespace", method: "POST", path: "/v1/responses", requestID: testRequestID, bundleHash: testBundleHash, recipients: []PublicRecipient{{PublicKey: key.PublicKey().Bytes()}}, inner: InnerRequest{APIKey: valid.APIKey, Accept: " application/json", Body: valid.Body}},
		{name: "invalid body", method: "POST", path: "/v1/responses", requestID: testRequestID, bundleHash: testBundleHash, recipients: []PublicRecipient{{PublicKey: key.PublicKey().Bytes()}}, inner: InnerRequest{APIKey: valid.APIKey, Body: json.RawMessage(`{`)}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, _, err := SealRequestWithID(
				test.method,
				test.path,
				test.requestID,
				now.Add(time.Minute),
				test.bundleHash,
				test.recipients,
				test.inner,
			); !errors.Is(err, ErrInvalidEnvelope) {
				t.Fatalf("SealRequestWithID error = %v, want ErrInvalidEnvelope", err)
			}
		})
	}
}

func TestOpenRequestAuthenticatesEveryEnvelopeBinding(t *testing.T) {
	key := generateXWingKey(t)
	other := generateXWingKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	body, _, err := SealRequestWithID(
		"POST",
		"/v1/chat/completions",
		testRequestID,
		now.Add(time.Minute),
		testBundleHash,
		[]PublicRecipient{
			{PublicKey: key.PublicKey().Bytes()},
			{PublicKey: other.PublicKey().Bytes()},
		},
		testInnerRequest(),
	)
	if err != nil {
		t.Fatal(err)
	}

	var original outerEnvelope
	if err := json.Unmarshal(body, &original); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*outerEnvelope){
		"request id": func(value *outerEnvelope) {
			value.E2EE.RequestID = "018f4f70-7c88-7b9a-baf8-31a93d2cf614"
		},
		"equivalent noncanonical request id": func(value *outerEnvelope) {
			value.E2EE.RequestID = strings.ToUpper(testRequestID)
		},
		"bundle hash": func(value *outerEnvelope) {
			value.E2EE.BundleSHA256 = strings.Repeat("0", 64)
		},
		"expiry": func(value *outerEnvelope) {
			value.E2EE.ExpiresAtMS++
		},
		"ciphertext": func(value *outerEnvelope) {
			value.E2EE.Ciphertext = flipBase64Byte(t, value.E2EE.Ciphertext)
		},
		"wrapped key": func(value *outerEnvelope) {
			localKeyID := KeyID(key.PublicKey().Bytes())
			for i := range value.E2EE.Recipients {
				if value.E2EE.Recipients[i].KeyID == localKeyID {
					value.E2EE.Recipients[i].WrappedKey = flipBase64Byte(t, value.E2EE.Recipients[i].WrappedKey)
					return
				}
			}
			t.Fatal("local recipient fixture is missing")
		},
		"encapsulated key": func(value *outerEnvelope) {
			localKeyID := KeyID(key.PublicKey().Bytes())
			for i := range value.E2EE.Recipients {
				if value.E2EE.Recipients[i].KeyID == localKeyID {
					value.E2EE.Recipients[i].EncapsulatedKey = flipBase64Byte(t, value.E2EE.Recipients[i].EncapsulatedKey)
					return
				}
			}
			t.Fatal("local recipient fixture is missing")
		},
		"recipient order": func(value *outerEnvelope) {
			value.E2EE.Recipients[0], value.E2EE.Recipients[1] = value.E2EE.Recipients[1], value.E2EE.Recipients[0]
		},
		"recipient removal": func(value *outerEnvelope) {
			value.E2EE.Recipients = value.E2EE.Recipients[:1]
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			value := cloneEnvelope(t, original)
			mutate(&value)
			mutated, err := json.Marshal(value)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, err := OpenRequest(mutated, "POST", "/v1/chat/completions", key, now); err == nil {
				t.Fatal("mutated envelope was accepted")
			}
		})
	}
	if _, _, err := OpenRequest(body, "POST", "/v1/responses", key, now); err == nil {
		t.Fatal("envelope was accepted on a different path")
	}
}

func TestInspectReservesEnvelopeFieldAndLeavesPlainJSONAlone(t *testing.T) {
	for _, test := range []struct {
		body      string
		encrypted bool
		wantError bool
	}{
		{body: `{"model":"gpt-5"}`},
		{body: `not json`},
		{body: `{"stogas_e2ee":{}}`, encrypted: true},
		{body: `{"stogas_e2ee":{},"stogas_e2ee":{}}`, encrypted: true, wantError: true},
	} {
		encrypted, err := Inspect([]byte(test.body))
		if encrypted != test.encrypted || (err != nil) != test.wantError {
			t.Fatalf("Inspect(%q) = (%v, %v)", test.body, encrypted, err)
		}
	}
}

func TestResponseRejectsTamperingAndTruncationButIgnoresPostTerminalData(t *testing.T) {
	key := generateXWingKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	_, session, err := SealRequestWithID(
		"POST",
		"/v1/chat/completions",
		testRequestID,
		now.Add(time.Minute),
		testBundleHash,
		[]PublicRecipient{{PublicKey: key.PublicKey().Bytes()}},
		testInnerRequest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := session.EncodeResponse(ResponseMetadata{StatusCode: 200, ContentType: "text/event-stream"}, bytes.Repeat([]byte("stream-data"), 20_000))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := session.DecodeResponse(encoded); err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte(nil), encoded...)
	tampered[len(tampered)/2] ^= 1
	nonceTampered := append([]byte(nil), encoded...)
	nonceTampered[len(responseMagic)] ^= 1
	unsupportedVersion := append([]byte(nil), encoded...)
	unsupportedVersion[len(responseMagic)-1] = Version + 1
	for name, value := range map[string][]byte{
		"tampered":            tampered,
		"response nonce":      nonceTampered,
		"unsupported version": unsupportedVersion,
		"truncated":           encoded[:len(encoded)-1],
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := session.DecodeResponse(value); err == nil {
				t.Fatal("invalid response was accepted")
			}
		})
	}
	withTrailing := append(append([]byte(nil), encoded...), []byte("ignored outer noise")...)
	decoded, err := session.DecodeResponse(withTrailing)
	if err != nil {
		t.Fatalf("post-terminal bytes changed the response: %v", err)
	}
	if !bytes.Equal(decoded.Body, bytes.Repeat([]byte("stream-data"), 20_000)) {
		t.Fatal("post-terminal bytes changed the authenticated body")
	}
}

func TestResponseReaderStreamsAndClosesSource(t *testing.T) {
	key := generateXWingKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	_, session, err := SealRequestWithID(
		"POST",
		"/v1/responses",
		testRequestID,
		now.Add(time.Minute),
		testBundleHash,
		[]PublicRecipient{{PublicKey: key.PublicKey().Bytes()}},
		testInnerRequest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	source := &trackedReader{Reader: bytes.NewReader(bytes.Repeat([]byte("x"), maxResponseRecordSize+17))}
	reader, err := session.NewResponseReader(source, ResponseMetadata{StatusCode: 200, ContentType: "text/event-stream"})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := io.ReadAll(&shortReader{Reader: reader, limit: 7})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := session.DecodeResponse(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded.Body) != maxResponseRecordSize+17 {
		t.Fatalf("decoded body length = %d", len(decoded.Body))
	}
	if err := reader.Close(); err != nil {
		t.Fatal(err)
	}
	if !source.closed {
		t.Fatal("closing encrypted response reader did not close source")
	}
}

func TestResponseReaderRejectsPermanentlyStalledSource(t *testing.T) {
	_, session := testSession(t)
	reader, err := session.NewResponseReader(stalledReader{}, ResponseMetadata{StatusCode: 200, ContentType: "text/event-stream"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); !errors.Is(err, io.ErrNoProgress) {
		t.Fatalf("ReadAll error = %v, want io.ErrNoProgress", err)
	}
}

func TestResponseReaderEnforcesAggregateBodyLimit(t *testing.T) {
	_, session := testSession(t)
	reader, err := session.NewResponseReader(bytes.NewReader([]byte("x")), ResponseMetadata{StatusCode: 200, ContentType: "application/json"})
	if err != nil {
		t.Fatal(err)
	}
	reader.bodyBytes = MaxResponseBodySize
	if _, err := io.ReadAll(reader); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Fatalf("oversized response error = %v", err)
	}
}

func TestResponseMetadataRejectsHeaderInjectionAndInvalidStatus(t *testing.T) {
	_, session := testSession(t)
	for _, metadata := range []ResponseMetadata{
		{StatusCode: 99, ContentType: "application/json"},
		{StatusCode: 200, ContentType: ""},
		{StatusCode: 200, ContentType: "applicationjson"},
		{StatusCode: 200, ContentType: "application/json\x01"},
		{StatusCode: 200, ContentType: "application/json", Headers: map[string]string{"X-Test\r\nX-Evil": "yes"}},
		{StatusCode: 200, ContentType: "application/json", Headers: map[string]string{"X-Test": "yes\r\nX-Evil: yes"}},
		{StatusCode: 200, ContentType: "application/json", Headers: map[string]string{"X Test": "yes"}},
		{StatusCode: 200, ContentType: "application/json", Headers: map[string]string{"X-Test": "yes\x01"}},
		{StatusCode: 200, ContentType: "application/json", Headers: map[string]string{"X-Test": "one", "x-test": "two"}},
	} {
		if _, err := session.EncodeResponse(metadata, nil); err == nil {
			t.Fatalf("invalid metadata was accepted: %#v", metadata)
		}
	}
}

func TestResponseReaderRejectsAggregateMetadataOverRecordLimit(t *testing.T) {
	_, session := testSession(t)
	headers := make(map[string]string, 5)
	for index := range 5 {
		headers[fmt.Sprintf("X-Large-%d", index)] = strings.Repeat("a", 16*1024)
	}
	reader, err := session.NewResponseReader(bytes.NewReader(nil), ResponseMetadata{
		StatusCode:  200,
		ContentType: "application/json",
		Headers:     headers,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(reader); err == nil || !strings.Contains(err.Error(), "metadata is too large") {
		t.Fatalf("oversized metadata error = %v", err)
	}
}

func TestResponseMetadataDecoderRejectsAmbiguousJSON(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(`{"status":200,"status":401,"content_type":"application/json"}`),
		[]byte(`{"status":200,"content_type":"application/json","unknown":true}`),
		[]byte(`{"status":200,"content_type":"application/json"} null`),
	} {
		if _, err := decodeResponseMetadata(data); err == nil {
			t.Fatalf("ambiguous metadata was accepted: %s", data)
		}
	}
}

func TestJSONScannerRejectsNestedDuplicatesAndTrailingValues(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(`{"outer":{"same":1,"same":2}}`),
		[]byte(`[{"same":1,"same":2}]`),
		[]byte(`{"valid":true} {"trailing":true}`),
	} {
		if err := rejectDuplicateJSONKeys(data); err == nil {
			t.Fatalf("ambiguous JSON was accepted: %s", data)
		}
	}
}

func FuzzOpenRequestNeverPanics(f *testing.F) {
	key, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte(`{"stogas_e2ee":{}}`))
	f.Add([]byte(`{"model":"gpt-5"}`))
	f.Fuzz(func(t *testing.T, body []byte) {
		_, _, _ = OpenRequest(body, "POST", "/v1/chat/completions", key, time.Unix(1_800_000_000, 0))
	})
}

func FuzzDecodeResponseNeverPanics(f *testing.F) {
	_, session := fuzzSession(f)
	valid, err := session.EncodeResponse(
		ResponseMetadata{StatusCode: 200, ContentType: "application/json"},
		[]byte(`{"ok":true}`),
	)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("STGE"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = session.DecodeResponse(data)
	})
}

func testSession(t *testing.T) (hpke.PrivateKey, *Session) {
	t.Helper()
	key := generateXWingKey(t)
	now := time.Unix(1_800_000_000, 0).UTC()
	_, session, err := SealRequestWithID(
		"POST",
		"/v1/responses",
		testRequestID,
		now.Add(time.Minute),
		testBundleHash,
		[]PublicRecipient{{PublicKey: key.PublicKey().Bytes()}},
		testInnerRequest(),
	)
	if err != nil {
		t.Fatal(err)
	}
	return key, session
}

func fuzzSession(f *testing.F) (hpke.PrivateKey, *Session) {
	f.Helper()
	key, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		f.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0).UTC()
	_, session, err := SealRequestWithID(
		"POST",
		"/v1/responses",
		testRequestID,
		now.Add(time.Minute),
		testBundleHash,
		[]PublicRecipient{{PublicKey: key.PublicKey().Bytes()}},
		testInnerRequest(),
	)
	if err != nil {
		f.Fatal(err)
	}
	return key, session
}

func generateXWingKey(t *testing.T) hpke.PrivateKey {
	t.Helper()
	key, err := hpke.MLKEM768X25519().GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func testInnerRequest() InnerRequest {
	return InnerRequest{
		APIKey:      "sk-stogas-test",
		Accept:      "application/json",
		ExtraFields: true,
		Body:        json.RawMessage(`{"model":"gpt-5","input":"hello"}`),
	}
}

func cloneEnvelope(t *testing.T, value outerEnvelope) outerEnvelope {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var clone outerEnvelope
	if err := json.Unmarshal(encoded, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func flipBase64Byte(t *testing.T, value string) string {
	t.Helper()
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) == 0 {
		t.Fatal("invalid fixture base64")
	}
	decoded[len(decoded)/2] ^= 1
	return base64.RawURLEncoding.EncodeToString(decoded)
}

func jsonEqual(left, right []byte) bool {
	var leftValue, rightValue any
	return json.Unmarshal(left, &leftValue) == nil &&
		json.Unmarshal(right, &rightValue) == nil &&
		reflect.DeepEqual(leftValue, rightValue)
}

type trackedReader struct {
	io.Reader
	closed bool
}

func (r *trackedReader) Close() error {
	r.closed = true
	return nil
}

type shortReader struct {
	io.Reader
	limit int
}

type stalledReader struct{}

func (stalledReader) Read([]byte) (int, error) {
	return 0, nil
}

func (r *shortReader) Read(p []byte) (int, error) {
	if len(p) > r.limit {
		p = p[:r.limit]
	}
	return r.Reader.Read(p)
}
