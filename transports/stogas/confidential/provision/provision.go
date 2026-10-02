package provision

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const DefaultMaxResponseBytes = 160 * 1024

type Client struct {
	BaseURL            string
	AccessClientID     string
	AccessClientSecret string
	HTTPClient         *http.Client
	MaxResponseBytes   int64
	AllowInsecureLocal bool
}

type controlError struct {
	Code    string `json:"error,omitempty"`
	Message string `json:"message"`
	Reason  string `json:"reason,omitempty"`
}

type HTTPResponseError struct {
	Code       string
	Message    string
	Path       string
	Reason     string
	StatusCode int
}

func (e *HTTPResponseError) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("control %s rejected request: %s: %s", e.Path, e.Message, e.Reason)
	}
	if e.Message != "" {
		return fmt.Sprintf("control %s rejected request: %s", e.Path, e.Message)
	}
	return fmt.Sprintf("control %s rejected request with status %d", e.Path, e.StatusCode)
}

// IsAuthoritativeRejection identifies failures that end this registration.
// Current policy rejection leaves the same boot unready until approval changes.
func IsAuthoritativeRejection(err error) bool {
	var responseError *HTTPResponseError
	if !errors.As(err, &responseError) {
		return false
	}
	if responseError.StatusCode < 400 || responseError.StatusCode >= 500 {
		return false
	}
	if responseError.StatusCode == http.StatusForbidden {
		switch responseError.Code {
		case "not_approved", "revoked", "key_rejected":
			return false
		}
	}
	switch responseError.StatusCode {
	case http.StatusRequestTimeout, http.StatusTooEarly, http.StatusTooManyRequests:
		return false
	default:
		return true
	}
}

func (c Client) postJSON(ctx context.Context, path string, body any, out any) error {
	endpoint, err := c.endpoint(path)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")
	if strings.TrimSpace(c.AccessClientID) != "" || strings.TrimSpace(c.AccessClientSecret) != "" {
		req.Header.Set("CF-Access-Client-Id", strings.TrimSpace(c.AccessClientID))
		req.Header.Set("CF-Access-Client-Secret", strings.TrimSpace(c.AccessClientSecret))
	}

	httpClient := c.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	safeClient := *httpClient
	safeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return errors.New("control redirects are not permitted")
	}
	resp, err := safeClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	limit := c.MaxResponseBytes
	if limit <= 0 {
		limit = DefaultMaxResponseBytes
	}
	bytes, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return err
	}
	if int64(len(bytes)) > limit {
		return fmt.Errorf("control response exceeded %d bytes", limit)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		controlErr := parseControlError(bytes)
		return &HTTPResponseError{
			Code:       controlErr.Code,
			Message:    controlErr.Message,
			Path:       path,
			Reason:     controlErr.Reason,
			StatusCode: resp.StatusCode,
		}
	}
	decoder := json.NewDecoder(bytesReader(bytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(out); err != nil {
		return fmt.Errorf("decode control %s response: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("decode control %s response: trailing data", path)
	}
	return nil
}

func (c Client) endpoint(path string) (string, error) {
	base, err := url.Parse(strings.TrimSpace(c.BaseURL))
	if err != nil {
		return "", fmt.Errorf("parse control url: %w", err)
	}
	if base.Scheme == "" || base.Host == "" {
		return "", errors.New("control url must be absolute")
	}
	if base.Scheme != "https" && !(c.AllowInsecureLocal && base.Scheme == "http" && isLocalHost(base.Hostname())) {
		return "", errors.New("control url must use https")
	}
	joined := base.ResolveReference(&url.URL{Path: path})
	return joined.String(), nil
}

func parseControlError(bytes []byte) controlError {
	var response controlError
	if err := json.Unmarshal(bytes, &response); err != nil {
		return controlError{}
	}
	return response
}

func isLocalHost(host string) bool {
	return host == "localhost" || host == "127.0.0.1" || host == "::1" || strings.HasSuffix(host, ".localhost")
}

func isLowerHash(value string) bool {
	if len(value) != 64 || value != strings.ToLower(value) {
		return false
	}
	for _, ch := range value {
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'f') {
			return false
		}
	}
	return true
}

func bytesReader(data []byte) *bytes.Reader { return bytes.NewReader(data) }
