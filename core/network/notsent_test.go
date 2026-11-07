package network

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/valyala/fasthttp"
)

// A POST that never reached the server goes again on another connection, within
// the same bound as any stale connection; one that may have reached it does not.
func TestStaleConnectionRetryIfErrRetriesAnUnsentPost(t *testing.T) {
	request := fasthttp.AcquireRequest()
	defer fasthttp.ReleaseRequest(request)
	request.Header.SetMethod(http.MethodPost)

	unsent := fmt.Errorf("write request: %w", &NotSentError{Err: errors.New("write: broken pipe")})
	if !RequestNotSent(unsent) {
		t.Fatal("a wrapped NotSentError was not recognised")
	}
	if resetTimeout, retry := StaleConnectionRetryIfErr(request, 1, unsent); !resetTimeout || !retry {
		t.Fatal("an unsent POST was not retried")
	}
	if _, retry := StaleConnectionRetryIfErr(request, maxStaleConnRetries+1, unsent); retry {
		t.Fatal("an unsent POST was retried past the bound")
	}
	if _, retry := StaleConnectionRetryIfErr(request, 1, io.EOF); retry {
		t.Fatal("a POST that may have reached the server was retried")
	}
}
