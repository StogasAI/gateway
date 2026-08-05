package chutese2ee

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestSafeReadRetryClassification(t *testing.T) {
	for _, status := range []int{408, 425, 429, 500, 502, 503, 504} {
		if !retryableChutesRead(&httpStatusError{StatusCode: status}, false) {
			t.Fatalf("status %d was not retryable", status)
		}
	}
	for _, status := range []int{400, 401, 403, 409, 422} {
		if retryableChutesRead(&httpStatusError{StatusCode: status}, true) {
			t.Fatalf("status %d was retryable", status)
		}
	}
	if retryableChutesRead(&httpStatusError{StatusCode: 404}, false) ||
		!retryableChutesRead(&httpStatusError{StatusCode: 404}, true) {
		t.Fatal("404 discovery-only retry policy changed")
	}
	for _, err := range []error{io.EOF, io.ErrUnexpectedEOF, &net.DNSError{IsTemporary: true}} {
		if !retryableChutesRead(err, false) {
			t.Fatalf("transient read error was not retryable: %v", err)
		}
	}
	for _, err := range []error{context.Canceled, context.DeadlineExceeded, errors.New("permanent")} {
		if retryableChutesRead(err, true) {
			t.Fatalf("terminal read error was retryable: %v", err)
		}
	}
}

func TestRetryAfterIsBounded(t *testing.T) {
	delay, ok := chutesReadRetryDelay(
		&httpStatusError{StatusCode: http.StatusTooManyRequests, RetryAfter: 2 * time.Second},
		0,
		5*time.Second,
	)
	if !ok || delay != 2*time.Second {
		t.Fatalf("accepted Retry-After delay=%s ok=%t", delay, ok)
	}
	if _, ok := chutesReadRetryDelay(
		&httpStatusError{StatusCode: http.StatusTooManyRequests, RetryAfter: 6 * time.Second},
		0,
		5*time.Second,
	); ok {
		t.Fatal("accepted Retry-After beyond the synchronous delay bound")
	}
}
