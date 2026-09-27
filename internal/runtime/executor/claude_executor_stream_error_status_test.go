package executor

import (
	"errors"
	"net/http"
	"testing"
)

func TestValidateClaudeStreamingResponseErrorEventStatus(t *testing.T) {
	cases := []struct {
		name    string
		payload string
		want    int
	}{
		{"rate_limit_error type", `{"type":"error","error":{"type":"rate_limit_error","message":"Rate limited"}}`, http.StatusTooManyRequests},
		{"rate limit message only", `{"type":"error","error":{"type":"api_error","message":"Rate-Limit exceeded"}}`, http.StatusTooManyRequests},
		{"overloaded_error", `{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}`, http.StatusServiceUnavailable},
		{"other error", `{"type":"error","error":{"type":"api_error","message":"Internal server error"}}`, http.StatusBadGateway},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateClaudeStreamingResponse([]byte("event: error\ndata: " + tc.payload + "\n\n"))
			var se statusErr
			if !errors.As(err, &se) {
				t.Fatalf("want statusErr, got %T %v", err, err)
			}
			if se.code != tc.want {
				t.Fatalf("status = %d, want %d (%s)", se.code, tc.want, se.msg)
			}
		})
	}
}
