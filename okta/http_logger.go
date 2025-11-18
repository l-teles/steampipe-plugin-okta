package okta

import (
	"context"
	"fmt"
	"net/http"

	"github.com/turbot/steampipe-plugin-sdk/v5/plugin"
)

// LoggingRoundTripper wraps an http.RoundTripper and logs all HTTP requests
type LoggingRoundTripper struct {
	wrapped http.RoundTripper
	ctx     context.Context
}

// RoundTrip implements the http.RoundTripper interface with logging
func (l *LoggingRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	logger := plugin.Logger(l.ctx)

	// Log the API call with method and endpoint
	endpoint := fmt.Sprintf("%s %s", req.Method, req.URL.Path)
	if req.URL.RawQuery != "" {
		endpoint = fmt.Sprintf("%s?%s", endpoint, req.URL.RawQuery)
	}

	logger.Info("okta_api_call", "endpoint", endpoint, "method", req.Method, "url", req.URL.String())

	// Execute the actual request
	resp, err := l.wrapped.RoundTrip(req)

	if err != nil {
		logger.Error("okta_api_call_error", "endpoint", endpoint, "error", err)
	} else {
		logger.Info("okta_api_response", "endpoint", endpoint, "status", resp.StatusCode)
	}

	return resp, err
}

// NewLoggingRoundTripper creates a new LoggingRoundTripper
func NewLoggingRoundTripper(ctx context.Context, wrapped http.RoundTripper) *LoggingRoundTripper {
	if wrapped == nil {
		wrapped = http.DefaultTransport
	}
	return &LoggingRoundTripper{
		wrapped: wrapped,
		ctx:     ctx,
	}
}
