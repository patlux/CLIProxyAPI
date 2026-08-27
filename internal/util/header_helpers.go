package util

import (
	"net/http"
	"strings"
)

// ApplyCustomHeadersFromAttrs applies user-defined headers stored in the provided attributes map.
// Custom headers override built-in defaults when conflicts occur. Values beginning with "$" are
// resolved from clientHeaders and omitted when the corresponding inbound header is unavailable.
func ApplyCustomHeadersFromAttrs(r *http.Request, attrs map[string]string, clientHeaders ...http.Header) {
	if r == nil {
		return
	}
	var inbound http.Header
	if len(clientHeaders) > 0 {
		inbound = clientHeaders[0]
	}
	applyCustomHeaders(r, extractCustomHeaders(attrs, inbound))
}

func extractCustomHeaders(attrs map[string]string, clientHeaders http.Header) map[string]string {
	if len(attrs) == 0 {
		return nil
	}
	headers := make(map[string]string)
	for k, v := range attrs {
		if !strings.HasPrefix(k, "header:") {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(k, "header:"))
		if name == "" {
			continue
		}
		val := strings.TrimSpace(v)
		if val == "" {
			continue
		}
		if strings.HasPrefix(val, "$") {
			source := strings.TrimSpace(strings.TrimPrefix(val, "$"))
			if source == "" || clientHeaders == nil {
				continue
			}
			val = clientHeaders.Get(source)
			if val == "" {
				continue
			}
		}
		headers[name] = val
	}
	if len(headers) == 0 {
		return nil
	}
	return headers
}

func applyCustomHeaders(r *http.Request, headers map[string]string) {
	if r == nil || len(headers) == 0 {
		return
	}
	for k, v := range headers {
		if k == "" || v == "" {
			continue
		}
		// net/http reads Host from req.Host (not req.Header) when writing
		// a real request, so we must mirror it there. Some callers pass
		// synthetic requests (e.g. &http.Request{Header: ...}) and only
		// consume r.Header afterwards, so keep the value in the header
		// map too.
		if http.CanonicalHeaderKey(k) == "Host" {
			r.Host = v
		}
		r.Header.Set(k, v)
	}
}
