package util

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestApplyCustomHeadersFromAttrsResolvesInboundHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://upstream.example", nil)
	attrs := map[string]string{
		"header:X-Session-Affinity": "$X-Session-Affinity",
		"header:X-Static":           "configured",
	}
	inbound := http.Header{"X-Session-Affinity": []string{"pi-session-1"}}

	ApplyCustomHeadersFromAttrs(req, attrs, inbound)

	if got := req.Header.Get("X-Session-Affinity"); got != "pi-session-1" {
		t.Fatalf("X-Session-Affinity = %q, want %q", got, "pi-session-1")
	}
	if got := req.Header.Get("X-Static"); got != "configured" {
		t.Fatalf("X-Static = %q, want %q", got, "configured")
	}
}

func TestApplyCustomHeadersFromAttrsOmitsMissingInboundHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "https://upstream.example", nil)
	attrs := map[string]string{
		"header:X-Session-Affinity": "$X-Session-Affinity",
	}

	ApplyCustomHeadersFromAttrs(req, attrs, http.Header{})

	if got := req.Header.Get("X-Session-Affinity"); got != "" {
		t.Fatalf("X-Session-Affinity = %q, want omitted header", got)
	}
}
