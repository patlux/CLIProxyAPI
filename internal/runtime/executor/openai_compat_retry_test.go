package executor

import (
	"net/http"
	"testing"
	"time"
)

func TestOpenAICompatRetryAfterUsesHeaderSeconds(t *testing.T) {
	duration := openAICompatRetryAfter(http.Header{"Retry-After": []string{"90"}}, nil, time.Now())
	if duration == nil || *duration != 90*time.Second {
		t.Fatalf("retry after = %v, want 90s", duration)
	}
}

func TestOpenAICompatRetryAfterUsesRateLimitResetEpoch(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	headers := http.Header{}
	headers.Set("X-RateLimit-Reset", "1700000120")
	duration := openAICompatRetryAfter(headers, nil, now)
	if duration == nil || *duration != 2*time.Minute {
		t.Fatalf("retry after = %v, want 2m", duration)
	}
}

func TestOpenAICompatRetryAfterUsesStructuredMilliseconds(t *testing.T) {
	body := []byte(`{"error":{"retry_after_ms":1250}}`)
	duration := openAICompatRetryAfter(nil, body, time.Now())
	if duration == nil || *duration != 1250*time.Millisecond {
		t.Fatalf("retry after = %v, want 1250ms", duration)
	}
}

func TestOpenAICompatRetryAfterParsesClineInferenceCap(t *testing.T) {
	body := []byte(`{"error":{"code":"INFERENCE_CAP_ERROR","message":"Error 429: Daily free limit reached on model deepseek/deepseek-v4-flash-0731. Try again in 21h 12m"}}`)
	duration := openAICompatRetryAfter(nil, body, time.Now())
	want := 21*time.Hour + 12*time.Minute
	if duration == nil || *duration != want {
		t.Fatalf("retry after = %v, want %s", duration, want)
	}
}

func TestOpenAICompatRetryAfterIgnoresUnrelatedMessage(t *testing.T) {
	body := []byte(`{"error":{"message":"rate limited"}}`)
	if duration := openAICompatRetryAfter(nil, body, time.Now()); duration != nil {
		t.Fatalf("retry after = %v, want nil", *duration)
	}
}
