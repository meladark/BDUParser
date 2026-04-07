package ffi

import (
	"encoding/json"
	"testing"
)

type ffiResponse[T any] struct {
	OK    bool    `json:"ok"`
	Data  *T      `json:"data"`
	Error *string `json:"error"`
}

func TestVersionReturnsString(t *testing.T) {
	version := Version()
	if version == "" {
		t.Fatal("expected non-empty version string")
	}
}

func TestUpdateReturnsJsonErrorForNilURL(t *testing.T) {
	raw := UpdateNil()
	if raw == "" {
		t.Fatal("expected non-empty JSON response")
	}

	var response ffiResponse[map[string]any]
	if err := json.Unmarshal([]byte(raw), &response); err != nil {
		t.Fatalf("expected valid JSON response, got %q: %v", raw, err)
	}

	if response.OK {
		t.Fatalf("expected failure response for nil postgres URL, got success: %s", raw)
	}

	if response.Error == nil || *response.Error == "" {
		t.Fatalf("expected error message in response: %s", raw)
	}

	if response.Data != nil {
		t.Fatalf("expected nil data on error response: %s", raw)
	}
}
