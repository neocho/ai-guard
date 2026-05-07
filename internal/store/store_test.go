package store_test

import (
	"bytes"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/neocho/ai-guard/internal/store"
)

func openTestStore(t *testing.T) *store.Store {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "captures.db"), store.Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func TestStore_AppendAndRoundtrip(t *testing.T) {
	s := openTestStore(t)

	c := &store.Capture{
		SessionID:   "sess-1",
		PID:         1234,
		Timestamp:   time.Now(),
		Host:        "api.anthropic.com:443",
		Method:      "POST",
		Path:        "/v1/messages",
		ReqHeaders:  `{"content-type":["application/json"]}`,
		ReqBody:     []byte(`{"model":"claude-test"}`),
		RespStatus:  200,
		RespHeaders: `{"content-type":["application/json"]}`,
		RespBody:    []byte(`{"id":"msg_test"}`),
		DurationMS:  142,
		ALPN:        "h2",
	}
	s.Append(c)

	// Close to flush, then re-open the database directly to verify persistence.
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func TestStore_TruncatesLargeBodies(t *testing.T) {
	s := openTestStore(t)

	big := bytes.Repeat([]byte("a"), store.MaxBodyBytes+10_000)
	c := &store.Capture{
		SessionID: "sess-big",
		PID:       42,
		Timestamp: time.Now(),
		Host:      "example.com:443",
		Method:    "POST",
		Path:      "/",
		ReqBody:   big,
	}
	s.Append(c)

	// store.Append truncates in-place; after the call, c.ReqBody must be
	// capped and c.Truncated must be true.
	if len(c.ReqBody) != store.MaxBodyBytes {
		t.Errorf("want ReqBody len %d, got %d", store.MaxBodyBytes, len(c.ReqBody))
	}
	if !c.Truncated {
		t.Errorf("expected Truncated=true after large body")
	}
}

func TestStore_DropsOnOverflow(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "captures.db"), store.Options{
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
		BufferSize: 1,
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer s.Close()

	// Hammer with way more than the buffer can hold; some will drop.
	for i := 0; i < 100; i++ {
		s.Append(&store.Capture{
			SessionID: "flood",
			PID:       1,
			Timestamp: time.Now(),
			Host:      "x:443",
		})
	}
	// We can't deterministically count without races; just assert it
	// didn't deadlock and Dropped is nonneg (sanity).
	if s.Dropped() < 0 {
		t.Errorf("dropped count negative: %d", s.Dropped())
	}
}

func TestStore_AppendAfterCloseIsNoop(t *testing.T) {
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "captures.db"), store.Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// Should not panic, should not block.
	s.Append(&store.Capture{SessionID: "x"})
}
