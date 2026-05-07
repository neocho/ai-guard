package api_test

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/neocho/ai-guard/internal/api"
	"github.com/neocho/ai-guard/internal/store"
)

func newTestServer(t *testing.T) (*store.Store, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(filepath.Join(dir, "captures.db"), store.Options{
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })

	srv := httptest.NewServer(api.New(s, slog.New(slog.NewTextHandler(io.Discard, nil))).Handler())
	t.Cleanup(srv.Close)
	return s, srv
}

func appendAnthropicCapture(t *testing.T, s *store.Store, sessionID string) {
	t.Helper()
	s.Append(&store.Capture{
		SessionID: sessionID,
		PID:       1234,
		Timestamp: time.Now(),
		Host:      "api.anthropic.com:443",
		Method:    "POST",
		Path:      "/v1/messages",
		ReqHeaders: `{"content-type":["application/json"]}`,
		ReqBody: []byte(`{
			"model": "claude-test",
			"system": "you are helpful",
			"messages": [{"role":"user","content":"hi"}]
		}`),
		RespStatus: 200,
		RespBody: []byte(`{
			"id": "msg_abc",
			"model": "claude-test",
			"content": [{"type":"text","text":"hello"}],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 5, "output_tokens": 1}
		}`),
		DurationMS: 142,
		ALPN:       "h2",
	})
	// Wait briefly for the async writer to flush.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		captures, _ := s.List(t.Context(), 0, 5)
		if len(captures) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("capture didn't land in store within 2s")
}

func TestAPI_Index(t *testing.T) {
	_, srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); ct == "" || ct[:9] != "text/html" {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestAPI_ListCaptures(t *testing.T) {
	s, srv := newTestServer(t)
	appendAnthropicCapture(t, s, "sess-1")
	appendAnthropicCapture(t, s, "sess-2")

	resp, err := http.Get(srv.URL + "/api/captures")
	if err != nil {
		t.Fatalf("GET /api/captures: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	var body struct {
		Items []struct {
			ID       int64  `json:"id"`
			Host     string `json:"host"`
			Provider string `json:"provider"`
		} `json:"items"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Items) != 2 {
		t.Fatalf("items = %d, want 2", len(body.Items))
	}
	if body.Items[0].ID <= body.Items[1].ID {
		t.Errorf("expected newest-first ordering, got %+v", body.Items)
	}
	if body.Items[0].Provider != "anthropic" {
		t.Errorf("Provider = %q, want anthropic", body.Items[0].Provider)
	}
}

func TestAPI_GetCapture_ParsedFields(t *testing.T) {
	s, srv := newTestServer(t)
	appendAnthropicCapture(t, s, "sess-detail")

	// Fetch the id from list.
	resp, err := http.Get(srv.URL + "/api/captures?limit=1")
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	var list struct {
		Items []struct {
			ID int64 `json:"id"`
		} `json:"items"`
	}
	json.NewDecoder(resp.Body).Decode(&list)
	resp.Body.Close()
	if len(list.Items) == 0 {
		t.Fatal("no captures listed")
	}
	id := list.Items[0].ID

	// Detail fetch.
	resp, err = http.Get(srv.URL + "/api/captures/" + jsonNum(id))
	if err != nil {
		t.Fatalf("detail: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}

	var d struct {
		Provider string `json:"provider"`
		Request  struct {
			Model    string `json:"model"`
			System   string `json:"system"`
			Messages []any  `json:"messages"`
		} `json:"request"`
		Response struct {
			ID         string `json:"id"`
			StopReason string `json:"stop_reason"`
			Usage      struct {
				InputTokens int `json:"input_tokens"`
			} `json:"usage"`
		} `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&d); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if d.Provider != "anthropic" {
		t.Errorf("Provider = %q", d.Provider)
	}
	if d.Request.Model != "claude-test" {
		t.Errorf("Request.Model = %q", d.Request.Model)
	}
	if d.Request.System != "you are helpful" {
		t.Errorf("Request.System = %q", d.Request.System)
	}
	if len(d.Request.Messages) != 1 {
		t.Errorf("Request.Messages count = %d, want 1", len(d.Request.Messages))
	}
	if d.Response.ID != "msg_abc" {
		t.Errorf("Response.ID = %q", d.Response.ID)
	}
	if d.Response.StopReason != "end_turn" {
		t.Errorf("Response.StopReason = %q", d.Response.StopReason)
	}
	if d.Response.Usage.InputTokens != 5 {
		t.Errorf("Response.Usage.InputTokens = %d", d.Response.Usage.InputTokens)
	}
}

func TestAPI_GetCapture_NotFound(t *testing.T) {
	_, srv := newTestServer(t)
	resp, err := http.Get(srv.URL + "/api/captures/99999")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

func jsonNum(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
