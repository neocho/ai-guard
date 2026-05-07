// Package api serves a small JSON HTTP API on top of the captures store
// for use by UI shells (web, SwiftUI, Tauri, Electron — whatever). All
// endpoints bind to 127.0.0.1 only.
package api

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/neocho/ai-guard/internal/parse"
	"github.com/neocho/ai-guard/internal/store"
)

// Server is the API HTTP handler. Build with New, mount with Handler().
type Server struct {
	store  *store.Store
	logger *slog.Logger
	mux    *http.ServeMux
}

// New constructs an API Server backed by the given Store. Caller owns
// the Store and is responsible for closing it; this Server does not.
func New(s *store.Store, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	srv := &Server{store: s, logger: logger}
	srv.mux = http.NewServeMux()
	srv.mux.HandleFunc("/", srv.handleIndex)
	srv.mux.HandleFunc("/api/captures", srv.handleListCaptures)
	srv.mux.HandleFunc("/api/captures/", srv.handleGetCapture)
	srv.mux.HandleFunc("/api/stream", srv.handleStream)
	return srv
}

// Handler returns the HTTP handler suitable for http.Server.Handler.
func (s *Server) Handler() http.Handler { return s.mux }

// --- Endpoint: GET / ---

const indexHTML = `<!doctype html>
<title>aig API</title>
<style>body{font-family:-apple-system,system-ui,sans-serif;max-width:48em;margin:3em auto;padding:0 1em;line-height:1.5;color:#222}code{background:#eee;padding:.1em .3em;border-radius:3px}h1{font-size:1.4em}</style>
<h1>aig API</h1>
<p>Local HTTP API for ai-guard captures. Consume from a UI shell (SwiftUI app, Electron, Tauri, web).</p>
<p>Endpoints:</p>
<ul>
<li><code>GET /api/captures</code> — list, newest first. Optional <code>?before_id=N</code> for pagination, <code>?limit=N</code> (default 50, max 200).</li>
<li><code>GET /api/captures/{id}</code> — detail with parsed request + response.</li>
<li><code>GET /api/stream</code> — Server-Sent Events stream of new captures as they arrive.</li>
</ul>
`

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

// --- Endpoint: GET /api/captures ---

type listItem struct {
	ID         int64  `json:"id"`
	SessionID  string `json:"session_id"`
	Timestamp  string `json:"timestamp"`
	PID        int    `json:"pid"`
	Host       string `json:"host"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	RespStatus int    `json:"resp_status"`
	DurationMS int64  `json:"duration_ms"`
	ALPN       string `json:"alpn"`
	ReqSize    int    `json:"req_size"`
	RespSize   int    `json:"resp_size"`
	Truncated  bool   `json:"truncated"`
	Provider   string `json:"provider,omitempty"`
}

type listResponse struct {
	Items []listItem `json:"items"`
}

func (s *Server) handleListCaptures(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	beforeID, _ := strconv.ParseInt(r.URL.Query().Get("before_id"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	captures, err := s.store.List(ctx, beforeID, limit)
	if err != nil {
		s.logger.Error("list captures failed", "err", err)
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}

	items := make([]listItem, 0, len(captures))
	for _, c := range captures {
		items = append(items, captureToListItem(c))
	}
	writeJSON(w, http.StatusOK, listResponse{Items: items})
}

// --- Endpoint: GET /api/captures/{id} ---

type detailResponse struct {
	listItem
	ReqHeaders  json.RawMessage `json:"req_headers,omitempty"`
	ReqBody     string          `json:"req_body,omitempty"`
	ReqBodyB64  string          `json:"req_body_base64,omitempty"`
	RespHeaders json.RawMessage `json:"resp_headers,omitempty"`
	RespBody    string          `json:"resp_body,omitempty"`
	RespBodyB64 string          `json:"resp_body_base64,omitempty"`
	Request     *parse.Request  `json:"request,omitempty"`
	Response    *parse.Response `json:"response,omitempty"`
}

func (s *Server) handleGetCapture(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	idStr := strings.TrimPrefix(r.URL.Path, "/api/captures/")
	id, err := strconv.ParseInt(idStr, 10, 64)
	if err != nil || id <= 0 {
		http.Error(w, "bad id", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	c, err := s.store.Get(ctx, id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}

	parsedReq, parsedResp := dispatchParse(c.Host, c.Path, c.ReqBody, c.RespBody)

	d := detailResponse{
		listItem:    captureToListItem(c),
		ReqHeaders:  json.RawMessage(c.ReqHeaders),
		RespHeaders: json.RawMessage(c.RespHeaders),
		Request:     parsedReq,
		Response:    parsedResp,
	}
	if utf8.Valid(c.ReqBody) {
		d.ReqBody = string(c.ReqBody)
	} else if len(c.ReqBody) > 0 {
		d.ReqBodyB64 = encodeBase64(c.ReqBody)
	}
	if utf8.Valid(c.RespBody) {
		d.RespBody = string(c.RespBody)
	} else if len(c.RespBody) > 0 {
		d.RespBodyB64 = encodeBase64(c.RespBody)
	}
	if d.Provider == "" && parsedReq != nil {
		d.Provider = parsedReq.Provider
	}
	writeJSON(w, http.StatusOK, d)
}

// --- Endpoint: GET /api/stream (SSE) ---

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming unsupported", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)

	cursor, err := s.store.LastID(r.Context())
	if err != nil {
		s.logger.Warn("stream: last id failed", "err", err)
	}

	// Hello event so the client knows it's connected.
	fmt.Fprintf(w, "event: hello\ndata: {\"cursor\": %d}\n\n", cursor)
	flusher.Flush()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
			ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
			items, err := s.store.ListSince(ctx, cursor, 100)
			cancel()
			if err != nil {
				s.logger.Warn("stream: list since failed", "err", err)
				continue
			}
			if len(items) == 0 {
				continue
			}
			for _, c := range items {
				body, err := json.Marshal(captureToListItem(c))
				if err != nil {
					continue
				}
				fmt.Fprintf(w, "event: capture\ndata: %s\n\n", body)
				cursor = c.ID
			}
			flusher.Flush()
		}
	}
}

// --- helpers ---

func captureToListItem(c *store.Capture) listItem {
	return listItem{
		ID:         c.ID,
		SessionID:  c.SessionID,
		Timestamp:  c.Timestamp.UTC().Format(time.RFC3339Nano),
		PID:        c.PID,
		Host:       c.Host,
		Method:     c.Method,
		Path:       c.Path,
		RespStatus: c.RespStatus,
		DurationMS: c.DurationMS,
		ALPN:       c.ALPN,
		ReqSize:    len(c.ReqBody),
		RespSize:   len(c.RespBody),
		Truncated:  c.Truncated,
		Provider:   providerOf(c.Host, c.Path),
	}
}

func providerOf(host, path string) string {
	h := stripPort(host)
	switch {
	case h == "api.anthropic.com" && path == "/v1/messages":
		return parse.ProviderAnthropic
	case h == "api.openai.com" && (path == "/v1/chat/completions" || path == "/v1/responses"):
		return parse.ProviderOpenAI
	}
	return ""
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		// Headers/status already sent; can't surface a clean error.
		_ = err
	}
}

func encodeBase64(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	return base64.StdEncoding.EncodeToString(b)
}
