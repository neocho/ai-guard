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
	"github.com/neocho/ai-guard/internal/paths"
	"github.com/neocho/ai-guard/internal/scanner"
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
	srv.mux.HandleFunc("/api/rules", srv.handleRules)
	srv.mux.HandleFunc("/api/rules/", srv.handleRuleItem)
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
	ID            int64  `json:"id"`
	SessionID     string `json:"session_id"`
	Timestamp     string `json:"timestamp"`
	PID           int    `json:"pid"`
	Host          string `json:"host"`
	Method        string `json:"method"`
	Path          string `json:"path"`
	RespStatus    int    `json:"resp_status"`
	DurationMS    int64  `json:"duration_ms"`
	ALPN          string `json:"alpn"`
	ReqSize       int    `json:"req_size"`
	RespSize      int    `json:"resp_size"`
	Truncated     bool   `json:"truncated"`
	Provider      string `json:"provider,omitempty"`
	FindingsCount int    `json:"findings_count"`
	MaxSeverity   string `json:"max_severity,omitempty"`
	Decision      string `json:"decision,omitempty"`
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
	ReqHeaders  json.RawMessage   `json:"req_headers,omitempty"`
	ReqBody     string            `json:"req_body,omitempty"`
	ReqBodyB64  string            `json:"req_body_base64,omitempty"`
	RespHeaders json.RawMessage   `json:"resp_headers,omitempty"`
	RespBody    string            `json:"resp_body,omitempty"`
	RespBodyB64 string            `json:"resp_body_base64,omitempty"`
	Request     *parse.Request    `json:"request,omitempty"`
	Response    *parse.Response   `json:"response,omitempty"`
	Findings    []scanner.Finding `json:"findings"`
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

	parsedReq, parsedResp := loadParsedOrDispatch(c)
	parse.NormalizeRequest(parsedReq)
	parse.NormalizeResponse(parsedResp)

	d := detailResponse{
		listItem:    captureToListItem(c),
		ReqHeaders:  json.RawMessage(c.ReqHeaders),
		RespHeaders: json.RawMessage(c.RespHeaders),
		Request:     parsedReq,
		Response:    parsedResp,
		Findings:    decodeFindings(c.Findings),
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

// --- Endpoint: GET /api/rules ---

type rulesResponseItem struct {
	ID          string `json:"id"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
	Direction   string `json:"direction"`
	Action      string `json:"action"`
	Enabled     bool   `json:"enabled"`
}

type rulesResponse struct {
	Rules      []rulesResponseItem `json:"rules"`
	Endpoints  []scanner.Endpoint  `json:"endpoints"`
	ConfigPath string              `json:"config_path"`
}

// handleRules returns the rule set as it lives in YAML — every rule,
// including disabled ones (UI needs to render their toggle state).
func (s *Server) handleRules(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	rulesPath, err := paths.RulesFile()
	if err != nil {
		http.Error(w, "rules path: "+err.Error(), http.StatusInternalServerError)
		return
	}
	cfg, err := scanner.LoadConfigRaw(rulesPath)
	if err != nil {
		s.logger.Warn("rules load failed", "err", err)
		cfg = &scanner.ConfigFile{}
	}

	out := rulesResponse{
		Endpoints:  scanner.ScannableEndpoints(),
		ConfigPath: rulesPath,
		Rules:      []rulesResponseItem{},
	}
	for _, rule := range cfg.Rules {
		enabled := rule.Enabled == nil || *rule.Enabled
		action := rule.Action
		if action == "" {
			action = string(scanner.DefaultAction)
		}
		out.Rules = append(out.Rules, rulesResponseItem{
			ID:          rule.ID,
			Description: rule.Description,
			Severity:    rule.Severity,
			Direction:   rule.Direction,
			Action:      action,
			Enabled:     enabled,
		})
	}
	writeJSON(w, http.StatusOK, out)
}

// handleRuleItem routes per-rule actions:
//
//   POST   /api/rules/{id}/toggle  → flip enabled state
//   DELETE /api/rules/{id}         → remove rule from YAML
func (s *Server) handleRuleItem(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/api/rules/")
	if rest == "" {
		http.NotFound(w, r)
		return
	}

	rulesPath, err := paths.RulesFile()
	if err != nil {
		http.Error(w, "rules path: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Path forms: "{id}" or "{id}/toggle". Use the last "/" to split.
	id := rest
	action := ""
	if i := strings.Index(rest, "/"); i >= 0 {
		id = rest[:i]
		action = rest[i+1:]
	}

	switch {
	case r.Method == http.MethodPost && action == "toggle":
		enabled, err := scanner.ToggleRule(rulesPath, id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "enabled": enabled})

	case r.Method == http.MethodPost && action == "action":
		var body struct {
			Action string `json:"action"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, "bad body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if err := scanner.SetRuleAction(rulesPath, id, body.Action); err != nil {
			// 400 for "invalid action" enum, 404 for missing rule.
			if strings.Contains(err.Error(), "invalid action") {
				http.Error(w, err.Error(), http.StatusBadRequest)
			} else {
				http.Error(w, err.Error(), http.StatusNotFound)
			}
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "action": body.Action})

	case r.Method == http.MethodDelete && action == "":
		if err := scanner.DeleteRule(rulesPath, id); err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"id": id, "deleted": true})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// --- helpers ---

func captureToListItem(c *store.Capture) listItem {
	findings := decodeFindings(c.Findings)
	return listItem{
		ID:            c.ID,
		SessionID:     c.SessionID,
		Timestamp:     c.Timestamp.UTC().Format(time.RFC3339Nano),
		PID:           c.PID,
		Host:          c.Host,
		Method:        c.Method,
		Path:          c.Path,
		RespStatus:    c.RespStatus,
		DurationMS:    c.DurationMS,
		ALPN:          c.ALPN,
		ReqSize:       len(c.ReqBody),
		RespSize:      len(c.RespBody),
		Truncated:     c.Truncated,
		Provider:      providerOf(c.Host, c.Path),
		FindingsCount: len(findings),
		MaxSeverity:   maxSeverity(findings),
		Decision:      c.Decision,
	}
}

// decodeFindings parses the JSON-encoded findings string. Returns empty
// (never nil — Mac client expects [] not null) on missing or invalid.
func decodeFindings(s string) []scanner.Finding {
	if s == "" {
		return []scanner.Finding{}
	}
	var out []scanner.Finding
	if err := json.Unmarshal([]byte(s), &out); err != nil {
		return []scanner.Finding{}
	}
	if out == nil {
		return []scanner.Finding{}
	}
	return out
}

// maxSeverity returns the highest severity among findings, or "" if none.
// Severity order: high > medium > low.
func maxSeverity(fs []scanner.Finding) string {
	rank := map[scanner.Severity]int{
		scanner.SeverityHigh:   3,
		scanner.SeverityMedium: 2,
		scanner.SeverityLow:    1,
	}
	var best scanner.Severity
	bestRank := 0
	for _, f := range fs {
		if rank[f.Severity] > bestRank {
			best = f.Severity
			bestRank = rank[f.Severity]
		}
	}
	return string(best)
}

func providerOf(host, path string) string {
	h := stripPortLocal(host)
	switch {
	case h == "api.anthropic.com" && path == "/v1/messages":
		return parse.ProviderAnthropic
	case h == "api.openai.com" && (path == "/v1/chat/completions" || path == "/v1/responses"):
		return parse.ProviderOpenAI
	}
	return ""
}

// stripPortLocal keeps the (host, _) helper local to this file. Mirror of
// parse.stripPort which is unexported. Trivial enough to duplicate.
func stripPortLocal(host string) string {
	for i := len(host) - 1; i >= 0; i-- {
		if host[i] == ':' {
			return host[:i]
		}
		if host[i] < '0' || host[i] > '9' {
			return host
		}
	}
	return host
}

// loadParsedOrDispatch returns the parsed request/response for c. Prefers
// the eagerly-stored ParsedReq/ParsedResp (proxy-side parse, T-010). Falls
// back to live parsing for legacy rows that predate the columns.
func loadParsedOrDispatch(c *store.Capture) (*parse.Request, *parse.Response) {
	var req *parse.Request
	var resp *parse.Response
	if c.ParsedReq != "" {
		var r parse.Request
		if err := json.Unmarshal([]byte(c.ParsedReq), &r); err == nil {
			req = &r
		}
	}
	if c.ParsedResp != "" {
		var r parse.Response
		if err := json.Unmarshal([]byte(c.ParsedResp), &r); err == nil {
			resp = &r
		}
	}
	if req == nil && resp == nil {
		return parse.Dispatch(c.Host, c.Path, c.ReqBody, c.RespBody)
	}
	return req, resp
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
