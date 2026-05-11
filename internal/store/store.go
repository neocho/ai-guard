// Package store persists intercepted HTTP requests + responses to a local
// SQLite database. Writes are async — the proxy hot path pushes Captures
// onto a buffered channel and a background goroutine drains them. The
// channel drops on overflow so traffic keeps flowing even if disk I/O
// stalls; dropped captures are logged via the supplied logger.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

// Capture is one intercepted request/response pair. ID is populated by
// queries; Append leaves it at zero.
type Capture struct {
	ID          int64
	SessionID   string
	PID         int
	Timestamp   time.Time
	Host        string // e.g. "api.anthropic.com:443"
	Method      string
	Path        string
	ReqHeaders  string // JSON-encoded http.Header
	ReqBody     []byte
	RespStatus  int
	RespHeaders string
	RespBody    []byte
	DurationMS  int64
	ALPN        string // "h2", "http/1.1", or ""
	Truncated   bool   // true if either body was capped at MaxBodyBytes

	// Eager-computed enrichment, set by the proxy before Append:
	//   - Findings:   JSON-encoded []scanner.Finding (or "" / "[]" if none)
	//   - ParsedReq:  JSON-encoded *parse.Request    (or "" if unparseable)
	//   - ParsedResp: JSON-encoded *parse.Response   (or "" if unparseable)
	//   - Decision:   "allowed" | "warned" | "blocked" (or "" for legacy rows)
	//
	// Store doesn't import scanner/parse — the proxy does the encoding so
	// the store stays a dumb byte-bucket. These columns are nullable on
	// disk to allow rows from older versions to coexist.
	Findings   string
	ParsedReq  string
	ParsedResp string
	Decision   string
}

// MaxBodyBytes caps inline body storage. Bodies larger than this are
// truncated and Capture.Truncated is set to true.
const MaxBodyBytes = 1 << 20 // 1 MiB

// Store is an append-only persistent log of Captures.
type Store struct {
	db     *sql.DB
	logger *slog.Logger

	ch     chan *Capture
	wg     sync.WaitGroup
	closed atomic.Bool

	dropped atomic.Int64
}

// Options configures Open.
type Options struct {
	// Logger receives drop/error events. Defaults to slog.Default().
	Logger *slog.Logger
	// BufferSize is the channel depth for pending writes. Defaults to 256.
	BufferSize int
}

// Open opens (or creates) the SQLite database at path, applies the schema,
// and starts the background drain goroutine. Call Close to flush + close.
func Open(path string, opts Options) (*Store, error) {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.BufferSize <= 0 {
		opts.BufferSize = 256
	}

	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping sqlite: %w", err)
	}

	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("apply schema: %w", err)
	}
	if err := migrate(db); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("migrate: %w", err)
	}

	s := &Store{
		db:     db,
		logger: opts.Logger,
		ch:     make(chan *Capture, opts.BufferSize),
	}
	s.wg.Add(1)
	go s.drain()
	return s, nil
}

// Append enqueues c for asynchronous persistence. Non-blocking: if the
// internal buffer is full, the capture is dropped and a warn is logged.
// Append is safe to call from any goroutine. After Close, Append is a
// no-op.
func (s *Store) Append(c *Capture) {
	if s.closed.Load() {
		return
	}
	c = truncate(c)
	select {
	case s.ch <- c:
	default:
		n := s.dropped.Add(1)
		s.logger.Warn("capture dropped (store buffer full)",
			"total_dropped", n, "session_id", c.SessionID)
	}
}

// Close flushes pending writes and closes the underlying database. Subsequent
// Append calls become no-ops.
func (s *Store) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}
	close(s.ch)
	s.wg.Wait()
	return s.db.Close()
}

// Dropped returns the number of captures dropped due to buffer overflow.
func (s *Store) Dropped() int64 {
	return s.dropped.Load()
}

// List returns up to limit captures, newest-first by id. If beforeID > 0,
// only rows with id < beforeID are returned (cursor pagination).
func (s *Store) List(ctx context.Context, beforeID int64, limit int) ([]*Capture, error) {
	var rows *sql.Rows
	var err error
	if beforeID > 0 {
		rows, err = s.db.QueryContext(ctx, listBeforeSQL, beforeID, limit)
	} else {
		rows, err = s.db.QueryContext(ctx, listSQL, limit)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Capture
	for rows.Next() {
		c, err := scanCapture(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListSince returns up to limit captures with id > sinceID, in ascending
// id order. Used by the SSE stream endpoint to push new captures in the
// order they were recorded.
func (s *Store) ListSince(ctx context.Context, sinceID int64, limit int) ([]*Capture, error) {
	rows, err := s.db.QueryContext(ctx, listSinceSQL, sinceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Capture
	for rows.Next() {
		c, err := scanCapture(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Get fetches a single capture by id. Returns sql.ErrNoRows if not found.
func (s *Store) Get(ctx context.Context, id int64) (*Capture, error) {
	row := s.db.QueryRowContext(ctx, getSQL, id)
	c, err := scanCaptureRow(row)
	if err != nil {
		return nil, err
	}
	c.ID = id
	return c, nil
}

// LastID returns the max id in the captures table, or 0 if empty.
func (s *Store) LastID(ctx context.Context) (int64, error) {
	var id sql.NullInt64
	if err := s.db.QueryRowContext(ctx, "SELECT MAX(id) FROM captures").Scan(&id); err != nil {
		return 0, err
	}
	return id.Int64, nil
}

// scannable is the minimal interface satisfied by both *sql.Row and *sql.Rows.
type scannable interface {
	Scan(dest ...any) error
}

func scanCapture(rows *sql.Rows) (*Capture, error) {
	c := &Capture{}
	var ts int64
	var truncated int
	var findings, parsedReq, parsedResp, decision sql.NullString
	if err := rows.Scan(
		&c.ID, &c.SessionID, &c.PID, &ts, &c.Host,
		&c.Method, &c.Path, &c.ReqHeaders, &c.ReqBody,
		&c.RespStatus, &c.RespHeaders, &c.RespBody,
		&c.DurationMS, &c.ALPN, &truncated,
		&findings, &parsedReq, &parsedResp, &decision,
	); err != nil {
		return nil, err
	}
	c.Timestamp = time.Unix(0, ts)
	c.Truncated = truncated != 0
	c.Findings = findings.String
	c.ParsedReq = parsedReq.String
	c.ParsedResp = parsedResp.String
	c.Decision = decision.String
	return c, nil
}

func scanCaptureRow(row *sql.Row) (*Capture, error) {
	c := &Capture{}
	var ts int64
	var truncated int
	var findings, parsedReq, parsedResp, decision sql.NullString
	if err := row.Scan(
		&c.SessionID, &c.PID, &ts, &c.Host,
		&c.Method, &c.Path, &c.ReqHeaders, &c.ReqBody,
		&c.RespStatus, &c.RespHeaders, &c.RespBody,
		&c.DurationMS, &c.ALPN, &truncated,
		&findings, &parsedReq, &parsedResp, &decision,
	); err != nil {
		return nil, err
	}
	c.Timestamp = time.Unix(0, ts)
	c.Truncated = truncated != 0
	c.Findings = findings.String
	c.ParsedReq = parsedReq.String
	c.ParsedResp = parsedResp.String
	c.Decision = decision.String
	return c, nil
}

// Flush blocks until the buffered writes drain to disk. Useful in tests
// after Append-ing rows to ensure they're visible. Production callers
// generally don't need it — Close drains too.
func (s *Store) Flush(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		if len(s.ch) == 0 {
			return nil
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func (s *Store) drain() {
	defer s.wg.Done()
	for c := range s.ch {
		if err := s.write(c); err != nil {
			s.logger.Error("capture write failed",
				"err", err, "session_id", c.SessionID, "host", c.Host)
		}
	}
}

func (s *Store) write(c *Capture) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.db.ExecContext(ctx, insertSQL,
		c.SessionID, c.PID, c.Timestamp.UnixNano(), c.Host,
		c.Method, c.Path, c.ReqHeaders, c.ReqBody,
		c.RespStatus, c.RespHeaders, c.RespBody,
		c.DurationMS, c.ALPN, c.Truncated,
		nullable(c.Findings), nullable(c.ParsedReq), nullable(c.ParsedResp),
		nullable(c.Decision),
	)
	if err != nil {
		return fmt.Errorf("insert: %w", err)
	}
	return nil
}

// nullable maps "" → sql.NullString{} so empty enrichment columns store
// as NULL instead of empty strings (queries can use IS NULL).
func nullable(s string) sql.NullString {
	if s == "" {
		return sql.NullString{}
	}
	return sql.NullString{String: s, Valid: true}
}

// migrate brings older databases up to the current column set. SQLite's
// ALTER TABLE ADD COLUMN can't be made idempotent in pure SQL, so we read
// table_info first and only add what's missing.
func migrate(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(captures)")
	if err != nil {
		return err
	}
	defer rows.Close()
	have := map[string]bool{}
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			return err
		}
		have[name] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	cols := []struct{ name, decl string }{
		{"findings", "TEXT"},
		{"parsed_req", "TEXT"},
		{"parsed_resp", "TEXT"},
		{"decision", "TEXT"},
	}
	for _, c := range cols {
		if have[c.name] {
			continue
		}
		if _, err := db.Exec(fmt.Sprintf("ALTER TABLE captures ADD COLUMN %s %s", c.name, c.decl)); err != nil {
			return fmt.Errorf("add column %s: %w", c.name, err)
		}
	}
	return nil
}

func truncate(c *Capture) *Capture {
	if len(c.ReqBody) > MaxBodyBytes {
		c.ReqBody = c.ReqBody[:MaxBodyBytes]
		c.Truncated = true
	}
	if len(c.RespBody) > MaxBodyBytes {
		c.RespBody = c.RespBody[:MaxBodyBytes]
		c.Truncated = true
	}
	return c
}

// ErrClosed is returned from query helpers when the store is closed.
var ErrClosed = errors.New("store: closed")

const schema = `
CREATE TABLE IF NOT EXISTS captures (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id    TEXT NOT NULL,
    pid           INTEGER NOT NULL,
    ts            INTEGER NOT NULL,
    host          TEXT NOT NULL,
    method        TEXT,
    path          TEXT,
    req_headers   TEXT,
    req_body      BLOB,
    resp_status   INTEGER,
    resp_headers  TEXT,
    resp_body     BLOB,
    duration_ms   INTEGER,
    alpn          TEXT,
    truncated     INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_captures_ts ON captures(ts);
CREATE INDEX IF NOT EXISTS idx_captures_session ON captures(session_id);
`

const insertSQL = `
INSERT INTO captures (
    session_id, pid, ts, host,
    method, path, req_headers, req_body,
    resp_status, resp_headers, resp_body,
    duration_ms, alpn, truncated,
    findings, parsed_req, parsed_resp, decision
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`

const listSQL = `
SELECT id, session_id, pid, ts, host,
       method, path, req_headers, req_body,
       resp_status, resp_headers, resp_body,
       duration_ms, alpn, truncated,
       findings, parsed_req, parsed_resp, decision
FROM captures
ORDER BY id DESC
LIMIT ?
`

const listBeforeSQL = `
SELECT id, session_id, pid, ts, host,
       method, path, req_headers, req_body,
       resp_status, resp_headers, resp_body,
       duration_ms, alpn, truncated,
       findings, parsed_req, parsed_resp, decision
FROM captures
WHERE id < ?
ORDER BY id DESC
LIMIT ?
`

const listSinceSQL = `
SELECT id, session_id, pid, ts, host,
       method, path, req_headers, req_body,
       resp_status, resp_headers, resp_body,
       duration_ms, alpn, truncated,
       findings, parsed_req, parsed_resp, decision
FROM captures
WHERE id > ?
ORDER BY id ASC
LIMIT ?
`

const getSQL = `
SELECT session_id, pid, ts, host,
       method, path, req_headers, req_body,
       resp_status, resp_headers, resp_body,
       duration_ms, alpn, truncated,
       findings, parsed_req, parsed_resp, decision
FROM captures
WHERE id = ?
`
