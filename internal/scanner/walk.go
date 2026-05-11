package scanner

import (
	"encoding/json"
	"fmt"
)

// ScanJSON walks a JSON document and scans every string leaf, tagging
// each finding with its JSON path (e.g. "req.messages[0].content").
// Schema-agnostic — new fields the parser doesn't know about still get
// scanned, since we walk the raw decoded tree, not a typed struct.
//
// Returns nil on empty input or parse failure (parse failure is silent
// because we'd rather scan as much as we can than crash on a single
// malformed body; the proxy still forwards the request either way).
func (s *Scanner) ScanJSON(data []byte, dir Direction, basePath string) []Finding {
	if len(data) == 0 {
		return nil
	}
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil
	}
	var out []Finding
	walkJSON(root, basePath, func(value, path string) {
		out = append(out, s.Scan([]byte(value), dir, path)...)
	})
	return out
}

// walkJSON recursively visits every string leaf in v. path is the
// accumulated JSON-pointer-style path; visit gets (string-value, path)
// for each leaf.
func walkJSON(v any, path string, visit func(value, path string)) {
	switch x := v.(type) {
	case string:
		visit(x, path)
	case map[string]any:
		for k, child := range x {
			walkJSON(child, path+"."+k, visit)
		}
	case []any:
		for i, child := range x {
			walkJSON(child, fmt.Sprintf("%s[%d]", path, i), visit)
		}
	}
}
