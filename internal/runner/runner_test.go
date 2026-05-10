package runner

import "testing"

func TestIsAppBundle(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"/Applications/Cursor.app", true},
		{"/Applications/Cursor.app/", true},
		{"/Applications/Codex.app", true},
		{"./MyApp.app", true},
		{"claude", false},
		{"/usr/local/bin/aig", false},
		{"/Applications/Cursor.app/Contents/MacOS/Cursor", false},
		{"", false},
		{".app", true}, // edge case: technically ends in .app
	}
	for _, c := range cases {
		got := isAppBundle(c.path)
		if got != c.want {
			t.Errorf("isAppBundle(%q) = %v, want %v", c.path, got, c.want)
		}
	}
}
