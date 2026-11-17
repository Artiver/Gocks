package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeArgsFile writes content to a temporary file and returns its path.
func writeArgsFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "rules.args")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// TestExpandArgs verifies the argument file tokenizer: comments, quotes,
// line continuations, and plain arguments passed through untouched.
func TestExpandArgs(t *testing.T) {
	path := writeArgsFile(t, `# full line comment
-L socks5://a:1
-L "socks5://b:2"   # trailing comment
-F "socks5://p:3, http://q:4"
-L socks5://c:5 \
   -F socks5://r:6
# last comment
`)

	got, err := ExpandArgs([]string{"-L", ":1", "@" + path, "--timeout", "1m"})
	if err != nil {
		t.Fatalf("ExpandArgs: %v", err)
	}
	want := []string{
		"-L", ":1",
		"-L", "socks5://a:1",
		"-L", "socks5://b:2",
		"-F", "socks5://p:3, http://q:4",
		"-L", "socks5://c:5",
		"-F", "socks5://r:6",
		"--timeout", "1m",
	}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d\ngot = %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("token %d = %q, want %q", i, got[i], want[i])
		}
	}

	// The expanded argument list must feed the real parser.
	flagArgs := got[:len(got)-2]
	var f Flags
	for i := 0; i < len(flagArgs); i += 2 {
		if flagArgs[i] == "-L" {
			if err := f.Listen().Set(flagArgs[i+1]); err != nil {
				t.Fatalf("Listen: %v", err)
			}
		} else {
			if err := f.Upstream().Set(flagArgs[i+1]); err != nil {
				t.Fatalf("Upstream: %v", err)
			}
		}
	}
	cfg, err := Load(&f, 0)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(cfg.Rules) != 4 {
		t.Errorf("len(Rules) = %d, want 4", len(cfg.Rules))
	}
}

// TestExpandArgsErrors covers a missing file, an oversized file, and an
// unterminated quote.
func TestExpandArgsErrors(t *testing.T) {
	if _, err := ExpandArgs([]string{"@does-not-exist.args"}); err == nil {
		t.Error("missing file err = nil, want error")
	}

	if _, err := tokenizeArgsFile("x.args", "a 'b"); err == nil || !strings.Contains(err.Error(), "unterminated quote") {
		t.Errorf("unterminated quote err = %v, want containing %q", err, "unterminated quote")
	}

	big := writeArgsFile(t, strings.Repeat("a", maxArgsFileSize+1))
	if _, err := ExpandArgs([]string{"@" + big}); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("oversized file err = %v, want containing %q", err, "larger than")
	}
}

// TestExpandArgsPassthrough verifies that normal arguments, including ones
// containing an at sign, are not treated as files.
func TestExpandArgsPassthrough(t *testing.T) {
	args := []string{"-L", "socks5://user@host:1", "-F", "@", "plain"}
	got, err := ExpandArgs(args)
	if err != nil {
		t.Fatalf("ExpandArgs: %v", err)
	}
	if len(got) != len(args) {
		t.Fatalf("len = %d, want %d", len(got), len(args))
	}
	for i := range args {
		if got[i] != args[i] {
			t.Errorf("token %d = %q, want %q", i, got[i], args[i])
		}
	}
}
