package config

import (
	"bytes"
	"strings"
	"testing"
)

func TestRuleLoggerWritesToLogOutput(t *testing.T) {
	var buf bytes.Buffer
	rule := Rule{Label: "1/2", LogOutput: &buf}

	rule.Logger().Print("hello")

	got := buf.String()
	if !strings.Contains(got, "[rule 1/2]") || !strings.Contains(got, "hello") {
		t.Fatalf("log output = %q; want rule label and message", got)
	}
}

func TestRuleLoggerWithoutLabel(t *testing.T) {
	var buf bytes.Buffer
	rule := Rule{LogOutput: &buf}

	rule.Logger().Print("hello")

	got := buf.String()
	if !strings.Contains(got, "hello") {
		t.Fatalf("log output = %q; want message", got)
	}
	if strings.Contains(got, "[rule") {
		t.Fatalf("log output = %q; want no rule label", got)
	}
}
