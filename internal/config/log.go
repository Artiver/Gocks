package config

import (
	"log"
	"os"
)

// LogFlags is the timestamp format used by both the standard logger and the
// per-rule loggers.
const LogFlags = log.Ldate | log.Lmicroseconds

// Logger returns a logger whose lines carry this rule's label, so that the
// output of several concurrent listeners stays distinguishable.
func (r Rule) Logger() *log.Logger {
	if r.Label == "" {
		return log.New(os.Stderr, "", LogFlags)
	}
	return log.New(os.Stderr, "[rule "+r.Label+"] ", LogFlags)
}

// LogPrefix prefixes name with the rule label for log lines emitted by the
// shared server accept loop, which uses the standard logger.
func (r Rule) LogPrefix(name string) string {
	if r.Label == "" {
		return name
	}
	return "[rule " + r.Label + "] " + name
}
