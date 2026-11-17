package config

import (
	"fmt"
	"os"
	"strings"
	"unicode"
)

// maxArgsFileSize bounds an @file argument list so a wrong path cannot feed an
// unbounded amount of data into the parser.
const maxArgsFileSize = 1 << 20

// ExpandArgs replaces every "@file" argument with the tokens read from that
// file. It runs before flag parsing because the standard library stops parsing
// options at the first non-option argument.
//
// File format: whitespace-separated tokens, '#' starts a comment when it is
// the first character of a token, single or double quotes group tokens with
// spaces, and a trailing backslash continues the line. Nested @file references
// are not expanded.
func ExpandArgs(args []string) ([]string, error) {
	out := make([]string, 0, len(args))
	for _, arg := range args {
		if !strings.HasPrefix(arg, "@") || len(arg) < 2 {
			out = append(out, arg)
			continue
		}

		name := arg[1:]
		info, err := os.Stat(name)
		if err != nil {
			return nil, fmt.Errorf("read args file %q: %w", name, err)
		}
		if info.Size() > maxArgsFileSize {
			return nil, fmt.Errorf("args file %q is larger than %d bytes", name, maxArgsFileSize)
		}
		data, err := os.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("read args file %q: %w", name, err)
		}
		tokens, err := tokenizeArgsFile(name, string(data))
		if err != nil {
			return nil, err
		}
		out = append(out, tokens...)
	}
	return out, nil
}

// tokenizeArgsFile splits an argument file into tokens.
func tokenizeArgsFile(name, text string) ([]string, error) {
	runes := []rune(text)
	var (
		tokens []string
		cur    strings.Builder
		quote  rune
		word   bool
	)
	flushWord := func() {
		if word {
			tokens = append(tokens, cur.String())
			cur.Reset()
			word = false
		}
	}

	for i := 0; i < len(runes); i++ {
		r := runes[i]
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
				continue
			}
			cur.WriteRune(r)
		case r == '\'' || r == '"':
			quote = r
			word = true
		case r == '#' && !word:
			for i < len(runes) && runes[i] != '\n' {
				i++
			}
		case r == '\\' && i+1 < len(runes) && (runes[i+1] == '\n' || runes[i+1] == '\r'):
			if runes[i+1] == '\r' {
				i++
			}
			if i+1 < len(runes) && runes[i+1] == '\n' {
				i++
			}
		case unicode.IsSpace(r):
			flushWord()
		default:
			cur.WriteRune(r)
			word = true
		}
	}

	if quote != 0 {
		return nil, fmt.Errorf("args file %q: unterminated quote", name)
	}
	flushWord()
	return tokens, nil
}
