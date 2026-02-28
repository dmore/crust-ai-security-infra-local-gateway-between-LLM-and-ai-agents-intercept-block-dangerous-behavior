// Package shellutil constructs shell commands via the mvdan.cc/sh AST,
// avoiding manual string concatenation of shell syntax.
package shellutil

import (
	"bytes"
	"errors"
	"fmt"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Command builds a shell command string from a program name and arguments.
// Each part is quoted with syntax.Quote, parsed into an AST Word node,
// assembled into a CallExpr, and printed via syntax.Printer.
func Command(parts ...string) (string, error) {
	if len(parts) == 0 {
		return "", errors.New("empty command")
	}
	words := make([]*syntax.Word, len(parts))
	for i, p := range parts {
		w, err := parseWord(p)
		if err != nil {
			return "", fmt.Errorf("argument %d (%q): %w", i, p, err)
		}
		words[i] = w
	}
	var buf bytes.Buffer
	if err := syntax.NewPrinter().Print(&buf, &syntax.CallExpr{Args: words}); err != nil {
		return "", fmt.Errorf("print: %w", err)
	}
	return buf.String(), nil
}

// parseWord quotes s and parses the result into an AST Word node.
func parseWord(s string) (*syntax.Word, error) {
	q, err := syntax.Quote(s, syntax.LangBash)
	if err != nil {
		return nil, fmt.Errorf("cannot quote: %w", err)
	}
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(q), "")
	if err != nil {
		return nil, fmt.Errorf("parse: %w", err)
	}
	if len(f.Stmts) == 0 {
		return nil, errors.New("empty result")
	}
	call, ok := f.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return nil, errors.New("unexpected AST")
	}
	return call.Args[0], nil
}
