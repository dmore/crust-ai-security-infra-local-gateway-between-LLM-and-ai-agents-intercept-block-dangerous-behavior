// schema-check validates that Go plugin types conform to the JSON Schema
// at docs/plugin-protocol.schema.json. Run via go generate.
//
// If validation passes, it writes schema_generated.go with the validation
// timestamp. If CI runs `go generate ./... && git diff --exit-code`, any
// schema drift will cause the generated file to change, failing CI.
package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
)

const (
	schemaPath = "../../docs/plugin-protocol.schema.json"
	outputFile = "schema_generated.go"
)

// Partial JSON Schema representation.
type schemaDoc struct {
	Defs map[string]schemaDef `json:"$defs"`
}

type schemaDef struct {
	Type       string                `json:"type"`
	Required   []string              `json:"required"`
	Properties map[string]schemaProp `json:"properties"`
	Enum       []string              `json:"enum"`
	OneOf      []json.RawMessage     `json:"oneOf"`
}

type schemaProp struct {
	Type json.RawMessage `json:"type"` // string or array of strings
	Ref  string          `json:"$ref"`
}

// structJSONFields extracts json tag names from a Go struct in the AST.
func structJSONFields(dir string, structName string) (map[string]bool, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool { //nolint:staticcheck // simple AST tool, no need for go/packages
		return !strings.HasSuffix(fi.Name(), "_test.go") &&
			!strings.HasSuffix(fi.Name(), "_generated.go")
	}, 0)
	if err != nil {
		return nil, err
	}

	fields := make(map[string]bool)
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.TYPE {
					continue
				}
				for _, spec := range gd.Specs {
					ts, ok := spec.(*ast.TypeSpec)
					if !ok || ts.Name.Name != structName {
						continue
					}
					st, ok := ts.Type.(*ast.StructType)
					if !ok {
						continue
					}
					for _, field := range st.Fields.List {
						if field.Tag == nil {
							continue
						}
						tag := field.Tag.Value
						// Extract json tag value
						_, after, ok0 := strings.Cut(tag, `json:"`)
						if !ok0 {
							continue
						}
						rest := after
						before, _, ok0 := strings.Cut(rest, `"`)
						if !ok0 {
							continue
						}
						jsonTag := before
						name, _, _ := strings.Cut(jsonTag, ",")
						if name != "" && name != "-" {
							fields[name] = true
						}
					}
				}
			}
		}
	}
	return fields, nil
}

// mapKeys extracts string keys from a Go source map literal like
// `var ValidSeverities = map[Severity]bool{...}`.
// Keys may be string literals or identifiers referencing typed string constants.
func mapKeys(dir string, varName string) ([]string, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool { //nolint:staticcheck // simple AST tool, no need for go/packages
		return !strings.HasSuffix(fi.Name(), "_test.go") &&
			!strings.HasSuffix(fi.Name(), "_generated.go")
	}, 0)
	if err != nil {
		return nil, err
	}

	// First pass: collect all string constant values by name.
	consts := make(map[string]string)
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, name := range vs.Names {
						if i < len(vs.Values) {
							bl, ok := vs.Values[i].(*ast.BasicLit)
							if ok && bl.Kind == token.STRING {
								consts[name.Name] = strings.Trim(bl.Value, `"`)
							}
						}
					}
				}
			}
		}
	}

	// Second pass: find the map literal and resolve keys.
	var keys []string
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.VAR {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok || len(vs.Names) == 0 || vs.Names[0].Name != varName {
						continue
					}
					if len(vs.Values) == 0 {
						continue
					}
					cl, ok := vs.Values[0].(*ast.CompositeLit)
					if !ok {
						continue
					}
					for _, elt := range cl.Elts {
						kv, ok := elt.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						switch k := kv.Key.(type) {
						case *ast.BasicLit:
							if k.Kind == token.STRING {
								keys = append(keys, strings.Trim(k.Value, `"`))
							}
						case *ast.Ident:
							if v, ok := consts[k.Name]; ok {
								keys = append(keys, v)
							}
						}
					}
				}
			}
		}
	}
	return keys, nil
}

func main() {
	// Load schema.
	absSchema, err := filepath.Abs(schemaPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "abs path %s: %v\n", schemaPath, err)
		os.Exit(1)
	}
	data, err := os.ReadFile(absSchema)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read schema %s: %v\n", absSchema, err)
		os.Exit(1)
	}
	if !json.Valid(data) {
		fmt.Fprintf(os.Stderr, "schema is not valid JSON\n")
		os.Exit(1)
	}
	var doc schemaDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		fmt.Fprintf(os.Stderr, "unmarshal schema: %v\n", err)
		os.Exit(1)
	}

	var errors []string
	check := func(format string, args ...any) {
		errors = append(errors, fmt.Sprintf(format, args...))
	}

	// Get the directory of the Go source files.
	goDir, err := filepath.Abs(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "abs path: %v\n", err)
		os.Exit(1)
	}
	// ValidSeverities and ValidResponseActions live in internal/rules.
	rulesDir, err := filepath.Abs("../rules")
	if err != nil {
		fmt.Fprintf(os.Stderr, "abs path rules: %v\n", err)
		os.Exit(1)
	}

	// Check struct ↔ schema field conformance.
	typeChecks := []struct {
		goStruct  string
		schemaDef string
	}{
		{"Request", "evaluateRequest"},
		{"RuleSnapshot", "ruleSnapshot"},
		{"InitParams", "initParams"},
	}

	for _, tc := range typeChecks {
		goFields, err := structJSONFields(goDir, tc.goStruct)
		if err != nil {
			check("%s: parse error: %v", tc.goStruct, err)
			continue
		}
		if len(goFields) == 0 {
			check("%s: no json fields found", tc.goStruct)
			continue
		}

		def, ok := doc.Defs[tc.schemaDef]
		if !ok {
			check("schema missing $defs/%s", tc.schemaDef)
			continue
		}

		for name := range goFields {
			if _, ok := def.Properties[name]; !ok {
				check("Go %s.%s not in schema %s", tc.goStruct, name, tc.schemaDef)
			}
		}
		for name := range def.Properties {
			if !goFields[name] {
				check("schema %s.%s not in Go %s", tc.schemaDef, name, tc.goStruct)
			}
		}
	}

	// Check Result (oneOf object variant in evaluateResult).
	resultFields, err := structJSONFields(goDir, "Result")
	if err == nil && len(resultFields) > 0 {
		if evalResult, ok := doc.Defs["evaluateResult"]; ok {
			for _, raw := range evalResult.OneOf {
				var s schemaDef
				if json.Unmarshal(raw, &s) != nil || s.Type != "object" {
					continue
				}
				for name := range resultFields {
					if _, ok := s.Properties[name]; !ok {
						check("Go Result.%s not in schema evaluateResult", name)
					}
				}
				for name := range s.Properties {
					if !resultFields[name] {
						check("schema evaluateResult.%s not in Go Result", name)
					}
				}
			}
		}
	}

	// Check severity enum.
	if sevDef, ok := doc.Defs["severity"]; ok {
		goSev, err := mapKeys(rulesDir, "ValidSeverities")
		if err != nil {
			check("ValidSeverities: parse error: %v", err)
		}
		for _, s := range sevDef.Enum {
			if !slices.Contains(goSev, s) {
				check("schema severity %q not in Go ValidSeverities", s)
			}
		}
		for _, s := range goSev {
			if !slices.Contains(sevDef.Enum, s) {
				check("Go ValidSeverities %q not in schema severity enum", s)
			}
		}
	}

	// Check action enum.
	if actDef, ok := doc.Defs["action"]; ok {
		goAct, err := mapKeys(rulesDir, "ValidResponseActions")
		if err != nil {
			check("ValidResponseActions: parse error: %v", err)
		}
		for _, a := range actDef.Enum {
			if !slices.Contains(goAct, a) {
				check("schema action %q not in Go ValidResponseActions", a)
			}
		}
		for _, a := range goAct {
			if a == "" {
				continue // empty defaults to "block"
			}
			if !slices.Contains(actDef.Enum, a) {
				check("Go ValidResponseActions %q not in schema action enum", a)
			}
		}
	}

	// Check method constants.
	if wireDef, ok := doc.Defs["wireRequest"]; ok {
		type methodConst struct {
			Properties struct {
				Method struct {
					Const string `json:"const"`
				} `json:"method"`
			} `json:"properties"`
		}
		var schemaMethods []string
		for _, raw := range wireDef.OneOf {
			var mc methodConst
			if json.Unmarshal(raw, &mc) == nil && mc.Properties.Method.Const != "" {
				schemaMethods = append(schemaMethods, mc.Properties.Method.Const)
			}
		}

		goConsts, err := constValues(goDir, []string{"MethodInit", "MethodEvaluate", "MethodClose"})
		if err != nil {
			check("method constants: parse error: %v", err)
		}
		for _, m := range schemaMethods {
			if !slices.Contains(goConsts, m) {
				check("schema method %q not in Go constants", m)
			}
		}
		for _, m := range goConsts {
			if !slices.Contains(schemaMethods, m) {
				check("Go method constant %q not in schema", m)
			}
		}
	}

	if len(errors) > 0 {
		fmt.Fprintf(os.Stderr, "schema validation failed:\n")
		for _, e := range errors {
			fmt.Fprintf(os.Stderr, "  - %s\n", e)
		}
		os.Exit(1)
	}

	// Write generated file with validation timestamp.
	out := fmt.Sprintf(`// Code generated by schema-check; DO NOT EDIT.
// Schema validated at %s against docs/plugin-protocol.schema.json.

package plugin
`, time.Now().UTC().Format(time.RFC3339))

	if err := os.WriteFile(outputFile, []byte(out), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", outputFile, err)
		os.Exit(1)
	}

	fmt.Printf("schema validation passed, wrote %s\n", outputFile)
}

// constValues extracts string constant values from Go source.
func constValues(dir string, names []string) ([]string, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool { //nolint:staticcheck // simple AST tool, no need for go/packages
		return !strings.HasSuffix(fi.Name(), "_test.go") &&
			!strings.HasSuffix(fi.Name(), "_generated.go")
	}, 0)
	if err != nil {
		return nil, err
	}

	nameSet := make(map[string]bool, len(names))
	for _, n := range names {
		nameSet[n] = true
	}

	var values []string
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, decl := range file.Decls {
				gd, ok := decl.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, name := range vs.Names {
						if !nameSet[name.Name] {
							continue
						}
						if len(vs.Values) > 0 {
							bl, ok := vs.Values[0].(*ast.BasicLit)
							if ok && bl.Kind == token.STRING {
								values = append(values, strings.Trim(bl.Value, `"`))
							}
						}
					}
				}
			}
		}
	}
	return values, nil
}
