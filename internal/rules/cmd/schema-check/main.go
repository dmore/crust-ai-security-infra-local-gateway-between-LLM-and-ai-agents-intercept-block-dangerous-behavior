// schema-check validates that Go rule types conform to the JSON Schema
// at docs/rules.schema.json. Run via go generate.
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
	schemaPath = "../../docs/rules.schema.json"
	outputFile = "schema_generated.go"
)

// Partial JSON Schema representation.
type schemaDoc struct {
	Defs map[string]schemaDef `json:"$defs"`
}

type schemaDef struct {
	Type       string                `json:"type"`
	Properties map[string]schemaProp `json:"properties"`
	Enum       []string              `json:"enum"`
	OneOf      []json.RawMessage     `json:"oneOf"`
	AnyOf      []json.RawMessage     `json:"anyOf"`
}

type schemaProp struct {
	Type json.RawMessage `json:"type"`
	Ref  string          `json:"$ref"`
}

// structYAMLFields extracts yaml tag names from a Go struct in the AST.
func structYAMLFields(dir string, structName string) (map[string]bool, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool { //nolint:staticcheck // simple AST tool
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
						_, after, ok0 := strings.Cut(tag, `yaml:"`)
						if !ok0 {
							continue
						}
						before, _, ok0 := strings.Cut(after, `"`)
						if !ok0 {
							continue
						}
						name, _, _ := strings.Cut(before, ",")
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

// mapKeys extracts keys from a Go source map literal.
// Handles both string literal keys and identifier keys (constants).
func mapKeys(dir string, varName string) ([]string, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, func(fi os.FileInfo) bool { //nolint:staticcheck // simple AST tool
		return !strings.HasSuffix(fi.Name(), "_test.go") &&
			!strings.HasSuffix(fi.Name(), "_generated.go")
	}, 0)
	if err != nil {
		return nil, err
	}

	// First pass: collect all const string values.
	constVals := make(map[string]string)
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
								constVals[name.Name] = strings.Trim(bl.Value, `"`)
							}
						}
					}
				}
			}
		}
	}

	// Second pass: extract map keys.
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
							if v, ok := constVals[k.Name]; ok {
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

	goDir, err := filepath.Abs(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "abs path: %v\n", err)
		os.Exit(1)
	}

	// --- Check RuleConfig YAML fields against schema ruleConfig variants ---
	goRuleFields, err := structYAMLFields(goDir, "RuleConfig")
	if err != nil {
		check("RuleConfig: parse error: %v", err)
	} else if len(goRuleFields) == 0 {
		check("RuleConfig: no yaml fields found")
	} else if ruleDef, ok := doc.Defs["ruleConfig"]; ok {
		// Collect all properties from all oneOf variants.
		schemaRuleFields := make(map[string]bool)
		for _, raw := range ruleDef.OneOf {
			var variant schemaDef
			if json.Unmarshal(raw, &variant) != nil {
				continue
			}
			for name := range variant.Properties {
				schemaRuleFields[name] = true
			}
		}
		for name := range goRuleFields {
			if !schemaRuleFields[name] {
				check("Go RuleConfig.%s not in schema ruleConfig", name)
			}
		}
		for name := range schemaRuleFields {
			if !goRuleFields[name] {
				check("schema ruleConfig.%s not in Go RuleConfig", name)
			}
		}
	}

	// --- Check MatchConfig YAML fields against schema matchConfig ---
	goMatchFields, err := structYAMLFields(goDir, "MatchConfig")
	if err != nil {
		check("MatchConfig: parse error: %v", err)
	} else if len(goMatchFields) == 0 {
		check("MatchConfig: no yaml fields found")
	} else if matchDef, ok := doc.Defs["matchConfig"]; ok {
		for name := range goMatchFields {
			if _, ok := matchDef.Properties[name]; !ok {
				check("Go MatchConfig.%s not in schema matchConfig", name)
			}
		}
		for name := range matchDef.Properties {
			if !goMatchFields[name] {
				check("schema matchConfig.%s not in Go MatchConfig", name)
			}
		}
	}

	// --- Check severity enum ---
	if sevDef, ok := doc.Defs["severity"]; ok {
		goSev, err := mapKeys(goDir, "ValidSeverities")
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

	// --- Check operation enum (includes "all" keyword) ---
	if opDef, ok := doc.Defs["operation"]; ok {
		goOps, err := mapKeys(goDir, "ValidOperations")
		if err != nil {
			check("ValidOperations: parse error: %v", err)
		}
		// Go also accepts "all" as a keyword (not in ValidOperations map).
		goOpsWithAll := append(slices.Clone(goOps), "all")
		for _, o := range opDef.Enum {
			if !slices.Contains(goOpsWithAll, o) {
				check("schema operation %q not in Go ValidOperations (or 'all')", o)
			}
		}
		for _, o := range goOpsWithAll {
			if !slices.Contains(opDef.Enum, o) {
				check("Go operation %q not in schema operation enum", o)
			}
		}
	}

	if len(errors) > 0 {
		fmt.Fprintf(os.Stderr, "rules schema validation failed:\n")
		for _, e := range errors {
			fmt.Fprintf(os.Stderr, "  - %s\n", e)
		}
		os.Exit(1)
	}

	// Write generated file with validation timestamp.
	out := fmt.Sprintf(`// Code generated by schema-check; DO NOT EDIT.
// Schema validated at %s against docs/rules.schema.json.

package rules
`, time.Now().UTC().Format(time.RFC3339))

	if err := os.WriteFile(outputFile, []byte(out), 0o600); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", outputFile, err)
		os.Exit(1)
	}

	fmt.Printf("rules schema validation passed, wrote %s\n", outputFile)
}
