// Package schemacheck provides shared helpers for go:generate schema
// validation tools. Both internal/rules/cmd/schema-check and
// internal/plugin/cmd/schema-check use these to compare Go types
// against JSON Schema definitions.
package schemacheck

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"slices"
	"strings"
)

// SchemaDoc is a partial JSON Schema representation (draft 2020-12).
type SchemaDoc struct {
	Defs map[string]SchemaDef `json:"$defs"`
}

// SchemaDef represents a single $defs entry.
type SchemaDef struct {
	Type       string                `json:"type"`
	Required   []string              `json:"required"`
	Properties map[string]SchemaProp `json:"properties"`
	Enum       []string              `json:"enum"`
	OneOf      []json.RawMessage     `json:"oneOf"`
	AnyOf      []json.RawMessage     `json:"anyOf"`
}

// SchemaProp represents a single property in a schema definition.
type SchemaProp struct {
	Type json.RawMessage `json:"type"`
	Ref  string          `json:"$ref"`
}

// LoadSchema reads and parses a JSON Schema file.
func LoadSchema(path string) (*SchemaDoc, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read schema %s: %w", path, err)
	}
	if !json.Valid(data) {
		return nil, fmt.Errorf("schema %s is not valid JSON", path)
	}
	var doc SchemaDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("unmarshal schema: %w", err)
	}
	return &doc, nil
}

// parseDir parses Go source files in dir, excluding test and generated files.
func parseDir(dir string) (map[string]*ast.Package, error) { //nolint:staticcheck // simple AST tool, no need for go/packages
	fset := token.NewFileSet()
	return parser.ParseDir(fset, dir, func(fi os.FileInfo) bool { //nolint:staticcheck // simple AST tool
		return !strings.HasSuffix(fi.Name(), "_test.go") &&
			!strings.HasSuffix(fi.Name(), "_generated.go")
	}, 0)
}

// StructFields extracts struct tag names from a Go struct in the AST.
// tagName should be "json" or "yaml".
func StructFields(dir, structName, tagName string) (map[string]bool, error) {
	pkgs, err := parseDir(dir)
	if err != nil {
		return nil, err
	}

	prefix := tagName + `:"`
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
						_, after, ok0 := strings.Cut(field.Tag.Value, prefix)
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

// MapKeys extracts string keys from a Go source map literal like
// `var ValidSeverities = map[Severity]bool{...}`.
// Keys may be string literals or identifiers referencing typed string constants.
func MapKeys(dir, varName string) ([]string, error) {
	pkgs, err := parseDir(dir)
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

// ConstValues extracts string constant values from Go source by name.
func ConstValues(dir string, names []string) ([]string, error) {
	pkgs, err := parseDir(dir)
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

// Checker collects validation errors.
type Checker struct {
	Errors []string
}

// Check records a validation error.
func (c *Checker) Check(format string, args ...any) {
	c.Errors = append(c.Errors, fmt.Sprintf(format, args...))
}

// Failed returns true if any errors were recorded.
func (c *Checker) Failed() bool { return len(c.Errors) > 0 }

// Report prints all errors to stderr.
func (c *Checker) Report(prefix string) {
	fmt.Fprintf(os.Stderr, "%s:\n", prefix)
	for _, e := range c.Errors {
		fmt.Fprintf(os.Stderr, "  - %s\n", e)
	}
}

// WriteGenerated writes the schema_generated.go stamp file.
func WriteGenerated(outputFile, pkgName, schemaRef string) error {
	out := fmt.Sprintf("// Code generated by schema-check; DO NOT EDIT.\n"+
		"// Schema: %s\n\npackage %s\n",
		schemaRef, pkgName)
	return os.WriteFile(outputFile, []byte(out), 0o600)
}

// CheckStructFields validates that Go struct fields match schema properties bidirectionally.
func (c *Checker) CheckStructFields(goFields map[string]bool, schemaProps map[string]SchemaProp, goName, schemaName string) {
	for name := range goFields {
		if _, ok := schemaProps[name]; !ok {
			c.Check("Go %s.%s not in schema %s", goName, name, schemaName)
		}
	}
	for name := range schemaProps {
		if !goFields[name] {
			c.Check("schema %s.%s not in Go %s", schemaName, name, goName)
		}
	}
}

// CheckEnumMatch validates that Go map keys match schema enum values bidirectionally.
func (c *Checker) CheckEnumMatch(goKeys, schemaEnum []string, goName, schemaName string, skipEmpty bool) {
	for _, s := range schemaEnum {
		if !contains(goKeys, s) {
			c.Check("schema %s %q not in Go %s", schemaName, s, goName)
		}
	}
	for _, s := range goKeys {
		if skipEmpty && s == "" {
			continue
		}
		if !contains(schemaEnum, s) {
			c.Check("Go %s %q not in schema %s", goName, s, schemaName)
		}
	}
}

func contains(ss []string, s string) bool {
	return slices.Contains(ss, s)
}
