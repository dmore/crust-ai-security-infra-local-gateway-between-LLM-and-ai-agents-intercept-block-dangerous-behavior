// schema-check validates that Go rule types conform to the JSON Schema
// embedded in the schemacheck package. Run via go generate.
//
// If validation passes, it writes schema_generated.go with the validation
// timestamp. If CI runs `go generate ./... && git diff --exit-code`, any
// schema drift will cause the generated file to change, failing CI.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/BakeLens/crust/internal/schemacheck"
)

const outputFile = "schema_generated.go"

func main() {
	doc, err := schemacheck.LoadSchemaBytes(schemacheck.RulesSchema)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	var c schemacheck.Checker

	goDir, err := filepath.Abs(".")
	if err != nil {
		fmt.Fprintf(os.Stderr, "abs path: %v\n", err)
		os.Exit(1)
	}

	// --- Check RuleConfig YAML fields against schema ruleConfig variants ---
	goRuleFields, err := schemacheck.StructFields(goDir, "RuleConfig", "yaml")
	if err != nil {
		c.Check("RuleConfig: parse error: %v", err)
	} else if len(goRuleFields) == 0 {
		c.Check("RuleConfig: no yaml fields found")
	} else if ruleDef, ok := doc.Defs["ruleConfig"]; ok {
		// Collect all properties from all oneOf variants.
		schemaRuleFields := make(map[string]bool)
		for _, raw := range ruleDef.OneOf {
			var variant schemacheck.SchemaDef
			if json.Unmarshal(raw, &variant) != nil {
				continue
			}
			for name := range variant.Properties {
				schemaRuleFields[name] = true
			}
		}
		for name := range goRuleFields {
			if !schemaRuleFields[name] {
				c.Check("Go RuleConfig.%s not in schema ruleConfig", name)
			}
		}
		for name := range schemaRuleFields {
			if !goRuleFields[name] {
				c.Check("schema ruleConfig.%s not in Go RuleConfig", name)
			}
		}
	}

	// --- Check MatchConfig YAML fields against schema matchConfig ---
	goMatchFields, err := schemacheck.StructFields(goDir, "MatchConfig", "yaml")
	if err != nil {
		c.Check("MatchConfig: parse error: %v", err)
	} else if len(goMatchFields) == 0 {
		c.Check("MatchConfig: no yaml fields found")
	} else if matchDef, ok := doc.Defs["matchConfig"]; ok {
		c.CheckStructFields(goMatchFields, matchDef.Properties, "MatchConfig", "matchConfig")
	}

	// --- Check severity enum ---
	if sevDef, ok := doc.Defs["severity"]; ok {
		goSev, err := schemacheck.MapKeys(goDir, "ValidSeverities")
		if err != nil {
			c.Check("ValidSeverities: parse error: %v", err)
		} else {
			c.CheckEnumMatch(goSev, sevDef.Enum, "ValidSeverities", "severity", false)
		}
	}

	// --- Check operation enum (includes "all" keyword) ---
	if opDef, ok := doc.Defs["operation"]; ok {
		goOps, err := schemacheck.MapKeys(goDir, "ValidOperations")
		if err != nil {
			c.Check("ValidOperations: parse error: %v", err)
		} else {
			// Go also accepts "all" as a keyword (not in ValidOperations map).
			goOpsWithAll := append(slices.Clone(goOps), "all")
			c.CheckEnumMatch(goOpsWithAll, opDef.Enum, "ValidOperations", "operation", false)
		}
	}

	// --- Check ruleSource enum ---
	if srcDef, ok := doc.Defs["ruleSource"]; ok {
		goSrc, err := schemacheck.MapKeys(goDir, "ValidSources")
		if err != nil {
			c.Check("ValidSources: parse error: %v", err)
		} else {
			c.CheckEnumMatch(goSrc, srcDef.Enum, "ValidSources", "ruleSource", false)
		}
	}

	if c.Failed() {
		c.Report("rules schema validation failed")
		os.Exit(1)
	}

	if err := schemacheck.WriteGenerated(outputFile, "rules", "internal/schemacheck/rules.schema.json"); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", outputFile, err)
		os.Exit(1)
	}

	fmt.Printf("rules schema validation passed, wrote %s\n", outputFile)
}
