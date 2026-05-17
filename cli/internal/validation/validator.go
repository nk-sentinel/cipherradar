package validation

import (
	"embed"
	"fmt"
	"sort"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/santhosh-tekuri/jsonschema/v6/kind"
)

//go:embed schema/bom-1.7.schema.json
var schemaBytes []byte

//go:embed schema
var schemaFS embed.FS

// schemaFiles maps embedded file names to the $id URLs used in the CycloneDX schemas.
var schemaFiles = []struct {
	file string
	url  string
}{
	{"schema/jsf-0.82.schema.json", "http://cyclonedx.org/schema/jsf-0.82.schema.json"},
	{"schema/cryptography-defs.schema.json", "http://cyclonedx.org/schema/cryptography-defs.schema.json"},
	{"schema/spdx.schema.json", "http://cyclonedx.org/schema/spdx.schema.json"},
	{"schema/bom-1.7.schema.json", "http://cyclonedx.org/schema/bom-1.7.schema.json"},
}

// ValidationResult holds the outcome of schema validation.
type ValidationResult struct {
	Valid  bool
	Errors []ValidationError
}

// ValidationError captures a single schema validation issue. Expected/Actual
// are filled in when the underlying jsonschema error kind exposes them —
// currently Enum, Const, and Type — so consumers can surface actionable
// messages like "expected one of [aes, rsa, ...]; got concatkdf".
type ValidationError struct {
	Path     string
	Message  string
	Keyword  string   // "enum", "const", "type", "required", etc.
	Actual   string   // JSON-encoded rendering of the offending value
	Expected []string // allowed values (for enum/type), single entry for const
}

// compiledSchema is lazily initialized on first use.
var compiledSchema *jsonschema.Schema

func getCompiledSchema() (*jsonschema.Schema, error) {
	if compiledSchema != nil {
		return compiledSchema, nil
	}

	c := jsonschema.NewCompiler()

	// Register all embedded schema files with their canonical URLs.
	for _, sf := range schemaFiles {
		data, err := schemaFS.ReadFile(sf.file)
		if err != nil {
			return nil, fmt.Errorf("failed to read embedded schema %s: %w", sf.file, err)
		}
		doc, err := jsonschema.UnmarshalJSON(strings.NewReader(string(data)))
		if err != nil {
			return nil, fmt.Errorf("failed to parse embedded schema %s: %w", sf.file, err)
		}
		if err := c.AddResource(sf.url, doc); err != nil {
			return nil, fmt.Errorf("failed to add schema resource %s: %w", sf.url, err)
		}
	}

	sch, err := c.Compile("http://cyclonedx.org/schema/bom-1.7.schema.json")
	if err != nil {
		return nil, fmt.Errorf("failed to compile schema: %w", err)
	}

	compiledSchema = sch
	return compiledSchema, nil
}

// ValidateCycloneDXJSON validates a CycloneDX JSON document against the 1.7 schema.
func ValidateCycloneDXJSON(jsonData []byte) (*ValidationResult, error) {
	if len(jsonData) == 0 {
		return nil, fmt.Errorf("empty JSON data")
	}

	sch, err := getCompiledSchema()
	if err != nil {
		return nil, fmt.Errorf("schema compilation error: %w", err)
	}

	// Parse the instance JSON.
	inst, err := jsonschema.UnmarshalJSON(strings.NewReader(string(jsonData)))
	if err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}

	// Validate the instance against the schema.
	err = sch.Validate(inst)
	if err == nil {
		return &ValidationResult{Valid: true}, nil
	}

	// Extract structured errors from the validation result.
	verr, ok := err.(*jsonschema.ValidationError)
	if !ok {
		return nil, fmt.Errorf("unexpected validation error type: %w", err)
	}

	validationErrors := collectErrors(verr)
	return &ValidationResult{
		Valid:  false,
		Errors: validationErrors,
	}, nil
}

// collectErrors walks a ValidationError tree and returns only leaf errors
// (nodes with no Causes). Each leaf is enriched with keyword/expected/actual
// when the underlying kind exposes them — for Enum, Const, and Type errors
// this produces actionable output like "expected one of [aes, rsa, ...]".
func collectErrors(verr *jsonschema.ValidationError) []ValidationError {
	var out []ValidationError
	walkCauses(verr, &out)
	if len(out) == 0 {
		out = append(out, ValidationError{
			Path:    "/",
			Message: verr.Error(),
		})
	}
	// Sort deterministically so test output is stable.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Path != out[j].Path {
			return out[i].Path < out[j].Path
		}
		return out[i].Keyword < out[j].Keyword
	})
	return out
}

func walkCauses(e *jsonschema.ValidationError, out *[]ValidationError) {
	if e == nil {
		return
	}
	if len(e.Causes) == 0 {
		*out = append(*out, convertLeaf(e))
		return
	}
	for _, c := range e.Causes {
		walkCauses(c, out)
	}
}

func convertLeaf(e *jsonschema.ValidationError) ValidationError {
	path := "/" + strings.Join(e.InstanceLocation, "/")
	if len(e.InstanceLocation) == 0 {
		path = "/"
	}
	ve := ValidationError{
		Path:    path,
		Message: e.Error(),
	}
	switch k := e.ErrorKind.(type) {
	case *kind.Enum:
		ve.Keyword = "enum"
		ve.Actual = renderValue(k.Got)
		for _, v := range k.Want {
			ve.Expected = append(ve.Expected, renderValue(v))
		}
	case *kind.Const:
		ve.Keyword = "const"
		ve.Actual = renderValue(k.Got)
		ve.Expected = []string{renderValue(k.Want)}
	case *kind.Type:
		ve.Keyword = "type"
		ve.Actual = k.Got
		ve.Expected = append(ve.Expected, k.Want...)
	case *kind.Required:
		ve.Keyword = "required"
		ve.Expected = append(ve.Expected, k.Missing...)
	case *kind.Format:
		ve.Keyword = "format"
		ve.Expected = []string{k.Want}
		ve.Actual = renderValue(k.Got)
	case *kind.AdditionalProperties:
		ve.Keyword = "additionalProperties"
		ve.Actual = strings.Join(k.Properties, ",")
	}
	return ve
}

func renderValue(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return t
	default:
		return fmt.Sprintf("%v", t)
	}
}
