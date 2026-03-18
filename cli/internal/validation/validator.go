package validation

import (
	"embed"
	"fmt"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v6"
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

// ValidationError captures a single schema validation issue.
type ValidationError struct {
	Path    string
	Message string
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

// collectErrors flattens a ValidationError tree into a list of ValidationError structs.
func collectErrors(verr *jsonschema.ValidationError) []ValidationError {
	basic := verr.BasicOutput()
	var errors []ValidationError
	for _, unit := range basic.Errors {
		if unit.Error == nil {
			continue
		}
		path := unit.InstanceLocation
		if path == "" {
			path = "/"
		}
		errors = append(errors, ValidationError{
			Path:    path,
			Message: unit.Error.String(),
		})
	}
	// If no leaf errors found, use the top-level error message.
	if len(errors) == 0 {
		errors = append(errors, ValidationError{
			Path:    "/",
			Message: verr.Error(),
		})
	}
	return errors
}
