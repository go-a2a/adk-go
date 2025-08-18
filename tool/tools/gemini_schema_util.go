// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"fmt"
	"maps"
	"strings"
	"unicode"

	"github.com/google/jsonschema-go/jsonschema"
	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/types"
)

// ExtendedJSONSchema represents a JSON schema with additional properties for Gemini compatibility.
// This extends the standard JSON schema with optional property ordering.
type ExtendedJSONSchema struct {
	*jsonschema.Schema

	// PropertyOrdering extended field for property ordering.
	// Not a standard field in open api spec. Only used to support the order of the properties.
	PropertyOrdering []string `json:"property_ordering,omitempty"`
}

// ToSnakeCase converts a string into snake_case.
//
// Handles lowerCamelCase, UpperCamelCase, space-separated case, acronyms
// (e.g., "REST API") and consecutive uppercase letters correctly. Also handles
// mixed cases with and without spaces.
//
// Examples:
//
//	ToSnakeCase("camelCase") -> "camel_case"
//	ToSnakeCase("UpperCamelCase") -> "upper_camel_case"
//	ToSnakeCase("space separated") -> "space_separated"
//	ToSnakeCase("REST API") -> "rest_api"
//
// This implementation uses a single-pass algorithm for optimal performance,
// avoiding regex compilation and multiple string allocations.
func ToSnakeCase(text string) string {
	if text == "" {
		return ""
	}

	var result strings.Builder
	result.Grow(len(text) + len(text)/2) // Pre-allocate with estimated size

	runes := []rune(text)
	lastWasUnderscore := false

	for i, r := range runes {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			if unicode.IsUpper(r) {
				// Check if we need to add an underscore before this uppercase letter
				needsUnderscore := false
				if i > 0 {
					prev := runes[i-1]
					if unicode.IsLower(prev) || unicode.IsDigit(prev) {
						// Previous was lowercase/digit, current is uppercase: camelCase
						needsUnderscore = true
					} else if unicode.IsUpper(prev) && i+1 < len(runes) && unicode.IsLower(runes[i+1]) {
						// Previous was uppercase, current is uppercase, next is lowercase: XMLHttp
						needsUnderscore = true
					}
				}

				if needsUnderscore && result.Len() > 0 && !lastWasUnderscore {
					result.WriteByte('_')
					lastWasUnderscore = true
				}
				result.WriteRune(unicode.ToLower(r))
				lastWasUnderscore = false
			} else {
				result.WriteRune(r)
				lastWasUnderscore = false
			}
		} else {
			// Replace non-alphanumeric with underscore, but avoid consecutive underscores
			if result.Len() > 0 && !lastWasUnderscore {
				result.WriteByte('_')
				lastWasUnderscore = true
			}
		}
	}

	return strings.Trim(result.String(), "_")
}

// sanitizeSchemaType sanitizes schema types by ensuring all schemas have a proper type.
// It handles missing types (defaults to "object"), processes list types with nullable
// variations, and converts pure "null" types to ["object", "null"].
func sanitizeSchemaType(schema *jsonschema.Schema) *jsonschema.Schema {
	if schema == nil {
		return nil
	}

	// Create a copy to avoid modifying the original
	result := &jsonschema.Schema{
		ID:          schema.ID,
		Schema:      schema.Schema,
		Ref:         schema.Ref,
		Comment:     schema.Comment,
		Title:       schema.Title,
		Description: schema.Description,
		Default:     schema.Default,
		Deprecated:  schema.Deprecated,
		ReadOnly:    schema.ReadOnly,
		WriteOnly:   schema.WriteOnly,
		Examples:    schema.Examples,
		Type:        schema.Type,
		Types:       schema.Types,
		Enum:        schema.Enum,
		Const:       schema.Const,
		Format:      schema.Format,
		Pattern:     schema.Pattern,
		Required:    schema.Required,
	}

	// Copy pointer fields
	if schema.MultipleOf != nil {
		result.MultipleOf = &(*schema.MultipleOf)
	}
	if schema.Minimum != nil {
		result.Minimum = &(*schema.Minimum)
	}
	if schema.Maximum != nil {
		result.Maximum = &(*schema.Maximum)
	}
	if schema.ExclusiveMinimum != nil {
		result.ExclusiveMinimum = &(*schema.ExclusiveMinimum)
	}
	if schema.ExclusiveMaximum != nil {
		result.ExclusiveMaximum = &(*schema.ExclusiveMaximum)
	}
	if schema.MinLength != nil {
		result.MinLength = &(*schema.MinLength)
	}
	if schema.MaxLength != nil {
		result.MaxLength = &(*schema.MaxLength)
	}
	if schema.MinItems != nil {
		result.MinItems = &(*schema.MinItems)
	}
	if schema.MaxItems != nil {
		result.MaxItems = &(*schema.MaxItems)
	}
	if schema.MinProperties != nil {
		result.MinProperties = &(*schema.MinProperties)
	}
	if schema.MaxProperties != nil {
		result.MaxProperties = &(*schema.MaxProperties)
	}

	// Copy schema pointers
	if schema.Items != nil {
		result.Items = schema.Items
	}
	if schema.AdditionalProperties != nil {
		result.AdditionalProperties = schema.AdditionalProperties
	}

	// Copy maps
	if schema.Properties != nil {
		result.Properties = make(map[string]*jsonschema.Schema)
		maps.Copy(result.Properties, schema.Properties)
	}
	if schema.Defs != nil {
		result.Defs = make(map[string]*jsonschema.Schema)
		maps.Copy(result.Defs, schema.Defs)
	}
	if schema.Extra != nil {
		result.Extra = make(map[string]any)
		maps.Copy(result.Extra, schema.Extra)
	}

	// Copy slices
	if schema.AllOf != nil {
		result.AllOf = make([]*jsonschema.Schema, len(schema.AllOf))
		copy(result.AllOf, schema.AllOf)
	}
	if schema.AnyOf != nil {
		result.AnyOf = make([]*jsonschema.Schema, len(schema.AnyOf))
		copy(result.AnyOf, schema.AnyOf)
	}
	if schema.OneOf != nil {
		result.OneOf = make([]*jsonschema.Schema, len(schema.OneOf))
		copy(result.OneOf, schema.OneOf)
	}

	// Check if type is missing or empty and schema doesn't have other defining fields
	if result.Type == "" && len(result.Types) == 0 {
		// If schema is essentially empty (no defining fields), default to object
		hasDefiningFields := result.Properties != nil || result.Items != nil || result.AllOf != nil ||
			result.AnyOf != nil || result.OneOf != nil || result.Enum != nil || result.Const != nil ||
			result.Minimum != nil || result.Maximum != nil || result.MinLength != nil || result.MaxLength != nil

		if !hasDefiningFields {
			result.Type = "object"
		}
	}

	// Handle Types field with nullable variations
	if len(result.Types) > 0 {
		nullable := false
		var nonNullType string

		for _, t := range result.Types {
			if t == "null" {
				nullable = true
			} else if nonNullType == "" {
				nonNullType = t
			}
		}

		if nonNullType == "" {
			nonNullType = "object"
		}

		if nullable {
			result.Types = []string{nonNullType, "null"}
		} else {
			result.Type = nonNullType
			result.Types = nil
		}
	} else if result.Type == "null" {
		result.Types = []string{"object", "null"}
		result.Type = ""
	}

	return result
}

// sanitizeSchemaFormatsForGemini filters the schema to only include fields that are
// supported by Gemini's JSON Schema implementation. It recursively processes nested
// objects and arrays and validates format fields.
func sanitizeSchemaFormatsForGemini(schema *jsonschema.Schema) (*jsonschema.Schema, error) {
	if schema == nil {
		return nil, nil
	}

	// Create a new schema with only supported fields
	result := &jsonschema.Schema{
		Description: schema.Description,
		Type:        schema.Type,
		Types:       schema.Types,
		Enum:        schema.Enum,
		Pattern:     schema.Pattern,
		Required:    schema.Required,
	}

	// Copy pointer fields that are supported
	if schema.Minimum != nil {
		result.Minimum = &(*schema.Minimum)
	}
	if schema.Maximum != nil {
		result.Maximum = &(*schema.Maximum)
	}
	if schema.MinLength != nil {
		result.MinLength = &(*schema.MinLength)
	}
	if schema.MaxLength != nil {
		result.MaxLength = &(*schema.MaxLength)
	}
	if schema.MinItems != nil {
		result.MinItems = &(*schema.MinItems)
	}
	if schema.MaxItems != nil {
		result.MaxItems = &(*schema.MaxItems)
	}
	if schema.MinProperties != nil {
		result.MinProperties = &(*schema.MinProperties)
	}
	if schema.MaxProperties != nil {
		result.MaxProperties = &(*schema.MaxProperties)
	}

	// Handle format field - only allow supported formats
	if schema.Format != "" {
		currentType := schema.Type
		if currentType == "" && len(schema.Types) > 0 {
			currentType = schema.Types[0] // Use first type if Types is used
		}

		// Only allow specific formats for each type
		validFormat := false
		switch currentType {
		case "integer", "number":
			validFormat = schema.Format == "int32" || schema.Format == "int64"
		case "string":
			validFormat = schema.Format == "date-time" || schema.Format == "enum"
		}

		if validFormat {
			result.Format = schema.Format
		}
	}

	// Handle nested schema in Items
	if schema.Items != nil {
		sanitized, err := sanitizeSchemaFormatsForGemini(schema.Items)
		if err != nil {
			return nil, fmt.Errorf("sanitize items schema: %w", err)
		}
		result.Items = sanitized
	}

	// Handle Properties (dictionary of schemas)
	if schema.Properties != nil {
		result.Properties = make(map[string]*jsonschema.Schema)
		for key, propSchema := range schema.Properties {
			sanitized, err := sanitizeSchemaFormatsForGemini(propSchema)
			if err != nil {
				return nil, fmt.Errorf("sanitize property %s schema: %w", key, err)
			}
			result.Properties[key] = sanitized
		}
	}

	// Handle AnyOf (list of schemas)
	if schema.AnyOf != nil {
		result.AnyOf = make([]*jsonschema.Schema, 0, len(schema.AnyOf))
		for i, anyOfSchema := range schema.AnyOf {
			sanitized, err := sanitizeSchemaFormatsForGemini(anyOfSchema)
			if err != nil {
				return nil, fmt.Errorf("sanitize anyOf schema[%d]: %w", i, err)
			}
			result.AnyOf = append(result.AnyOf, sanitized)
		}
	}

	// Handle Examples (single example becomes array)
	if len(schema.Examples) > 0 {
		result.Examples = make([]any, len(schema.Examples))
		copy(result.Examples, schema.Examples)
	}

	// Handle Extra fields for additional properties like nullable and property_ordering
	if schema.Extra != nil {
		result.Extra = make(map[string]any)

		// Only include supported extra fields
		supportedExtraFields := map[string]bool{
			"nullable":          true,
			"property_ordering": true,
		}

		for key, value := range schema.Extra {
			if supportedExtraFields[key] {
				result.Extra[key] = value
			}
		}
	}

	return sanitizeSchemaType(result), nil
}

// ToGeminiSchema converts a JSON schema to a Gemini Schema object.
// This is the main entry point for converting JSON schemas to Gemini-compatible schemas.
//
// The function:
//  1. Validates the input is a non-nil schema
//  2. Sanitizes the schema to include only Gemini-supported fields
//  3. Converts the sanitized schema to a genai.Schema object
//
// Example usage:
//
//	schema := &jsonschema.Schema{
//	    Type: "object",
//	    Properties: map[string]*jsonschema.Schema{
//	        "name": {Type: "string"},
//	        "age": {Type: "integer"},
//	    },
//	    Required: []string{"name"},
//	}
//
//	geminiSchema, err := ToGeminiSchema(schema)
//	if err != nil {
//	    // handle error
//	}
func ToGeminiSchema(openapiSchema *jsonschema.Schema) (*genai.Schema, error) {
	if openapiSchema == nil {
		return nil, nil
	}

	// Sanitize the schema for Gemini compatibility
	sanitized, err := sanitizeSchemaFormatsForGemini(openapiSchema)
	if err != nil {
		return nil, fmt.Errorf("sanitize schema: %w", err)
	}

	// Convert the sanitized schema to genai.Schema
	return convertToGenaiSchema(sanitized)
}

// convertToGenaiSchema converts a sanitized schema map to a genai.Schema object.
func convertToGenaiSchema(schema *jsonschema.Schema) (*genai.Schema, error) {
	if schema == nil {
		return nil, nil
	}

	result := &genai.Schema{}

	// Handle type field
	if typ := schema.Type; typ != "" {
		switch schema.Type {
		case "string":
			result.Type = genai.TypeString
		case "integer":
			result.Type = genai.TypeInteger
		case "number":
			result.Type = genai.TypeNumber
		case "boolean":
			result.Type = genai.TypeBoolean
		case "array":
			result.Type = genai.TypeArray
		case "object":
			result.Type = genai.TypeObject
		default:
			result.Type = genai.TypeObject // Default fallback
		}
	}

	// Handle scalar fields
	if desc := schema.Description; desc != "" {
		result.Description = desc
	}

	if format := schema.Format; format != "" {
		result.Format = format
	}

	if pattern := schema.Pattern; pattern != "" {
		result.Pattern = pattern
	}

	// Handle enum
	if enumList := schema.Enum; enumList != nil {
		var enumStrs []string
		for _, item := range enumList {
			if itemStr, ok := item.(string); ok {
				enumStrs = append(enumStrs, itemStr)
			}
		}
		result.Enum = enumStrs
	}

	// Handle required fields
	if requiredList := schema.Required; len(requiredList) > 0 {
		result.Required = requiredList
	}

	// Handle nullable
	if nullableVal, exists := schema.Extra["nullable"]; exists {
		if nullableBool, ok := nullableVal.(bool); ok {
			result.Nullable = &nullableBool
		}
	}

	// Handle numeric constraints
	result.Minimum = schema.Minimum
	result.Maximum = schema.Maximum

	// Handle string constraints
	if schema.MinLength != nil {
		result.MinLength = types.ToPtr(int64(*schema.MinLength))
	}
	if schema.MaxLength != nil {
		result.MaxLength = types.ToPtr(int64(*schema.MaxLength))
	}
	if schema.MinItems != nil {
		result.MinItems = types.ToPtr(int64(*schema.MinItems))
	}
	if schema.MaxItems != nil {
		result.MaxItems = types.ToPtr(int64(*schema.MaxItems))
	}
	if schema.MinProperties != nil {
		result.MinProperties = types.ToPtr(int64(*schema.MinProperties))
	}
	if schema.MaxProperties != nil {
		result.MaxProperties = types.ToPtr(int64(*schema.MaxProperties))
	}

	var err error
	result.Items, err = convertToGenaiSchema(schema.Items)
	if err != nil {
		return nil, fmt.Errorf("convert items schema: %w", err)
	}

	// Handle object properties
	if len(schema.Properties) > 0 {
		properties := make(map[string]*genai.Schema)
		for propName, propVal := range schema.Properties {
			converted, err := convertToGenaiSchema(propVal)
			if err != nil {
				return nil, fmt.Errorf("convert property %s schema: %w", propName, err)
			}
			properties[propName] = converted
		}
		result.Properties = properties
	}

	// Handle example
	if exampleVal := schema.Examples; len(exampleVal) > 0 {
		result.Example = exampleVal
	}

	return result, nil
}

// ValidateGeminiSchema validates that a schema is compatible with Gemini's requirements.
// This function checks for common issues and returns descriptive error messages.
func ValidateGeminiSchema(schema *genai.Schema) error {
	if schema == nil {
		return nil
	}

	// Validate type-specific constraints
	switch schema.Type {
	case genai.TypeString:
		if schema.Format != "" {
			validFormats := map[string]bool{"date-time": true, "enum": true}
			if !validFormats[schema.Format] {
				return fmt.Errorf("invalid format %q for string type, supported formats: date-time, enum", schema.Format)
			}
		}

	case genai.TypeInteger, genai.TypeNumber:
		if schema.Format != "" {
			validFormats := map[string]bool{"int32": true, "int64": true}
			if !validFormats[schema.Format] {
				return fmt.Errorf("invalid format %q for numeric type, supported formats: int32, int64", schema.Format)
			}
		}

	case genai.TypeArray:
		if schema.Items == nil {
			return fmt.Errorf("array type requires items schema")
		}

		// Recursively validate items schema
		if err := ValidateGeminiSchema(schema.Items); err != nil {
			return fmt.Errorf("invalid items schema: %w", err)
		}

	case genai.TypeObject:
		// Validate properties if present
		for propName, propSchema := range schema.Properties {
			if err := ValidateGeminiSchema(propSchema); err != nil {
				return fmt.Errorf("invalid property %s schema: %w", propName, err)
			}
		}

		// Validate required fields reference existing properties
		if len(schema.Required) > 0 && len(schema.Properties) > 0 {
			for _, reqField := range schema.Required {
				if _, exists := schema.Properties[reqField]; !exists {
					return fmt.Errorf("required field %q not found in properties", reqField)
				}
			}
		}
	}

	return nil
}
