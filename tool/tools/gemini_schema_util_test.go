// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package tools

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/jsonschema-go/jsonschema"
	"google.golang.org/genai"
)

func TestToSnakeCase(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "camelCase",
			input:    "camelCase",
			expected: "camel_case",
		},
		{
			name:     "PascalCase",
			input:    "PascalCase",
			expected: "pascal_case",
		},
		{
			name:     "UpperCamelCase",
			input:    "UpperCamelCase",
			expected: "upper_camel_case",
		},
		{
			name:     "space separated",
			input:    "space separated",
			expected: "space_separated",
		},
		{
			name:     "mixed spaces and cases",
			input:    "Mixed Case With Spaces",
			expected: "mixed_case_with_spaces",
		},
		{
			name:     "REST API",
			input:    "REST API",
			expected: "rest_api",
		},
		{
			name:     "APIKey",
			input:    "APIKey",
			expected: "api_key",
		},
		{
			name:     "HTTPSConnection",
			input:    "HTTPSConnection",
			expected: "https_connection",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "single word",
			input:    "word",
			expected: "word",
		},
		{
			name:     "already snake_case",
			input:    "already_snake_case",
			expected: "already_snake_case",
		},
		{
			name:     "with numbers",
			input:    "version2Beta",
			expected: "version2_beta",
		},
		{
			name:     "special characters",
			input:    "field-name.with@special#chars",
			expected: "field_name_with_special_chars",
		},
		{
			name:     "consecutive underscores",
			input:    "field__with___underscores",
			expected: "field_with_underscores",
		},
		{
			name:     "leading and trailing underscores",
			input:    "_field_name_",
			expected: "field_name",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ToSnakeCase(tt.input)
			if result != tt.expected {
				t.Errorf("ToSnakeCase(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestSanitizeSchemaType(t *testing.T) {
	tests := []struct {
		name     string
		input    *jsonschema.Schema
		expected *jsonschema.Schema
	}{
		{
			name: "missing type defaults to object",
			input: &jsonschema.Schema{
				Description: "A schema without type",
			},
			expected: &jsonschema.Schema{
				Description: "A schema without type",
				Type:        "object",
			},
		},
		{
			name: "empty type defaults to object",
			input: &jsonschema.Schema{
				Type:        "",
				Description: "A schema with empty type",
			},
			expected: &jsonschema.Schema{
				Type:        "object",
				Description: "A schema with empty type",
			},
		},
		{
			name: "list type with null becomes nullable",
			input: &jsonschema.Schema{
				Types: []string{"string", "null"},
			},
			expected: &jsonschema.Schema{
				Types: []string{"string", "null"},
			},
		},
		{
			name: "list type without null becomes single type",
			input: &jsonschema.Schema{
				Types: []string{"string"},
			},
			expected: &jsonschema.Schema{
				Type: "string",
			},
		},
		{
			name: "list type with multiple non-null types keeps first",
			input: &jsonschema.Schema{
				Types: []string{"string", "number", "null"},
			},
			expected: &jsonschema.Schema{
				Types: []string{"string", "null"},
			},
		},
		{
			name: "pure null type becomes nullable object",
			input: &jsonschema.Schema{
				Type: "null",
			},
			expected: &jsonschema.Schema{
				Types: []string{"object", "null"},
			},
		},
		{
			name: "valid string type unchanged",
			input: &jsonschema.Schema{
				Type: "string",
			},
			expected: &jsonschema.Schema{
				Type: "string",
			},
		},
		{
			name: "schema with properties keeps existing type",
			input: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"name": {Type: "string"},
				},
			},
			expected: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"name": {Type: "string"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := sanitizeSchemaType(tt.input)
			if diff := cmp.Diff(tt.expected, result, cmpopts.IgnoreUnexported(jsonschema.Schema{})); diff != "" {
				t.Errorf("sanitizeSchemaType() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSanitizeSchemaFormatsForGemini(t *testing.T) {
	tests := []struct {
		name     string
		input    *jsonschema.Schema
		expected *jsonschema.Schema
		wantErr  bool
	}{
		{
			name: "basic string schema",
			input: &jsonschema.Schema{
				Type:        "string",
				Description: "A string field",
			},
			expected: &jsonschema.Schema{
				Type:        "string",
				Description: "A string field",
			},
		},
		{
			name: "object with properties",
			input: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"firstName": {Type: "string"},
					"lastName":  {Type: "string"},
				},
				Required: []string{"firstName"},
			},
			expected: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"firstName": {Type: "string"},
					"lastName":  {Type: "string"},
				},
				Required: []string{"firstName"},
			},
		},
		{
			name: "format validation for string type",
			input: &jsonschema.Schema{
				Type:   "string",
				Format: "date-time",
			},
			expected: &jsonschema.Schema{
				Type:   "string",
				Format: "date-time",
			},
		},
		{
			name: "invalid format for string type removed",
			input: &jsonschema.Schema{
				Type:   "string",
				Format: "invalid-format",
			},
			expected: &jsonschema.Schema{
				Type: "string",
			},
		},
		{
			name: "format validation for integer type",
			input: &jsonschema.Schema{
				Type:   "integer",
				Format: "int64",
			},
			expected: &jsonschema.Schema{
				Type:   "integer",
				Format: "int64",
			},
		},
		{
			name: "invalid format for integer type removed",
			input: &jsonschema.Schema{
				Type:   "integer",
				Format: "date-time",
			},
			expected: &jsonschema.Schema{
				Type: "integer",
			},
		},
		{
			name: "nested object with items",
			input: &jsonschema.Schema{
				Type: "array",
				Items: &jsonschema.Schema{
					Type: "object",
					Properties: map[string]*jsonschema.Schema{
						"name": {Type: "string"},
					},
				},
			},
			expected: &jsonschema.Schema{
				Type: "array",
				Items: &jsonschema.Schema{
					Type: "object",
					Properties: map[string]*jsonschema.Schema{
						"name": {Type: "string"},
					},
				},
			},
		},
		{
			name: "anyOf schemas",
			input: &jsonschema.Schema{
				AnyOf: []*jsonschema.Schema{
					{Type: "string"},
					{Type: "integer"},
				},
			},
			expected: &jsonschema.Schema{
				AnyOf: []*jsonschema.Schema{
					{Type: "string"},
					{Type: "integer"},
				},
			},
		},
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name: "constraints preserved",
			input: &jsonschema.Schema{
				Type:      "string",
				MinLength: func() *int { i := 5; return &i }(),
				MaxLength: func() *int { i := 100; return &i }(),
				Pattern:   "^[a-zA-Z]+$",
			},
			expected: &jsonschema.Schema{
				Type:      "string",
				MinLength: func() *int { i := 5; return &i }(),
				MaxLength: func() *int { i := 100; return &i }(),
				Pattern:   "^[a-zA-Z]+$",
			},
		},
		{
			name: "extra fields preserved",
			input: &jsonschema.Schema{
				Type: "string",
				Extra: map[string]any{
					"nullable":          true,
					"property_ordering": []string{"a", "b"},
					"unsupported":       "removed",
				},
			},
			expected: &jsonschema.Schema{
				Type: "string",
				Extra: map[string]any{
					"nullable":          true,
					"property_ordering": []string{"a", "b"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := sanitizeSchemaFormatsForGemini(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("sanitizeSchemaFormatsForGemini() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.expected, result, cmpopts.IgnoreUnexported(jsonschema.Schema{})); diff != "" {
				t.Errorf("sanitizeSchemaFormatsForGemini() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestToGeminiSchema(t *testing.T) {
	tests := []struct {
		name     string
		input    *jsonschema.Schema
		expected *genai.Schema
		wantErr  bool
	}{
		{
			name:     "nil input",
			input:    nil,
			expected: nil,
		},
		{
			name: "basic string schema",
			input: &jsonschema.Schema{
				Type:        "string",
				Description: "A string field",
			},
			expected: &genai.Schema{
				Type:        genai.TypeString,
				Description: "A string field",
			},
		},
		{
			name: "integer schema with constraints",
			input: &jsonschema.Schema{
				Type:    "integer",
				Minimum: func() *float64 { f := 0.0; return &f }(),
				Maximum: func() *float64 { f := 100.0; return &f }(),
				Format:  "int32",
			},
			expected: &genai.Schema{
				Type:    genai.TypeInteger,
				Format:  "int32",
				Minimum: func() *float64 { f := 0.0; return &f }(),
				Maximum: func() *float64 { f := 100.0; return &f }(),
			},
		},
		{
			name: "array schema with items",
			input: &jsonschema.Schema{
				Type: "array",
				Items: &jsonschema.Schema{
					Type: "string",
				},
				MinItems: func() *int { i := 1; return &i }(),
				MaxItems: func() *int { i := 10; return &i }(),
			},
			expected: &genai.Schema{
				Type: genai.TypeArray,
				Items: &genai.Schema{
					Type: genai.TypeString,
				},
				MinItems: func() *int64 { i := int64(1); return &i }(),
				MaxItems: func() *int64 { i := int64(10); return &i }(),
			},
		},
		{
			name: "object schema with properties",
			input: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"name": {Type: "string"},
					"age":  {Type: "integer"},
				},
				Required: []string{"name"},
			},
			expected: &genai.Schema{
				Type: genai.TypeObject,
				Properties: map[string]*genai.Schema{
					"name": {Type: genai.TypeString},
					"age":  {Type: genai.TypeInteger},
				},
				Required: []string{"name"},
			},
		},
		{
			name: "schema with enum",
			input: &jsonschema.Schema{
				Type: "string",
				Enum: []any{"red", "green", "blue"},
			},
			expected: &genai.Schema{
				Type: genai.TypeString,
				Enum: []string{"red", "green", "blue"},
			},
		},
		{
			name: "schema with nullable",
			input: &jsonschema.Schema{
				Type: "string",
				Extra: map[string]any{
					"nullable": true,
				},
			},
			expected: &genai.Schema{
				Type:     genai.TypeString,
				Nullable: func() *bool { b := true; return &b }(),
			},
		},
		{
			name: "string schema with length constraints",
			input: &jsonschema.Schema{
				Type:      "string",
				MinLength: func() *int { i := 5; return &i }(),
				MaxLength: func() *int { i := 50; return &i }(),
				Pattern:   "^[a-zA-Z]+$",
			},
			expected: &genai.Schema{
				Type:      genai.TypeString,
				MinLength: func() *int64 { i := int64(5); return &i }(),
				MaxLength: func() *int64 { i := int64(50); return &i }(),
				Pattern:   "^[a-zA-Z]+$",
			},
		},
		{
			name: "object with property constraints",
			input: &jsonschema.Schema{
				Type:          "object",
				MinProperties: func() *int { i := 1; return &i }(),
				MaxProperties: func() *int { i := 10; return &i }(),
			},
			expected: &genai.Schema{
				Type:          genai.TypeObject,
				MinProperties: func() *int64 { i := int64(1); return &i }(),
				MaxProperties: func() *int64 { i := int64(10); return &i }(),
			},
		},
		{
			name: "schema with example",
			input: &jsonschema.Schema{
				Type:     "string",
				Examples: []any{"sample value"},
			},
			expected: &genai.Schema{
				Type:    genai.TypeString,
				Example: []any{"sample value"},
			},
		},
		{
			name: "complex nested schema",
			input: &jsonschema.Schema{
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"users": {
						Type: "array",
						Items: &jsonschema.Schema{
							Type: "object",
							Properties: map[string]*jsonschema.Schema{
								"name": {Type: "string"},
								"emails": {
									Type: "array",
									Items: &jsonschema.Schema{
										Type: "string",
									},
								},
							},
							Required: []string{"name"},
						},
					},
				},
			},
			expected: &genai.Schema{
				Type: genai.TypeObject,
				Properties: map[string]*genai.Schema{
					"users": {
						Type: genai.TypeArray,
						Items: &genai.Schema{
							Type: genai.TypeObject,
							Properties: map[string]*genai.Schema{
								"name": {Type: genai.TypeString},
								"emails": {
									Type: genai.TypeArray,
									Items: &genai.Schema{
										Type: genai.TypeString,
									},
								},
							},
							Required: []string{"name"},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ToGeminiSchema(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ToGeminiSchema() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if diff := cmp.Diff(tt.expected, result); diff != "" {
				t.Errorf("ToGeminiSchema() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestValidateGeminiSchema(t *testing.T) {
	tests := []struct {
		name    string
		input   *genai.Schema
		wantErr bool
		errMsg  string
	}{
		{
			name:    "nil schema",
			input:   nil,
			wantErr: false,
		},
		{
			name: "valid string schema",
			input: &genai.Schema{
				Type: genai.TypeString,
			},
			wantErr: false,
		},
		{
			name: "string with valid format",
			input: &genai.Schema{
				Type:   genai.TypeString,
				Format: "date-time",
			},
			wantErr: false,
		},
		{
			name: "string with invalid format",
			input: &genai.Schema{
				Type:   genai.TypeString,
				Format: "invalid-format",
			},
			wantErr: true,
			errMsg:  "invalid format",
		},
		{
			name: "integer with valid format",
			input: &genai.Schema{
				Type:   genai.TypeInteger,
				Format: "int64",
			},
			wantErr: false,
		},
		{
			name: "integer with invalid format",
			input: &genai.Schema{
				Type:   genai.TypeInteger,
				Format: "date-time",
			},
			wantErr: true,
			errMsg:  "invalid format",
		},
		{
			name: "array without items",
			input: &genai.Schema{
				Type: genai.TypeArray,
			},
			wantErr: true,
			errMsg:  "array type requires items schema",
		},
		{
			name: "array with valid items",
			input: &genai.Schema{
				Type: genai.TypeArray,
				Items: &genai.Schema{
					Type: genai.TypeString,
				},
			},
			wantErr: false,
		},
		{
			name: "object with valid properties",
			input: &genai.Schema{
				Type: genai.TypeObject,
				Properties: map[string]*genai.Schema{
					"name": {Type: genai.TypeString},
					"age":  {Type: genai.TypeInteger},
				},
				Required: []string{"name"},
			},
			wantErr: false,
		},
		{
			name: "object with required field not in properties",
			input: &genai.Schema{
				Type: genai.TypeObject,
				Properties: map[string]*genai.Schema{
					"name": {Type: genai.TypeString},
				},
				Required: []string{"age"},
			},
			wantErr: true,
			errMsg:  "required field \"age\" not found in properties",
		},
		{
			name: "nested validation error",
			input: &genai.Schema{
				Type: genai.TypeArray,
				Items: &genai.Schema{
					Type:   genai.TypeString,
					Format: "invalid-format",
				},
			},
			wantErr: true,
			errMsg:  "invalid items schema",
		},
		{
			name: "nested object validation error",
			input: &genai.Schema{
				Type: genai.TypeObject,
				Properties: map[string]*genai.Schema{
					"data": {
						Type:   genai.TypeString,
						Format: "invalid-format",
					},
				},
			},
			wantErr: true,
			errMsg:  "invalid property data schema",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateGeminiSchema(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateGeminiSchema() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("ValidateGeminiSchema() error message %q does not contain expected %q", err.Error(), tt.errMsg)
				}
			}
		})
	}
}

func TestIntegration(t *testing.T) {
	// Test a complete flow from JSON schema to Gemini schema
	openapiSchema := &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"firstName": {
				Type:        "string",
				Description: "User's first name",
				MinLength:   func() *int { i := 1; return &i }(),
				MaxLength:   func() *int { i := 50; return &i }(),
			},
			"lastName": {
				Type:        "string",
				Description: "User's last name",
				MinLength:   func() *int { i := 1; return &i }(),
				MaxLength:   func() *int { i := 50; return &i }(),
			},
			"age": {
				Type:    "integer",
				Format:  "int32",
				Minimum: func() *float64 { f := 0.0; return &f }(),
				Maximum: func() *float64 { f := 150.0; return &f }(),
			},
			"email": {
				Type:   "string",
				Format: "email", // This should be removed as it's not supported
			},
			"preferences": {
				Type: "object",
				Properties: map[string]*jsonschema.Schema{
					"theme": {
						Type: "string",
						Enum: []any{"light", "dark"},
					},
					"notifications": {
						Type: "boolean",
					},
				},
			},
			"tags": {
				Type: "array",
				Items: &jsonschema.Schema{
					Type: "string",
				},
				MinItems: func() *int { i := 0; return &i }(),
				MaxItems: func() *int { i := 10; return &i }(),
			},
		},
		Required: []string{"firstName", "lastName", "email"},
	}

	// Convert to Gemini schema
	geminiSchema, err := ToGeminiSchema(openapiSchema)
	if err != nil {
		t.Fatalf("ToGeminiSchema() failed: %v", err)
	}

	// Validate the result
	if err := ValidateGeminiSchema(geminiSchema); err != nil {
		t.Fatalf("ValidateGeminiSchema() failed: %v", err)
	}

	// Verify the structure
	if geminiSchema.Type != genai.TypeObject {
		t.Errorf("Expected object type, got %v", geminiSchema.Type)
	}

	if len(geminiSchema.Properties) != 6 {
		t.Errorf("Expected 6 properties, got %d", len(geminiSchema.Properties))
	}

	// Check that firstName property is correctly converted
	firstName := geminiSchema.Properties["firstName"]
	if firstName == nil {
		t.Fatal("firstName property not found")
	}
	if firstName.Type != genai.TypeString {
		t.Errorf("firstName should be string type, got %v", firstName.Type)
	}
	if firstName.Description != "User's first name" {
		t.Errorf("firstName description mismatch: got %q", firstName.Description)
	}

	// Check that email format was removed (not supported)
	email := geminiSchema.Properties["email"]
	if email == nil {
		t.Fatal("email property not found")
	}
	if email.Format != "" {
		t.Errorf("email format should be removed, but got %q", email.Format)
	}

	// Check that age format was preserved (supported)
	age := geminiSchema.Properties["age"]
	if age == nil {
		t.Fatal("age property not found")
	}
	if age.Format != "int32" {
		t.Errorf("age format should be preserved, got %q", age.Format)
	}

	// Check nested object
	preferences := geminiSchema.Properties["preferences"]
	if preferences == nil {
		t.Fatal("preferences property not found")
	}
	if preferences.Type != genai.TypeObject {
		t.Errorf("preferences should be object type, got %v", preferences.Type)
	}

	// Check array with items
	tags := geminiSchema.Properties["tags"]
	if tags == nil {
		t.Fatal("tags property not found")
	}
	if tags.Type != genai.TypeArray {
		t.Errorf("tags should be array type, got %v", tags.Type)
	}
	if tags.Items == nil {
		t.Fatal("tags items should not be nil")
	}
	if tags.Items.Type != genai.TypeString {
		t.Errorf("tags items should be string type, got %v", tags.Items.Type)
	}

	// Check required fields
	expectedRequired := []string{"firstName", "lastName", "email"}
	if diff := cmp.Diff(expectedRequired, geminiSchema.Required); diff != "" {
		t.Errorf("Required fields mismatch (-want +got):\n%s", diff)
	}
}

// TestToolSystemIntegration demonstrates how to use the schema utility with the existing tool system
func TestToolSystemIntegration(t *testing.T) {
	// Simulate a JSON schema that might come from a tool definition
	openapiSchema := &jsonschema.Schema{
		Type: "object",
		Properties: map[string]*jsonschema.Schema{
			"query": {
				Type:        "string",
				Description: "Search query",
				MinLength:   func() *int { i := 1; return &i }(),
			},
			"maxResults": {
				Type:    "integer",
				Format:  "int32",
				Minimum: func() *float64 { f := 1.0; return &f }(),
				Maximum: func() *float64 { f := 100.0; return &f }(),
			},
			"includeMetadata": {
				Type: "boolean",
				// Note: Default is not supported in the current struct but could be in Extra
			},
		},
		Required: []string{"query"},
	}

	// Convert to Gemini schema
	geminiSchema, err := ToGeminiSchema(openapiSchema)
	if err != nil {
		t.Fatalf("Failed to convert schema: %v", err)
	}

	// Validate the converted schema
	if err := ValidateGeminiSchema(geminiSchema); err != nil {
		t.Fatalf("Schema validation failed: %v", err)
	}

	// The schema can now be used with genai.FunctionDeclaration
	functionDecl := &genai.FunctionDeclaration{
		Name:       "search_tool",
		Parameters: geminiSchema,
	}

	// Verify the function declaration is properly structured
	if functionDecl.Name != "search_tool" {
		t.Errorf("Expected function name 'search_tool', got %q", functionDecl.Name)
	}

	if functionDecl.Parameters.Type != genai.TypeObject {
		t.Errorf("Expected object type for parameters, got %v", functionDecl.Parameters.Type)
	}

	if len(functionDecl.Parameters.Properties) != 3 {
		t.Errorf("Expected 3 properties, got %d", len(functionDecl.Parameters.Properties))
	}

	if len(functionDecl.Parameters.Required) != 1 {
		t.Errorf("Expected 1 required field, got %d", len(functionDecl.Parameters.Required))
	}

	if functionDecl.Parameters.Required[0] != "query" {
		t.Errorf("Expected required field 'query', got %q", functionDecl.Parameters.Required[0])
	}
}
