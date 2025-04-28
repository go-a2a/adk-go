// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package godantic

import (
	"fmt"
	"reflect"
	"strings"
)

// Schema represents a model schema with fields and validation rules.
// Similar to Pydantic's internal model schema.
type Schema struct {
	Fields     map[string]*Field
	Config     Config
	Title      string
	Validators []ModelValidator
}

// Config represents model configuration options.
// Similar to Pydantic's ConfigDict.
type Config struct {
	Strict           bool
	AllowExtraFields bool
	PopulateByName   bool
	Title            string
	Description      string
}

// ModelValidator is a function that validates an entire model.
type ModelValidator func(*BaseModel) error

// SchemaFromStruct creates a new schema from a struct type.
func SchemaFromStruct(v any, opts ...ModelOption) (*Schema, error) {
	val := reflect.ValueOf(v)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return nil, fmt.Errorf("expected struct, got %T", v)
	}

	// Create schema with default config
	schema := &Schema{
		Fields: make(map[string]*Field),
		Config: Config{
			Strict:           false,
			AllowExtraFields: false,
			PopulateByName:   true,
		},
	}

	// Apply model options
	for _, opt := range opts {
		opt(&schema.Config)
	}

	// Get struct type
	typ := val.Type()

	// Set title to struct name if not specified
	if schema.Config.Title == "" {
		schema.Title = typ.Name()
	} else {
		schema.Title = schema.Config.Title
	}

	// Process struct fields
	for i := 0; i < typ.NumField(); i++ {
		structField := typ.Field(i)

		// Skip unexported fields
		if !structField.IsExported() {
			continue
		}

		field, err := fieldFromStructField(structField)
		if err != nil {
			return nil, err
		}

		schema.Fields[structField.Name] = field
	}

	return schema, nil
}

// fieldFromStructField creates a Field from a reflect.StructField.
func fieldFromStructField(structField reflect.StructField) (*Field, error) {
	field := &Field{
		Name:        structField.Name,
		Type:        structField.Type,
		Required:    false,
		Description: "",
		Validators:  nil,
	}

	// Process struct tags
	tag := structField.Tag.Get(`godantic`)
	if tag != "" {
		parts := strings.SplitSeq(tag, ",")
		for part := range parts {
			keyValue := strings.SplitN(part, "=", 2)
			key := keyValue[0]

			switch key {
			case `required`:
				field.Required = true

			case `default`:
				if len(keyValue) != 2 {
					return nil, fmt.Errorf("default value not specified for field %s", structField.Name)
				}
				// Parse default value based on field type
				defaultVal, err := parseDefaultValue(keyValue[1], structField.Type)
				if err != nil {
					return nil, fmt.Errorf("invalid default value for field %s: %v", structField.Name, err)
				}
				field.Default = defaultVal

			case `min`:
				if len(keyValue) != 2 {
					return nil, fmt.Errorf("min value not specified for field %s", structField.Name)
				}
				// Add min validator based on field type
				validator, err := minValidator(keyValue[1], structField.Type)
				if err != nil {
					return nil, fmt.Errorf("invalid min value for field %s: %v", structField.Name, err)
				}
				field.Validators = append(field.Validators, validator)

			case `max`:
				if len(keyValue) != 2 {
					return nil, fmt.Errorf("max value not specified for field %s", structField.Name)
				}
				// Add max validator based on field type
				validator, err := maxValidator(keyValue[1], structField.Type)
				if err != nil {
					return nil, fmt.Errorf("invalid max value for field %s: %v", structField.Name, err)
				}
				field.Validators = append(field.Validators, validator)
			}
		}
	}

	// Also check json tag for field alias
	jsonTag := structField.Tag.Get(`json`)
	if jsonTag != "" {
		parts := strings.Split(jsonTag, ",")
		if parts[0] != "" && parts[0] != "-" {
			field.Alias = parts[0]
		}
	}

	return field, nil
}

// JSONSchema returns the JSON schema for the schema.
func (s *Schema) JSONSchema() map[string]any {
	schema := map[string]any{
		"title":      s.Title,
		"type":       "object",
		"properties": make(map[string]any),
	}

	properties := schema["properties"].(map[string]any)
	required := []string{}

	for name, field := range s.Fields {
		fieldName := name
		if field.Alias != "" && s.Config.PopulateByName {
			fieldName = field.Alias
		}

		properties[fieldName] = field.JSONSchema()

		if field.Required {
			required = append(required, fieldName)
		}
	}

	if len(required) > 0 {
		schema["required"] = required
	}

	return schema
}
