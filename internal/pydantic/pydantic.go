// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package pydantic

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/bytedance/sonic"
)

// BaseModel represents the core validation model, equivalent to pydantic.BaseModel.
type BaseModel interface {
	// Validate performs data validation against the model schema
	Validate() error

	// ModelDump converts the model to a map representation
	ModelDump(options ...DumpOption) map[string]any

	// ModelDumpJSON converts the model to a JSON string
	ModelDumpJSON(options ...DumpOption) (string, error)

	// ModelCopy creates a deep or shallow copy of the model
	ModelCopy(deep bool) BaseModel

	// ModelSchema returns the JSON schema for the model
	ModelSchema() map[string]any

	// GetField returns a field value by name
	GetField(name string) (any, bool)

	// SetField sets a field value by name
	SetField(name string, value any) error
}

// Model is the basic implementation of BaseModel
type Model struct {
	fields       map[string]Field
	values       map[string]any
	fieldsSet    map[string]bool
	modelConfig  ModelConfig
	privateAttrs map[string]any
}

// Field represents a model field with validation constraints
type Field struct {
	Name        string
	Type        reflect.Type
	Required    bool
	Default     any
	Constraints []Constraint
	Description string
}

// Constraint represents a validation constraint
type Constraint interface {
	Validate(value any) error
	Name() string
}

// ModelConfig controls model behavior
type ModelConfig struct {
	ExtraForbid           bool
	ValidateAssignment    bool
	Frozen                bool
	PopulateByName        bool
	ArbitraryTypesAllowed bool
	ValidateDefaultValues bool
	JSONSchemaExtra       map[string]any
}

// DumpOption configures model serialization
type DumpOption func(*dumpOptions)

type dumpOptions struct {
	excludeUnset    bool
	excludeDefaults bool
	includePrivate  bool
}

// NewModel creates a new model with given fields and config
func NewModel(fields map[string]Field, config ModelConfig) *Model {
	return &Model{
		fields:       fields,
		values:       make(map[string]any),
		fieldsSet:    make(map[string]bool),
		modelConfig:  config,
		privateAttrs: make(map[string]any),
	}
}

// Validate validates all model fields
func (m *Model) Validate() error {
	var errors ValidationErrors

	for name, field := range m.fields {
		value, exists := m.values[name]

		// Check required fields
		if field.Required && !exists {
			errors = append(errors, ValidationError{
				Field:   name,
				Message: "field required",
			})
			continue
		}

		// Skip validation for unset fields
		if !exists {
			continue
		}

		// Check type
		if !isTypeCompatible(value, field.Type) {
			errors = append(errors, ValidationError{
				Field:   name,
				Message: fmt.Sprintf("expected %s, got %T", field.Type, value),
			})
			continue
		}

		// Apply constraints
		for _, constraint := range field.Constraints {
			if err := constraint.Validate(value); err != nil {
				errors = append(errors, ValidationError{
					Field:   name,
					Message: err.Error(),
				})
			}
		}
	}

	if len(errors) > 0 {
		return errors
	}

	return nil
}

// ModelDump converts the model to a map
func (m *Model) ModelDump(options ...DumpOption) map[string]any {
	opts := dumpOptions{}
	for _, option := range options {
		option(&opts)
	}

	result := make(map[string]any)

	for name, value := range m.values {
		// Skip unset fields if requested
		if opts.excludeUnset && !m.fieldsSet[name] {
			continue
		}

		// Skip default values if requested
		if opts.excludeDefaults {
			field := m.fields[name]
			if reflect.DeepEqual(value, field.Default) {
				continue
			}
		}

		// Handle nested BaseModels
		if model, ok := value.(BaseModel); ok {
			result[name] = model.ModelDump(options...)
		} else {
			result[name] = value
		}
	}

	return result
}

// ModelDumpJSON converts the model to a JSON string
func (m *Model) ModelDumpJSON(options ...DumpOption) (string, error) {
	data := m.ModelDump(options...)
	bytes, err := sonic.ConfigFastest.Marshal(data)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

// ModelCopy creates a copy of the model
func (m *Model) ModelCopy(deep bool) BaseModel {
	copy := NewModel(m.fields, m.modelConfig)

	for name, value := range m.values {
		if deep {
			// Deep copy value (handle nested models)
			if model, ok := value.(BaseModel); ok {
				copy.values[name] = model.ModelCopy(true)
			} else {
				// TODO: implement deep copy for other types
				copy.values[name] = value
			}
		} else {
			copy.values[name] = value
		}

		if m.fieldsSet[name] {
			copy.fieldsSet[name] = true
		}
	}

	return copy
}

// ModelSchema returns the JSON schema for the model
func (m *Model) ModelSchema() map[string]any {
	schema := map[string]any{
		"type":       "object",
		"properties": make(map[string]any),
	}

	properties := schema["properties"].(map[string]any)
	required := []string{}

	for name, field := range m.fields {
		property := make(map[string]any)

		// Determine type for JSON schema
		switch field.Type.Kind() {
		case reflect.String:
			property["type"] = "string"
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			property["type"] = "integer"
		case reflect.Float32, reflect.Float64:
			property["type"] = "number"
		case reflect.Bool:
			property["type"] = "boolean"
		case reflect.Slice, reflect.Array:
			property["type"] = "array"
		case reflect.Map, reflect.Struct:
			property["type"] = "object"
		}

		if field.Description != "" {
			property["description"] = field.Description
		}

		properties[name] = property

		if field.Required {
			required = append(required, name)
		}
	}

	if len(required) > 0 {
		schema["required"] = required
	}

	// Add any extra schema information from config
	for key, value := range m.modelConfig.JSONSchemaExtra {
		schema[key] = value
	}

	return schema
}

// GetField returns a field value by name
func (m *Model) GetField(name string) (any, bool) {
	value, ok := m.values[name]
	return value, ok
}

// SetField sets a field value by name
func (m *Model) SetField(name string, value any) error {
	// Check if model is frozen
	if m.modelConfig.Frozen {
		return fmt.Errorf("cannot modify frozen model")
	}

	// Check if field exists
	field, exists := m.fields[name]
	if !exists {
		if m.modelConfig.ExtraForbid {
			return fmt.Errorf("extra fields not permitted: %s", name)
		}
		// For non-extra-forbid models, just set the value
		m.values[name] = value
		m.fieldsSet[name] = true
		return nil
	}

	// Validate if required
	if m.modelConfig.ValidateAssignment {
		if !isTypeCompatible(value, field.Type) {
			return fmt.Errorf("expected %s, got %T", field.Type, value)
		}

		for _, constraint := range field.Constraints {
			if err := constraint.Validate(value); err != nil {
				return err
			}
		}
	}

	m.values[name] = value
	m.fieldsSet[name] = true
	return nil
}

// ValidationError represents a single validation error
type ValidationError struct {
	Field   string
	Message string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationErrors is a collection of validation errors
type ValidationErrors []ValidationError

func (e ValidationErrors) Error() string {
	if len(e) == 0 {
		return ""
	}

	messages := make([]string, len(e))
	for i, err := range e {
		messages[i] = err.Error()
	}

	return "validation errors:\n" + strings.Join(messages, "\n")
}

// ModelValidate validates data against a model
func ModelValidate[T any](data map[string]any) (T, error) {
	var model T
	// This would use reflection to initialize and validate the model
	// according to its field definitions and constraints
	return model, nil
}

// Helper function to check if a value is compatible with a type
func isTypeCompatible(value any, typ reflect.Type) bool {
	valueType := reflect.TypeOf(value)
	return valueType.AssignableTo(typ)
}
