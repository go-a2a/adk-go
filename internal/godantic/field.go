// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package godantic

import (
	"fmt"
	"maps"
	"reflect"
	"strconv"
)

// Field represents a model field with validation rules.
// Similar to Pydantic's Field class.
type Field struct {
	Name        string
	Alias       string
	Type        reflect.Type
	Required    bool
	Default     any
	Description string
	Validators  []FieldValidator
}

// FieldOption represents a configuration option for a field.
type FieldOption func(*Field)

// FieldValidator is a function that validates a field value.
type FieldValidator func(any) error

// Required marks a field as required.
func Required() FieldOption {
	return func(f *Field) {
		f.Required = true
	}
}

// Default sets a default value for a field.
func Default(value any) FieldOption {
	return func(f *Field) {
		f.Default = value
	}
}

// Description sets a description for a field.
func Description(desc string) FieldOption {
	return func(f *Field) {
		f.Description = desc
	}
}

// Validator adds a validator to a field.
func Validator(fn FieldValidator) FieldOption {
	return func(f *Field) {
		f.Validators = append(f.Validators, fn)
	}
}

// Validate validates a value against the field's validation rules.
func (f *Field) Validate(value any) error {
	// Check if value is nil
	if value == nil {
		if f.Required {
			return fmt.Errorf("field is required")
		}
		return nil
	}

	// Check type compatibility
	val := reflect.ValueOf(value)
	if !val.Type().AssignableTo(f.Type) {
		return fmt.Errorf("expected type %s, got %T", f.Type, value)
	}

	// Run validators
	for _, validator := range f.Validators {
		if err := validator(value); err != nil {
			return err
		}
	}

	return nil
}

// JSONSchema returns the JSON schema for the field.
func (f *Field) JSONSchema() map[string]any {
	schema := make(map[string]any)

	// Add description if available
	if f.Description != "" {
		schema["description"] = f.Description
	}

	// Add default if available
	if f.Default != nil {
		schema["default"] = f.Default
	}

	// Set type based on field type
	switch f.Type.Kind() {
	case reflect.Bool:
		schema["type"] = "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		schema["type"] = "integer"
	case reflect.Float32, reflect.Float64:
		schema["type"] = "number"
	case reflect.String:
		schema["type"] = "string"
	case reflect.Slice, reflect.Array:
		schema["type"] = "array"
		// Set items type based on slice element type
		elemType := f.Type.Elem()
		schema["items"] = schemaTypeFromReflectType(elemType)
	case reflect.Map:
		schema["type"] = "object"
	case reflect.Struct:
		schema["type"] = "object"
		// TODO: Handle nested struct fields
	case reflect.Ptr:
		// For pointers, get the element type
		elemType := f.Type.Elem()
		elemSchema := schemaTypeFromReflectType(elemType)
		maps.Copy(schema, elemSchema)
	default:
		schema["type"] = "string"
	}

	return schema
}

// schemaTypeFromReflectType returns a minimal JSON schema for a reflect.Type.
func schemaTypeFromReflectType(t reflect.Type) map[string]any {
	schema := make(map[string]any)

	switch t.Kind() {
	case reflect.Bool:
		schema["type"] = "boolean"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		schema["type"] = "integer"
	case reflect.Float32, reflect.Float64:
		schema["type"] = "number"
	case reflect.String:
		schema["type"] = "string"
	case reflect.Slice, reflect.Array:
		schema["type"] = "array"
	case reflect.Map, reflect.Struct:
		schema["type"] = "object"
	case reflect.Ptr:
		return schemaTypeFromReflectType(t.Elem())
	default:
		schema["type"] = "string"
	}

	return schema
}

// parseDefaultValue parses a default value string based on the field type.
func parseDefaultValue(value string, fieldType reflect.Type) (any, error) {
	switch fieldType.Kind() {
	case reflect.Bool:
		return strconv.ParseBool(value)
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		val, err := strconv.ParseInt(value, 10, 64)
		if err != nil {
			return nil, err
		}
		return reflect.ValueOf(val).Convert(fieldType).Interface(), nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		val, err := strconv.ParseUint(value, 10, 64)
		if err != nil {
			return nil, err
		}
		return reflect.ValueOf(val).Convert(fieldType).Interface(), nil
	case reflect.Float32, reflect.Float64:
		val, err := strconv.ParseFloat(value, 64)
		if err != nil {
			return nil, err
		}
		return reflect.ValueOf(val).Convert(fieldType).Interface(), nil
	case reflect.String:
		return value, nil
	default:
		return nil, fmt.Errorf("unsupported type for default value: %s", fieldType)
	}
}

// minValidator creates a validator for minimum value constraints.
func minValidator(minStr string, fieldType reflect.Type) (FieldValidator, error) {
	switch fieldType.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		min, err := strconv.ParseInt(minStr, 10, 64)
		if err != nil {
			return nil, err
		}

		return func(v any) error {
			val := reflect.ValueOf(v).Int()
			if val < min {
				return fmt.Errorf("value must be at least %d", min)
			}
			return nil
		}, nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		min, err := strconv.ParseUint(minStr, 10, 64)
		if err != nil {
			return nil, err
		}

		return func(v any) error {
			val := reflect.ValueOf(v).Uint()
			if val < min {
				return fmt.Errorf("value must be at least %d", min)
			}
			return nil
		}, nil

	case reflect.Float32, reflect.Float64:
		min, err := strconv.ParseFloat(minStr, 64)
		if err != nil {
			return nil, err
		}

		return func(v any) error {
			val := reflect.ValueOf(v).Float()
			if val < min {
				return fmt.Errorf("value must be at least %f", min)
			}
			return nil
		}, nil

	case reflect.String:
		min, err := strconv.Atoi(minStr)
		if err != nil {
			return nil, err
		}

		return func(v any) error {
			val := reflect.ValueOf(v).String()
			if len(val) < min {
				return fmt.Errorf("string length must be at least %d", min)
			}
			return nil
		}, nil

	case reflect.Slice, reflect.Array:
		min, err := strconv.Atoi(minStr)
		if err != nil {
			return nil, err
		}

		return func(v any) error {
			val := reflect.ValueOf(v)
			if val.Len() < min {
				return fmt.Errorf("length must be at least %d", min)
			}
			return nil
		}, nil

	default:
		return nil, fmt.Errorf("min constraint not supported for type %s", fieldType)
	}
}

// maxValidator creates a validator for maximum value constraints.
func maxValidator(maxStr string, fieldType reflect.Type) (FieldValidator, error) {
	switch fieldType.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		max, err := strconv.ParseInt(maxStr, 10, 64)
		if err != nil {
			return nil, err
		}

		return func(v any) error {
			val := reflect.ValueOf(v).Int()
			if val > max {
				return fmt.Errorf("value must be at most %d", max)
			}
			return nil
		}, nil

	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		max, err := strconv.ParseUint(maxStr, 10, 64)
		if err != nil {
			return nil, err
		}

		return func(v any) error {
			val := reflect.ValueOf(v).Uint()
			if val > max {
				return fmt.Errorf("value must be at most %d", max)
			}
			return nil
		}, nil

	case reflect.Float32, reflect.Float64:
		max, err := strconv.ParseFloat(maxStr, 64)
		if err != nil {
			return nil, err
		}

		return func(v any) error {
			val := reflect.ValueOf(v).Float()
			if val > max {
				return fmt.Errorf("value must be at most %f", max)
			}
			return nil
		}, nil

	case reflect.String:
		max, err := strconv.Atoi(maxStr)
		if err != nil {
			return nil, err
		}

		return func(v any) error {
			val := reflect.ValueOf(v).String()
			if len(val) > max {
				return fmt.Errorf("string length must be at most %d", max)
			}
			return nil
		}, nil

	case reflect.Slice, reflect.Array:
		max, err := strconv.Atoi(maxStr)
		if err != nil {
			return nil, err
		}

		return func(v any) error {
			val := reflect.ValueOf(v)
			if val.Len() > max {
				return fmt.Errorf("length must be at most %d", max)
			}
			return nil
		}, nil

	default:
		return nil, fmt.Errorf("max constraint not supported for type %s", fieldType)
	}
}
