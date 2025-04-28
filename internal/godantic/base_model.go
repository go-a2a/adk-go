// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package godantic

import (
	"fmt"
	"reflect"
	"slices"

	"github.com/bytedance/sonic"
)

// BaseModel is the core type that provides validation and serialization
// functionality similar to Pydantic's BaseModel.
type BaseModel struct {
	schema      *Schema
	values      map[string]any
	modelType   reflect.Type
	initialized bool
}

// ModelOption represents a configuration option for a model.
type ModelOption func(*Config)

// StrictMode enables strict type checking mode for the model.
func StrictMode() ModelOption {
	return func(c *Config) {
		c.Strict = true
	}
}

// AllowExtraFields allows the model to accept fields not defined in the schema.
func AllowExtraFields() ModelOption {
	return func(c *Config) {
		c.AllowExtraFields = true
	}
}

// ForbidExtraFields prevents the model from accepting fields not defined in the schema.
func ForbidExtraFields() ModelOption {
	return func(c *Config) {
		c.AllowExtraFields = false
	}
}

// New creates a new model instance from the provided struct and validates it.
func New(v any, opts ...ModelOption) (*BaseModel, error) {
	schema, err := SchemaFromStruct(v, opts...)
	if err != nil {
		return nil, err
	}

	model := &BaseModel{
		schema:    schema,
		values:    make(map[string]any),
		modelType: reflect.TypeOf(v),
	}

	// Validate and populate the model with values from v
	if err := model.validate(v); err != nil {
		return nil, err
	}

	model.initialized = true
	return model, nil
}

// newUnchecked creates a new model without validating it.
// Used internally for performance in cases where validation is known to be unnecessary.
func newUnchecked(schema *Schema, values map[string]any, modelType reflect.Type) *BaseModel {
	return &BaseModel{
		schema:      schema,
		values:      values,
		modelType:   modelType,
		initialized: true,
	}
}

// Validate validates data against the model's schema.
// Similar to Pydantic's model_validate method.
func (m *BaseModel) Validate(data any) error {
	return m.validate(data)
}

// validate is the internal validation method.
func (m *BaseModel) validate(data any) error {
	val := reflect.ValueOf(data)
	if val.Kind() == reflect.Ptr {
		val = val.Elem()
	}

	if val.Kind() != reflect.Struct {
		return &ValidationError{
			Message: fmt.Sprintf("expected struct, got %T", data),
		}
	}

	// Clear existing values
	m.values = make(map[string]any)

	// Validate and populate field values
	for fieldName, field := range m.schema.Fields {
		fieldValue := val.FieldByName(fieldName)

		// Skip if field doesn't exist in the struct
		if !fieldValue.IsValid() {
			if field.Required {
				return &ValidationError{
					Field:   fieldName,
					Message: "field is required but missing",
				}
			}
			// Use default value if available
			if field.Default != nil {
				m.values[fieldName] = field.Default
			}
			continue
		}

		// Get field value as interface
		fieldInterface := fieldValue.Interface()

		// Validate field
		if err := field.Validate(fieldInterface); err != nil {
			return &ValidationError{
				Field:   fieldName,
				Message: err.Error(),
				Value:   fieldInterface,
			}
		}

		// Store validated value
		m.values[fieldName] = fieldInterface
	}

	// Run model validators
	for _, validator := range m.schema.Validators {
		if err := validator(m); err != nil {
			return &ValidationError{
				Message: err.Error(),
			}
		}
	}

	return nil
}

// ValidateJSON validates JSON data against the model's schema.
// Similar to Pydantic's model_validate_json method.
func (m *BaseModel) ValidateJSON(data []byte) error {
	// Create a new instance of the underlying struct
	structPtr := reflect.New(m.modelType).Interface()

	// Unmarshal JSON into the struct
	if err := sonic.ConfigFastest.Unmarshal(data, structPtr); err != nil {
		return &ValidationError{
			Message: fmt.Sprintf("failed to unmarshal JSON: %v", err),
		}
	}

	// Validate the struct
	return m.validate(structPtr)
}

// Get retrieves a field value from the model.
func (m *BaseModel) Get(field string) (any, bool) {
	value, ok := m.values[field]
	return value, ok
}

// Set sets a field value in the model and validates it.
func (m *BaseModel) Set(field string, value any) error {
	fieldDef, ok := m.schema.Fields[field]
	if !ok {
		if !m.schema.Config.AllowExtraFields {
			return &ValidationError{
				Field:   field,
				Message: "field not defined in model schema",
				Value:   value,
			}
		}
		// Allow extra field if configured
		m.values[field] = value
		return nil
	}

	// Validate field
	if err := fieldDef.Validate(value); err != nil {
		return &ValidationError{
			Field:   field,
			Message: err.Error(),
			Value:   value,
		}
	}

	// Store validated value
	m.values[field] = value
	return nil
}

// Dump returns a map of the model's fields and values.
// Similar to Pydantic's model_dump method.
func (m *BaseModel) Dump(opts ...DumpOption) map[string]any {
	options := defaultDumpOptions()
	for _, opt := range opts {
		opt(&options)
	}

	result := make(map[string]any)

	// Add all values from the model
	for field, value := range m.values {
		if !options.shouldInclude(field) {
			continue
		}

		// Skip nil values if ExcludeNone is true
		if options.ExcludeNone && isNilValue(value) {
			continue
		}

		// Handle nested models
		if nestedModel, ok := value.(*BaseModel); ok {
			result[field] = nestedModel.Dump(opts...)
			continue
		}

		result[field] = value
	}

	return result
}

// isNilValue checks if a value is nil or a zero value.
func isNilValue(v any) bool {
	if v == nil {
		return true
	}

	val := reflect.ValueOf(v)
	switch val.Kind() {
	case reflect.Ptr, reflect.Interface, reflect.Map, reflect.Slice, reflect.Chan, reflect.Func:
		return val.IsNil()
	}

	return false
}

// DumpJSON returns a JSON representation of the model.
// Similar to Pydantic's model_dump_json method.
func (m *BaseModel) DumpJSON(opts ...DumpOption) ([]byte, error) {
	data := m.Dump(opts...)
	return sonic.ConfigFastest.Marshal(data)
}

// Copy creates a copy of the model.
func (m *BaseModel) Copy() *BaseModel {
	// Create a copy of values
	valuesCopy := make(map[string]any)
	for k, v := range m.values {
		// Handle nested models
		if nestedModel, ok := v.(*BaseModel); ok {
			valuesCopy[k] = nestedModel.Copy()
			continue
		}

		// For other values, just copy the reference
		// This is a shallow copy, which is consistent with Python's behavior
		valuesCopy[k] = v
	}

	return newUnchecked(m.schema, valuesCopy, m.modelType)
}

// Schema returns the model's schema.
// Similar to Pydantic's model_json_schema classmethod.
func (m *BaseModel) Schema() *Schema {
	return m.schema
}

// JSONSchema returns the JSON schema for the model.
// Similar to Pydantic's model_json_schema method.
func (m *BaseModel) JSONSchema() map[string]any {
	return m.schema.JSONSchema()
}

// DumpOptions controls the behavior of Dump and DumpJSON.
type DumpOptions struct {
	ExcludeFields []string
	IncludeFields []string
	ByAlias       bool
	ExcludeNone   bool
}

// defaultDumpOptions returns the default dump options.
func defaultDumpOptions() DumpOptions {
	return DumpOptions{
		ExcludeFields: nil,
		IncludeFields: nil,
		ByAlias:       false,
		ExcludeNone:   false,
	}
}

// shouldInclude determines if a field should be included in the output.
func (o *DumpOptions) shouldInclude(field string) bool {
	// If include list is specified, only include fields in that list
	if len(o.IncludeFields) > 0 {
		return slices.Contains(o.IncludeFields, field)
	}

	// If field is in exclude list, don't include it
	return slices.Contains(o.ExcludeFields, field)
}

// DumpOption represents an option for the Dump and DumpJSON methods.
type DumpOption func(*DumpOptions)

// ExcludeFields specifies fields to exclude from the output.
func ExcludeFields(fields ...string) DumpOption {
	return func(o *DumpOptions) {
		o.ExcludeFields = fields
	}
}

// IncludeFields specifies fields to include in the output.
func IncludeFields(fields ...string) DumpOption {
	return func(o *DumpOptions) {
		o.IncludeFields = fields
	}
}

// ByAlias specifies to use field aliases in the output.
func ByAlias() DumpOption {
	return func(o *DumpOptions) {
		o.ByAlias = true
	}
}

// ExcludeNone specifies to exclude nil values from the output.
func ExcludeNone() DumpOption {
	return func(o *DumpOptions) {
		o.ExcludeNone = true
	}
}
