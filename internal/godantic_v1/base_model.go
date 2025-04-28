// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package godantic

import (
	"fmt"
	"reflect"

	"github.com/bytedance/sonic"
)

// Model represents the interface all model types should implement.
type Model interface {
	Validate() error
	ValidateJSON(data []byte) error
	ToMap(exclude ...string) map[string]any
	ToJSON(exclude ...string) ([]byte, error)
	Copy(updates map[string]any) (Model, error)
}

// ValidatorFunc is a function that validates a field value.
type ValidatorFunc func(value any) error

// BaseModel is the foundation for data models with validation.
type BaseModel struct {
	Config      ModelConfig
	validators  map[string][]ValidatorFunc
	fieldConfig map[string]FieldConfig
}

// ModelConfig represents configuration for a model.
type ModelConfig struct {
	ExtraForbid    bool
	PopulateByName bool
	ValidateAll    bool
	FrozenFields   bool
}

// FieldConfig represents configuration for a model field.
type FieldConfig struct {
	Required  bool
	Default   any
	Min       *float64
	Max       *float64
	MinLength *int
	MaxLength *int
	Regex     *string
	Alias     string
}

// NewModel creates a new model instance from data.
func NewModel[T any](data map[string]any) (*T, error) {
	model := new(T)
	baseModel := extractBaseModel(model)

	if baseModel == nil {
		return nil, fmt.Errorf("model must embed BaseModel")
	}

	if err := populateAndValidate(model, data, baseModel); err != nil {
		return nil, err
	}

	return model, nil
}

// NewModelFromJSON creates a new model instance from JSON.
func NewModelFromJSON[T any](data []byte) (*T, error) {
	var mapData map[string]any
	if err := sonic.ConfigFastest.Unmarshal(data, &mapData); err != nil {
		return nil, err
	}

	return NewModel[T](mapData)
}

// RegisterValidator registers a validator for a field.
func (m *BaseModel) RegisterValidator(field string, validator ValidatorFunc) {
	if m.validators == nil {
		m.validators = make(map[string][]ValidatorFunc)
	}

	m.validators[field] = append(m.validators[field], validator)
}

// Validate validates model fields.
func (m *BaseModel) Validate(modelPtr any) error {
	modelType := reflect.TypeOf(modelPtr).Elem()
	modelValue := reflect.ValueOf(modelPtr).Elem()
	var errors []ValidationError

	for i := 0; i < modelType.NumField(); i++ {
		field := modelType.Field(i)

		// Skip BaseModel field
		if field.Type == reflect.TypeOf(BaseModel{}) {
			continue
		}

		fieldValue := modelValue.Field(i)
		fieldName := field.Name

		// Get field config from tags
		config := parseFieldTags(field)

		// Store field config for later use
		if m.fieldConfig == nil {
			m.fieldConfig = make(map[string]FieldConfig)
		}
		m.fieldConfig[fieldName] = config

		// Check required
		if config.Required && fieldValue.IsZero() {
			errors = append(errors, ValidationError{
				Field:   fieldName,
				Message: "field is required",
			})
			if !m.Config.ValidateAll {
				break
			}
			continue
		}

		// Run field validators
		if fieldValidators, ok := m.validators[fieldName]; ok {
			for _, validator := range fieldValidators {
				if err := validator(fieldValue.Interface()); err != nil {
					errors = append(errors, ValidationError{
						Field:   fieldName,
						Message: err.Error(),
					})
					if !m.Config.ValidateAll {
						break
					}
				}
			}
		}

		// Validate nested models
		if fieldValue.Kind() == reflect.Struct {
			if nestedModel, ok := fieldValue.Addr().Interface().(Model); ok {
				if err := nestedModel.Validate(); err != nil {
					if modelErr, ok := err.(ModelError); ok {
						for _, valErr := range modelErr.Errors {
							errors = append(errors, ValidationError{
								Field:   fieldName + "." + valErr.Field,
								Message: valErr.Message,
							})
						}
					} else {
						errors = append(errors, ValidationError{
							Field:   fieldName,
							Message: err.Error(),
						})
					}
					if !m.Config.ValidateAll {
						break
					}
				}
			}
		}
	}

	if len(errors) > 0 {
		return ModelError{Errors: errors}
	}

	return nil
}

// ValidateJSON validates a model from JSON data.
func (m *BaseModel) ValidateJSON(modelPtr any, data []byte) error {
	var mapData map[string]any
	if err := sonic.ConfigFastest.Unmarshal(data, &mapData); err != nil {
		return err
	}

	return populateAndValidate(modelPtr, mapData, m)
}

// ToMap converts a model to a map.
func (m *BaseModel) ToMap(modelPtr any, exclude ...string) map[string]any {
	result := make(map[string]any)
	excludeMap := make(map[string]bool)

	for _, field := range exclude {
		excludeMap[field] = true
	}

	modelType := reflect.TypeOf(modelPtr).Elem()
	modelValue := reflect.ValueOf(modelPtr).Elem()

	for i := 0; i < modelType.NumField(); i++ {
		field := modelType.Field(i)

		// Skip BaseModel field
		if field.Type == reflect.TypeOf(BaseModel{}) {
			continue
		}

		fieldName := field.Name
		if excludeMap[fieldName] {
			continue
		}

		fieldValue := modelValue.Field(i)

		// Check for alias
		if m.fieldConfig != nil {
			if config, ok := m.fieldConfig[fieldName]; ok && config.Alias != "" {
				fieldName = config.Alias
			}
		}

		// Handle nested models
		if fieldValue.Kind() == reflect.Struct {
			if nestedModel, ok := fieldValue.Addr().Interface().(Model); ok {
				result[fieldName] = nestedModel.ToMap()
				continue
			}
		}

		result[fieldName] = fieldValue.Interface()
	}

	return result
}

// ToJSON converts a model to JSON.
func (m *BaseModel) ToJSON(modelPtr any, exclude ...string) ([]byte, error) {
	return sonic.ConfigFastest.Marshal(m.ToMap(modelPtr, exclude...))
}

// Copy creates a copy of the model with optional updates.
func (m *BaseModel) Copy(modelPtr any, updates map[string]any) (any, error) {
	modelType := reflect.TypeOf(modelPtr).Elem()
	newModel := reflect.New(modelType).Interface()

	// Copy the original model
	modelValue := reflect.ValueOf(modelPtr).Elem()
	newModelValue := reflect.ValueOf(newModel).Elem()
	newModelValue.Set(modelValue)

	// Apply updates
	if len(updates) > 0 {
		if err := populateAndValidate(newModel, updates, m); err != nil {
			return nil, err
		}
	}

	return newModel, nil
}

// NewBaseModel creates a new BaseModel with optional configuration.
func NewBaseModel(config ...ModelConfig) BaseModel {
	var cfg ModelConfig
	if len(config) > 0 {
		cfg = config[0]
	}

	return BaseModel{
		Config:      cfg,
		validators:  make(map[string][]ValidatorFunc),
		fieldConfig: make(map[string]FieldConfig),
	}
}
