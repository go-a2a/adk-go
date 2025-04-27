// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package godantic

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/bytedance/sonic"
)

// Helper function to populate a model from a map and validate it.
func populateAndValidate(modelPtr any, data map[string]any, baseModel *BaseModel) error {
	modelType := reflect.TypeOf(modelPtr).Elem()
	modelValue := reflect.ValueOf(modelPtr).Elem()

	// Track fields used from data to check for extra fields
	fieldsUsed := make(map[string]bool)

	// Populate the model from data
	for i := 0; i < modelType.NumField(); i++ {
		field := modelType.Field(i)

		// Skip BaseModel field
		if field.Type == reflect.TypeOf(BaseModel{}) {
			continue
		}

		fieldName := field.Name
		jsonTag := field.Tag.Get("json")
		jsonName := fieldName

		if jsonTag != "" {
			parts := strings.Split(jsonTag, ",")
			if parts[0] != "" {
				jsonName = parts[0]
			}
		}

		// Try to get value using exact field name or JSON alias
		var foundValue any
		var found bool

		// First check for exact field name
		if value, ok := data[fieldName]; ok {
			foundValue = value
			found = true
			fieldsUsed[fieldName] = true
		} else if baseModel.Config.PopulateByName {
			// Then check JSON name if different
			if jsonName != fieldName {
				if value, ok := data[jsonName]; ok {
					foundValue = value
					found = true
					fieldsUsed[jsonName] = true
				}
			}

			// Check field config for alias
			if baseModel.fieldConfig != nil {
				if config, ok := baseModel.fieldConfig[fieldName]; ok && config.Alias != "" {
					if value, ok := data[config.Alias]; ok {
						foundValue = value
						found = true
						fieldsUsed[config.Alias] = true
					}
				}
			}
		}

		// If found a value, try to set it
		if found {
			fieldValue := modelValue.Field(i)
			if fieldValue.CanSet() {
				// Convert value to field type if possible
				destType := fieldValue.Type()
				sourceValue := reflect.ValueOf(foundValue)

				// Handle primitive type conversions
				if sourceValue.Type().ConvertibleTo(destType) {
					fieldValue.Set(sourceValue.Convert(destType))
				} else {
					// For complex types, try JSON marshaling and unmarshaling
					jsonData, err := sonic.ConfigFastest.Marshal(foundValue)
					if err != nil {
						return fmt.Errorf("failed to convert field %s: %w", fieldName, err)
					}

					destPtr := reflect.New(destType).Interface()
					if err := sonic.ConfigFastest.Unmarshal(jsonData, destPtr); err != nil {
						return fmt.Errorf("failed to convert field %s: %w", fieldName, err)
					}

					fieldValue.Set(reflect.ValueOf(destPtr).Elem())
				}
			}
		}
	}

	// Check for extra fields
	if baseModel.Config.ExtraForbid {
		for key := range data {
			if !fieldsUsed[key] {
				return ModelError{
					Errors: []ValidationError{
						{
							Field:   key,
							Message: "extra fields not permitted",
						},
					},
				}
			}
		}
	}

	// Validate the model
	return baseModel.Validate(modelPtr)
}

// Helper function to extract BaseModel from a struct.
func extractBaseModel(modelPtr any) *BaseModel {
	modelValue := reflect.ValueOf(modelPtr).Elem()
	modelType := reflect.TypeOf(modelPtr).Elem()

	for i := 0; i < modelType.NumField(); i++ {
		field := modelType.Field(i)

		if field.Type == reflect.TypeOf(BaseModel{}) {
			baseModelField := modelValue.Field(i)
			baseModel := baseModelField.Addr().Interface().(*BaseModel)
			return baseModel
		}
	}

	return nil
}

// Helper function to parse field tags into FieldConfig.
func parseFieldTags(field reflect.StructField) FieldConfig {
	config := FieldConfig{}

	// Parse validate tag
	validateTag := field.Tag.Get("validate")
	if validateTag != "" {
		parts := strings.SplitSeq(validateTag, ",")
		for part := range parts {
			if part == "required" {
				config.Required = true
				continue
			}

			if strings.HasPrefix(part, "min=") {
				var min float64
				fmt.Sscanf(part, "min=%f", &min)
				config.Min = &min
				continue
			}

			if strings.HasPrefix(part, "max=") {
				var max float64
				fmt.Sscanf(part, "max=%f", &max)
				config.Max = &max
				continue
			}

			if strings.HasPrefix(part, "minLength=") {
				var minLength int
				fmt.Sscanf(part, "minLength=%d", &minLength)
				config.MinLength = &minLength
				continue
			}

			if strings.HasPrefix(part, "maxLength=") {
				var maxLength int
				fmt.Sscanf(part, "maxLength=%d", &maxLength)
				config.MaxLength = &maxLength
				continue
			}
		}
	}

	// Parse JSON tag for alias
	jsonTag := field.Tag.Get("json")
	if jsonTag != "" {
		parts := strings.Split(jsonTag, ",")
		if parts[0] != "" {
			config.Alias = parts[0]
		}
	}

	// Parse default tag
	defaultTag := field.Tag.Get("default")
	if defaultTag != "" {
		config.Default = defaultTag
	}

	return config
}
