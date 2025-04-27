// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package godantic

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/bytedance/sonic"
)

// ModelDumpOptions contains options for controlling the behavior of ModelDump.
type ModelDumpOptions struct {
	// Mode specifies the serialization mode ("json" or "python").
	Mode string

	// Include is a set of fields to include in the output.
	Include map[string]any

	// Exclude is a set of fields to exclude from the output.
	Exclude map[string]any

	// Context provides additional context for the serializer.
	Context any

	// ByAlias specifies whether to use field aliases in the output.
	ByAlias bool

	// ExcludeUnset excludes fields that haven't been explicitly set.
	ExcludeUnset bool

	// ExcludeDefaults excludes fields set to their default values.
	ExcludeDefaults bool

	// ExcludeNone excludes fields with nil values.
	ExcludeNone bool

	// RoundTrip ensures values are valid as input for non-idempotent types.
	RoundTrip bool

	// Warnings controls how serialization errors are handled.
	// "none" ignores errors, "warn" logs them, "error" raises them.
	Warnings string

	// SerializeAsAny enables duck-typing serialization behavior.
	SerializeAsAny bool
}

// DefaultModelDumpOptions returns the default options for ModelDump.
func DefaultModelDumpOptions() *ModelDumpOptions {
	return &ModelDumpOptions{
		Mode:            "python",
		ByAlias:         false,
		ExcludeUnset:    false,
		ExcludeDefaults: false,
		ExcludeNone:     false,
		RoundTrip:       false,
		Warnings:        "error",
		SerializeAsAny:  false,
	}
}

// BaseModel is the base struct for all model types.
type BaseModel struct {
	// FieldsSet contains the names of fields that were explicitly set.
	FieldsSet map[string]struct{}

	// Extra contains additional values for models that allow extra fields.
	Extra map[string]any
}

// ModelDump generates a map representation of the model.
func (m *BaseModel) ModelDump(opts *ModelDumpOptions) (map[string]any, error) {
	if opts == nil {
		opts = DefaultModelDumpOptions()
	}

	return m.toPython(opts)
}

// toPython converts the model to a map based on the provided options.
func (m *BaseModel) toPython(opts *ModelDumpOptions) (map[string]any, error) {
	result := make(map[string]any)

	val := reflect.ValueOf(m).Elem()
	typ := val.Type()

	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		fieldValue := val.Field(i)

		if !field.IsExported() {
			continue
		}

		fieldName := field.Name

		if opts.ByAlias {
			if jsonTag := field.Tag.Get("json"); jsonTag != "" {
				parts := strings.Split(jsonTag, ",")
				if parts[0] != "" && parts[0] != "-" {
					fieldName = parts[0]
				}
			}
		}

		if shouldSkipField(fieldName, opts) {
			continue
		}

		if opts.ExcludeUnset {
			if _, isSet := m.FieldsSet[field.Name]; !isSet {
				continue
			}
		}

		if opts.ExcludeNone && fieldValue.IsNil() {
			continue
		}

		var fieldVal any

		if fieldValue.Kind() == reflect.Ptr && !fieldValue.IsNil() {
			nestedValue := fieldValue.Elem()

			if nestedModel, ok := fieldValue.Interface().(interface {
				ModelDump(*ModelDumpOptions) (map[string]any, error)
			}); ok {
				nestedMap, err := nestedModel.ModelDump(opts)
				if err != nil {
					return nil, err
				}
				fieldVal = nestedMap
			} else {
				fieldVal = nestedValue.Interface()
			}
		} else {
			fieldVal = fieldValue.Interface()
		}

		result[fieldName] = fieldVal
	}

	if m.Extra != nil {
		for k, v := range m.Extra {
			if _, exists := result[k]; !exists {
				result[k] = v
			}
		}
	}

	if opts.Mode == "json" {
		_, err := sonic.ConfigFastest.Marshal(result)
		if err != nil {
			return nil, fmt.Errorf("non-JSON-serializable field found: %w", err)
		}
	}

	return result, nil
}

// shouldSkipField determines if a field should be skipped based on Include/Exclude options.
func shouldSkipField(fieldName string, opts *ModelDumpOptions) bool {
	if opts.Include != nil {
		_, included := opts.Include[fieldName]
		return !included
	}

	if opts.Exclude != nil {
		_, excluded := opts.Exclude[fieldName]
		return excluded
	}

	return false
}

// ModelDumpJSON returns a JSON string representation of the model.
func (m *BaseModel) ModelDumpJSON(opts *ModelDumpOptions) (string, error) {
	if opts == nil {
		opts = DefaultModelDumpOptions()
	}

	jsonOpts := *opts
	jsonOpts.Mode = "json"

	data, err := m.ModelDump(&jsonOpts)
	if err != nil {
		return "", err
	}

	jsonBytes, err := sonic.ConfigFastest.MarshalToString(data)
	if err != nil {
		return "", err
	}

	return jsonBytes, nil
}
