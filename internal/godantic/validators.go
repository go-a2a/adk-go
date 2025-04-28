// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package godantic

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"
)

// Common validators
// Similar to Pydantic's validator functionality

// StringMinLength creates a validator that checks if a string has at least the given length.
func StringMinLength(min int) FieldValidator {
	return func(v any) error {
		str, ok := v.(string)
		if !ok {
			return fmt.Errorf("expected string, got %T", v)
		}

		if len(str) < min {
			return fmt.Errorf("string length must be at least %d", min)
		}

		return nil
	}
}

// StringMaxLength creates a validator that checks if a string has at most the given length.
func StringMaxLength(max int) FieldValidator {
	return func(v any) error {
		str, ok := v.(string)
		if !ok {
			return fmt.Errorf("expected string, got %T", v)
		}

		if len(str) > max {
			return fmt.Errorf("string length must be at most %d", max)
		}

		return nil
	}
}

// StringPattern creates a validator that checks if a string matches the given pattern.
func StringPattern(pattern string) FieldValidator {
	re, err := regexp.Compile(pattern)
	if err != nil {
		panic(fmt.Sprintf("invalid pattern: %v", err))
	}

	return func(v any) error {
		str, ok := v.(string)
		if !ok {
			return fmt.Errorf("expected string, got %T", v)
		}

		if !re.MatchString(str) {
			return fmt.Errorf("string must match pattern '%s'", pattern)
		}

		return nil
	}
}

// EmailValidator creates a validator that checks if a string is a valid email address.
func EmailValidator() FieldValidator {
	// Simple email regex for demonstration purposes
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	return StringPattern(pattern)
}

// URLValidator creates a validator that checks if a string is a valid URL.
func URLValidator() FieldValidator {
	// Simple URL regex for demonstration purposes
	pattern := `^(http|https)://[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(/.*)?$`
	return StringPattern(pattern)
}

// IntMinValue creates a validator that checks if an integer is at least the given value.
func IntMinValue(min int64) FieldValidator {
	return func(v any) error {
		val := reflect.ValueOf(v)

		switch val.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if val.Int() < min {
				return fmt.Errorf("value must be at least %d", min)
			}
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			if val.Uint() < uint64(min) && min >= 0 {
				return fmt.Errorf("value must be at least %d", min)
			}
		default:
			return fmt.Errorf("expected integer, got %T", v)
		}

		return nil
	}
}

// IntMaxValue creates a validator that checks if an integer is at most the given value.
func IntMaxValue(max int64) FieldValidator {
	return func(v any) error {
		val := reflect.ValueOf(v)

		switch val.Kind() {
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
			if val.Int() > max {
				return fmt.Errorf("value must be at most %d", max)
			}
		case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
			if max < 0 || val.Uint() > uint64(max) {
				return fmt.Errorf("value must be at most %d", max)
			}
		default:
			return fmt.Errorf("expected integer, got %T", v)
		}

		return nil
	}
}

// FloatMinValue creates a validator that checks if a float is at least the given value.
func FloatMinValue(min float64) FieldValidator {
	return func(v any) error {
		val := reflect.ValueOf(v)

		switch val.Kind() {
		case reflect.Float32, reflect.Float64:
			if val.Float() < min {
				return fmt.Errorf("value must be at least %f", min)
			}
		default:
			return fmt.Errorf("expected float, got %T", v)
		}

		return nil
	}
}

// FloatMaxValue creates a validator that checks if a float is at most the given value.
func FloatMaxValue(max float64) FieldValidator {
	return func(v any) error {
		val := reflect.ValueOf(v)

		switch val.Kind() {
		case reflect.Float32, reflect.Float64:
			if val.Float() > max {
				return fmt.Errorf("value must be at most %f", max)
			}
		default:
			return fmt.Errorf("expected float, got %T", v)
		}

		return nil
	}
}

// SliceMinLength creates a validator that checks if a slice has at least the given length.
func SliceMinLength(min int) FieldValidator {
	return func(v any) error {
		val := reflect.ValueOf(v)

		switch val.Kind() {
		case reflect.Slice, reflect.Array:
			if val.Len() < min {
				return fmt.Errorf("slice length must be at least %d", min)
			}
		default:
			return fmt.Errorf("expected slice or array, got %T", v)
		}

		return nil
	}
}

// SliceMaxLength creates a validator that checks if a slice has at most the given length.
func SliceMaxLength(max int) FieldValidator {
	return func(v any) error {
		val := reflect.ValueOf(v)

		switch val.Kind() {
		case reflect.Slice, reflect.Array:
			if val.Len() > max {
				return fmt.Errorf("slice length must be at most %d", max)
			}
		default:
			return fmt.Errorf("expected slice or array, got %T", v)
		}

		return nil
	}
}

// OneOf creates a validator that checks if a value is one of the given values.
func OneOf(values ...any) FieldValidator {
	return func(v any) error {
		for _, value := range values {
			if reflect.DeepEqual(v, value) {
				return nil
			}
		}

		valuesStr := make([]string, 0, len(values))
		for _, value := range values {
			valuesStr = append(valuesStr, fmt.Sprintf("%v", value))
		}

		return fmt.Errorf("value must be one of [%s]", strings.Join(valuesStr, ", "))
	}
}
