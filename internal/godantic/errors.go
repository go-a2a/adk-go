// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package godantic

import (
	"fmt"
	"strings"
)

// ValidationError represents a validation error.
// Similar to Pydantic's ValidationError.
type ValidationError struct {
	Field   string
	Message string
	Value   any
	Path    []string // Path to nested errors for nested models
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	if e.Field == "" {
		return e.Message
	}

	path := e.Field
	if len(e.Path) > 0 {
		path = fmt.Sprintf("%s.%s", strings.Join(e.Path, "."), e.Field)
	}

	if e.Value != nil {
		return fmt.Sprintf("validation error for '%s': %s (got %v)", path, e.Message, e.Value)
	}

	return fmt.Sprintf("validation error for '%s': %s", path, e.Message)
}

// ValidationErrors represents multiple validation errors.
// Similar to Pydantic's multiple error handling.
type ValidationErrors struct {
	Errors []*ValidationError
}

// Error implements the error interface.
func (e *ValidationErrors) Error() string {
	if len(e.Errors) == 0 {
		return "validation errors"
	}

	messages := make([]string, 0, len(e.Errors))
	for _, err := range e.Errors {
		messages = append(messages, err.Error())
	}

	return strings.Join(messages, "\n")
}

// Unwrap returns the underlying errors.
func (e *ValidationErrors) Unwrap() []error {
	errs := make([]error, len(e.Errors))
	for i, err := range e.Errors {
		errs[i] = err
	}
	return errs
}

// Add adds a validation error.
func (e *ValidationErrors) Add(err *ValidationError) {
	e.Errors = append(e.Errors, err)
}

// HasErrors returns true if there are validation errors.
func (e *ValidationErrors) HasErrors() bool {
	return len(e.Errors) > 0
}

// NewValidationErrors creates a new ValidationErrors instance.
func NewValidationErrors() *ValidationErrors {
	return &ValidationErrors{
		Errors: []*ValidationError{},
	}
}

// SchemaError represents an error in the schema definition.
// Similar to Pydantic's configuration errors.
type SchemaError struct {
	Message string
	Field   string
}

// Error implements the error interface.
func (e *SchemaError) Error() string {
	if e.Field == "" {
		return fmt.Sprintf("schema error: %s", e.Message)
	}
	return fmt.Sprintf("schema error for field '%s': %s", e.Field, e.Message)
}
