// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package godantic

import (
	"fmt"
	"strings"
)

// ValidationError represents a validation error.
type ValidationError struct {
	Field   string
	Message string
}

// ModelError contains all validation errors.
type ModelError struct {
	Errors []ValidationError
}

func (e ModelError) Error() string {
	if len(e.Errors) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("validation failed for model:\n")
	for _, err := range e.Errors {
		sb.WriteString(fmt.Sprintf("  %s: %s\n", err.Field, err.Message))
	}
	return sb.String()
}
