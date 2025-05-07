// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"log/slog"
)

// InMemoryOption configures an InMemoryService.
type InMemoryOption func(*InMemoryService)

// WithLogger sets the logger for the InMemoryService.
func WithLogger(logger *slog.Logger) InMemoryOption {
	return func(s *InMemoryService) {
		s.logger = logger
	}
}
