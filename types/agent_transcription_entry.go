// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"

	"google.golang.org/genai"
)

// TranscriptionEntry represents a store the data that can be used for transcription.
type TranscriptionEntry struct {
	// The role that created this data, typically "user" or "model".
	Role string

	// The data that can be used for transcription.
	Data any // *genai.Blob or *genai.Content
}

// NewTranscriptionEntry creates a new [TranscriptionEntry].
func NewTranscriptionEntry(role string, data any) *TranscriptionEntry {
	switch data.(type) {
	case *genai.Blob, *genai.Content:
		// valid, nothing to do
	default:
		panic(fmt.Errorf("data type is either *genai.Blob or *genai.Content: %T", data))
	}

	return &TranscriptionEntry{
		Role: role,
		Data: data,
	}
}
