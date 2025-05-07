// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"time"
)

// TranscriptionEntry represents an entry in a transcription.
type TranscriptionEntry struct {
	// Timestamp is when the entry was created.
	Timestamp time.Time

	// Role is who created the entry (user, assistant, system, etc.).
	Role string

	// Content is the text content of the entry.
	Content string

	// Metadata contains additional information about the entry.
	Metadata map[string]any
}

// NewTranscriptionEntry creates a new transcription entry.
func NewTranscriptionEntry(role, content string) *TranscriptionEntry {
	return &TranscriptionEntry{
		Role:      role,
		Content:   content,
		Timestamp: time.Now(),
		Metadata:  make(map[string]any),
	}
}

// WithMetadata adds metadata to the entry.
func (e *TranscriptionEntry) WithMetadata(key string, value any) *TranscriptionEntry {
	e.Metadata[key] = value
	return e
}

// Transcription represents a conversation transcription.
type Transcription struct {
	// Entries are the entries in the transcription.
	Entries []*TranscriptionEntry

	// Metadata contains additional information about the transcription.
	Metadata map[string]any
}

// NewTranscription creates a new transcription.
func NewTranscription() *Transcription {
	return &Transcription{
		Entries:  []*TranscriptionEntry{},
		Metadata: make(map[string]any),
	}
}

// AddEntry adds an entry to the transcription.
func (t *Transcription) AddEntry(entry *TranscriptionEntry) {
	t.Entries = append(t.Entries, entry)
}

// GetLatest returns the latest entry in the transcription.
func (t *Transcription) GetLatest() *TranscriptionEntry {
	if len(t.Entries) == 0 {
		return nil
	}

	return t.Entries[len(t.Entries)-1]
}

// WithMetadata adds metadata to the transcription.
func (t *Transcription) WithMetadata(key string, value any) *Transcription {
	t.Metadata[key] = value
	return t
}
