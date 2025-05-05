// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package agent

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
		Timestamp: time.Now(),
		Role:      role,
		Content:   content,
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
		Entries:  make([]*TranscriptionEntry, 0),
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

// ConvertToMemory converts the transcription to a memory.
func (t *Transcription) ConvertToMemory() Memory {
	memory := NewSimpleMemory(len(t.Entries))

	for _, entry := range t.Entries {
		memory.Add(entry.Role, entry.Content)
	}

	return memory
}

// WithMetadata adds metadata to the transcription.
func (t *Transcription) WithMetadata(key string, value any) *Transcription {
	t.Metadata[key] = value
	return t
}
