// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"fmt"
	"log/slog"
	"math"

	"github.com/go-a2a/adk-go/observability"
)

// StreamingMode defines different modes for response streaming.
type StreamingMode int

const (
	// StreamingModeNone disables streaming responses.
	StreamingModeNone StreamingMode = iota

	// StreamingModeSSE represents Server-Sent Events streaming mode.
	StreamingModeSSE

	// StreamingModeBIDI represents Bidirectional streaming mode.
	StreamingModeBIDI
)

// String returns the string representation of a StreamingMode.
func (s StreamingMode) String() string {
	switch s {
	case StreamingModeNone:
		return "none"
	case StreamingModeSSE:
		return "sse"
	case StreamingModeBIDI:
		return "bidi"
	default:
		return "unknown"
	}
}

// SpeechConfig defines configuration for speech input/output in agents.
type SpeechConfig struct {
	// InputEnabled determines if speech input is enabled
	InputEnabled bool `json:"input_enabled"`

	// OutputEnabled determines if speech output is enabled
	OutputEnabled bool `json:"output_enabled"`

	// InputLanguage is the language code for speech input
	InputLanguage string `json:"input_language,omitempty"`

	// OutputLanguage is the language code for speech output
	OutputLanguage string `json:"output_language,omitempty"`

	// Voice is the voice to use for speech output
	Voice string `json:"voice,omitempty"`
}

// ResponseModality represents the type of response an agent can produce.
type ResponseModality string

const (
	// ResponseModalityText indicates text output is supported.
	ResponseModalityText ResponseModality = "text"

	// ResponseModalitySpeech indicates speech output is supported.
	ResponseModalitySpeech ResponseModality = "speech"

	// ResponseModalityVideo indicates video output is supported.
	ResponseModalityVideo ResponseModality = "video"
)

// RunConfig defines configuration options for an agent run.
type RunConfig struct {
	// SpeechConfig provides configuration for speech capabilities
	SpeechConfig *SpeechConfig `json:"speech_config,omitempty"`

	// ResponseModalities defines the allowed output modalities for this run
	ResponseModalities []ResponseModality `json:"response_modalities,omitempty"`

	// SaveInputBlobsAsArtifacts determines if input blobs should be saved
	SaveInputBlobsAsArtifacts bool `json:"save_input_blobs_as_artifacts"`

	// SupportCFC enables experimental compositional function calling
	SupportCFC bool `json:"support_cfc"`

	// StreamingMode defines how streaming responses are handled
	StreamingMode StreamingMode `json:"streaming_mode"`

	// MaxLLMCalls limits the total number of LLM calls for an agent run
	MaxLLMCalls int `json:"max_llm_calls"`
}

// NewRunConfig creates a new RunConfig with default values.
func NewRunConfig() *RunConfig {
	return &RunConfig{
		ResponseModalities:        []ResponseModality{ResponseModalityText},
		SaveInputBlobsAsArtifacts: false,
		SupportCFC:                false,
		StreamingMode:             StreamingModeNone,
		MaxLLMCalls:               10, // Default max LLM calls
	}
}

// WithSpeechConfig sets the speech configuration.
func (r *RunConfig) WithSpeechConfig(config *SpeechConfig) *RunConfig {
	r.SpeechConfig = config
	return r
}

// WithResponseModalities sets the allowed response modalities.
func (r *RunConfig) WithResponseModalities(modalities ...ResponseModality) *RunConfig {
	r.ResponseModalities = modalities
	return r
}

// WithSaveInputBlobsAsArtifacts sets whether input blobs should be saved as artifacts.
func (r *RunConfig) WithSaveInputBlobsAsArtifacts(save bool) *RunConfig {
	r.SaveInputBlobsAsArtifacts = save
	return r
}

// WithSupportCFC sets whether compositional function calling is supported.
func (r *RunConfig) WithSupportCFC(support bool) *RunConfig {
	r.SupportCFC = support
	return r
}

// WithStreamingMode sets the streaming mode.
func (r *RunConfig) WithStreamingMode(mode StreamingMode) *RunConfig {
	r.StreamingMode = mode
	return r
}

// WithMaxLLMCalls sets the maximum number of LLM calls.
// Values <= 0 will log a warning and use a sensible default.
// Returns an error if the value exceeds the system's maximum int.
func (r *RunConfig) WithMaxLLMCalls(max int) (*RunConfig, error) {
	if max == math.MaxInt {
		return nil, fmt.Errorf("max_llm_calls cannot be set to maximum integer value")
	}

	if max <= 0 {
		// Log a warning but use a sensible default
		observability.Logger(nil).Warn(
			"Invalid max_llm_calls value, using default",
			slog.Int("provided_value", max),
			slog.Int("default_value", 10),
		)
		r.MaxLLMCalls = 10
	} else {
		r.MaxLLMCalls = max
	}

	return r, nil
}

// ValidateMaxLLMCalls checks if the maximum number of LLM calls is valid.
func (r *RunConfig) ValidateMaxLLMCalls() error {
	if r.MaxLLMCalls <= 0 {
		return fmt.Errorf("max_llm_calls must be greater than 0, got: %d", r.MaxLLMCalls)
	}

	if r.MaxLLMCalls == math.MaxInt {
		return fmt.Errorf("max_llm_calls cannot be set to maximum integer value")
	}

	return nil
}

// HasResponseModality checks if a specific modality is supported.
func (r *RunConfig) HasResponseModality(modality ResponseModality) bool {
	for _, m := range r.ResponseModalities {
		if m == modality {
			return true
		}
	}
	return false
}

// IsStreamingEnabled returns true if any form of streaming is enabled.
func (r *RunConfig) IsStreamingEnabled() bool {
	return r.StreamingMode != StreamingModeNone
}
