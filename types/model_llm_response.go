// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"google.golang.org/genai"
)

// LLMResponse represents a LLM response class that provides the first candidate response from the
// model if available. Otherwise, returns error code and message.
type LLMResponse struct {
	// Content is the content of the response.
	Content *genai.Content

	// GroundingMetadata is the grounding metadata of the response.
	GroundingMetadata *genai.GroundingMetadata

	// Partial indicates whether the text content is part of an unfinished text stream.
	// Only used for streaming mode and when the content is plain text.
	Partial bool

	// TurnComplete indicates whether the response from the model is complete.
	// Only used for streaming mode.
	TurnComplete bool

	// ErrorCode is the error code if the response is an error. Code varies by model.
	ErrorCode string

	// ErrorMessage is the error message if the response is an error.
	ErrorMessage string

	// Interrupted indicates that LLM was interrupted when generating the content.
	// Usually it's due to user interruption during a bidirectional streaming.
	Interrupted bool

	// CustomMetadata is the custom metadata of the LLMResponse.
	// An optional key-value pair to label an LLMResponse.
	// The entire map must be JSON serializable.
	CustomMetadata map[string]any

	FinishReason genai.FinishReason

	UsageMetadata *genai.GenerateContentResponseUsageMetadata
}

// CreateLLMResponse creates an [LLMResponse] from a [*genai.GenerateContentResponse].
func CreateLLMResponse(resp *genai.GenerateContentResponse) *LLMResponse {
	response := &LLMResponse{}

	if resp == nil {
		response.ErrorCode = "UNKNOWN_ERROR"
		response.ErrorMessage = "Generate content response is nil."
		return response
	}

	switch {
	case len(resp.Candidates) > 0:
		candidate := resp.Candidates[0]
		if candidate.Content != nil && len(candidate.Content.Parts) > 0 {
			response.Content = candidate.Content
			response.GroundingMetadata = candidate.GroundingMetadata
		} else {
			response.ErrorCode = string(candidate.FinishReason)
			response.ErrorMessage = candidate.FinishMessage
		}

	case resp.PromptFeedback != nil:
		promptFeedback := resp.PromptFeedback

		// Handle safety ratings if available
		blockReason := "UNKNOWN_BLOCK"
		blockMessage := "Content was blocked. Check prompt feedback for details."
		if safety := promptFeedback.SafetyRatings; len(safety) > 0 {
			for _, rating := range safety {
				if rating.Blocked {
					blockReason = string(rating.Category)
					if rating.Probability != genai.HarmProbabilityUnspecified {
						blockMessage = "Content was blocked due to safety concerns."
					}
					break
				}
			}
		}
		response.ErrorCode = blockReason
		response.ErrorMessage = blockMessage

	default:
		response.ErrorCode = "UNKNOWN_ERROR"
		response.ErrorMessage = "Unknown error"
	}

	return response
}

// CreateFromGenerateContentResponse creates an LLMResponse from a GenerateContentResponse.
// This is kept for backward compatibility.
//
// Parameters:
//   - generateContentResponse: The GenerateContentResponse to create the LLMResponse from.
//
// Returns:
//   - The LLMResponse.
func CreateFromGenerateContentResponse(generateContentResponse *genai.GenerateContentResponse) *LLMResponse {
	return CreateLLMResponse(generateContentResponse)
}

// WithPartial sets the partial flag and returns the response.
func (r *LLMResponse) WithPartial(partial bool) *LLMResponse {
	r.Partial = partial
	return r
}

// WithTurnComplete sets the turn complete flag and returns the response.
func (r *LLMResponse) WithTurnComplete(complete bool) *LLMResponse {
	r.TurnComplete = complete
	return r
}

// WithInterrupted sets the interrupted flag and returns the response.
func (r *LLMResponse) WithInterrupted(interrupted bool) *LLMResponse {
	r.Interrupted = interrupted
	return r
}

// WithCustomMetadata sets the custom metadata and returns the response.
func (r *LLMResponse) WithCustomMetadata(metadata map[string]any) *LLMResponse {
	r.CustomMetadata = metadata
	return r
}

// IsError returns true if the response contains an error.
func (r *LLMResponse) IsError() bool {
	return r.ErrorCode != "" || r.ErrorMessage != ""
}

// GetText returns the text content of the response if available.
// Returns empty string if no content is available.
func (r *LLMResponse) GetText() string {
	if r.Content == nil || len(r.Content.Parts) == 0 {
		return ""
	}

	// Attempt to extract text from the content parts
	for _, part := range r.Content.Parts {
		// Check if part contains text
		if part.Text != "" {
			return part.Text
		}
	}

	return ""
}
