// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

// Package models provides implementations of various language models.
package models

import (
	"fmt"
	"strings"

	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/model"
	"github.com/go-a2a/adk-go/tool"
)

type Option struct {
	// The title for the generated JSON schema, defaults to the model's name
	Title string
}

// LlmRequest represents a LLM request class that allows passing in tools, output schema and system
type LlmRequest struct {
	Model    string
	Contents []*genai.Content
	Config   *genai.GenerateContentConfig
	Tools    map[string]tool.Tool
}

// AppendInstructions appends instructions to the system instruction.
func (r *LlmRequest) AppendInstructions(instructions []string) {
	if r.Config == nil {
		return
	}
	if r.Config.SystemInstruction == nil {
		r.Config.SystemInstruction = &genai.Content{}
	}
	r.Config.SystemInstruction.Parts = append(
		r.Config.SystemInstruction.Parts,
		&genai.Part{
			Text: "\n\n" + strings.Join(instructions, "\n\n"),
		},
	)
}

// AppendTools appends tools to the request.
func (r *LlmRequest) AppendTools(tools []tool.Tool) {
	if len(tools) == 0 || r.Config == nil {
		return
	}

	declarations := make([]*genai.FunctionDeclaration, len(tools))
	for i, t := range tools {
		declarations[i] = t.FunctionDeclaration()
		r.Tools[t.Name()] = t
	}
	r.Config.Tools = append(r.Config.Tools, &genai.Tool{
		FunctionDeclarations: declarations,
	})
}

// SetOutputSchema sets the output schema for the request.
func (r *LlmRequest) SetOutputSchema(schema *genai.Schema) {
	if r.Config == nil {
		return
	}

	r.Config.ResponseSchema = schema
	r.Config.ResponseMIMEType = "application/json"
}

// LlmResponse represents a response from a language model.
type LlmResponse struct {
	// The content of the response.
	Content *genai.Content

	// The grounding metadata of the response.
	GroundingMetadata *genai.GroundingMetadata

	// Partial indicates whether the text content is part of a unfinished text stream.
	// Only used for streaming mode and when the content is plain text.
	Partial bool

	// TurnComplete indicates whether the response from the model is complete.
	//
	// Only used for streaming mode.
	TurnComplete bool

	// ErrorCode if the response is an error. Code varies by model.
	ErrorCode string

	// ErrorMessage if the response is an error.
	ErrorMessage string

	// Interrupted flag indicating that LLM was interrupted when generating the content.
	//
	// Usually it's due to user interruption during a bidi streaming.
	Interrupted bool

	Request       *LlmRequest
	FunctionCalls []*genai.FunctionCall
}

// NewLlmResponse creates an [LlmResponse] from a [genai.GenerateContentResponse].
func NewLlmResponse(genCtxResp *genai.GenerateContentResponse) *LlmResponse {
	if len(genCtxResp.Candidates) > 0 {
		candidate := genCtxResp.Candidates[0]
		if candidate.Content != nil && len(candidate.Content.Parts) > 0 {
			return &LlmResponse{
				Content:           candidate.Content,
				GroundingMetadata: candidate.GroundingMetadata,
			}
		}
		return &LlmResponse{
			ErrorCode:    string(candidate.FinishReason),
			ErrorMessage: candidate.FinishMessage,
		}
	}

	if genCtxResp.PromptFeedback != nil {
		promptFeedback := genCtxResp.PromptFeedback
		return &LlmResponse{
			ErrorCode:    string(promptFeedback.BlockReason),
			ErrorMessage: promptFeedback.BlockReasonMessage,
		}
	}

	return &LlmResponse{
		ErrorCode:    "UNKNOWN_ERROR",
		ErrorMessage: "Unknown error",
	}
}

// NewModelFromID creates a new model instance from a model ID.
func NewModelFromID(modelID string) (*genai.Model, error) {
	return GetModel(modelID)
}

// GetSupportedModelProviders returns a list of supported model providers.
func GetSupportedModelProviders() []model.ModelProvider {
	return []model.ModelProvider{
		model.ModelProviderGoogle,
		model.ModelProviderOpenAI,
		model.ModelProviderAnthropic,
		model.ModelProviderMock,
	}
}

// GetDefaultModelID returns the default model ID for a given provider.
func GetDefaultModelID(provider model.ModelProvider) (string, error) {
	switch provider {
	case model.ModelProviderGoogle:
		return DefaultGeminiModel, nil
	case model.ModelProviderOpenAI:
		return DefaultOpenAIModel, nil
	case model.ModelProviderAnthropic:
		return DefaultClaudeModel, nil
	case model.ModelProviderMock:
		return "mock-model", nil
	default:
		return "", fmt.Errorf("unsupported model provider: %s", provider)
	}
}

// NewModelFromProvider creates a new model instance for the given provider using the default model ID.
func NewModelFromProvider(provider model.ModelProvider) (*genai.Model, error) {
	modelID, err := GetDefaultModelID(provider)
	if err != nil {
		return nil, err
	}
	return NewModelFromID(modelID)
}
