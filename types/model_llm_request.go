// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"fmt"
	"strings"

	"github.com/bytedance/sonic"
	"google.golang.org/genai"
)

// LLMRequest represents a LLM request class that allows passing in tools, output schema and system.
type LLMRequest struct {
	// The model name.
	Model string `json:"model,omitempty"`

	// The contents to send to the model.
	Contents []*genai.Content `json:"contents"`

	// Additional config for the generate content request.
	//
	// tools in generate_content_config should not be set.
	Config            *genai.GenerateContentConfig `json:"config,omitempty"`
	LiveConnectConfig *genai.LiveConnectConfig     `json:"live_connect_config,omitempty"`

	// The tools map.
	ToolMap map[string]Tool `json:"tool_map,omitempty"`
}

type LLMRequestOption func(*LLMRequest)

// WithModelName sets the model name.
func (r *LLMRequest) WithModelName(name string) LLMRequestOption {
	return func(r *LLMRequest) {
		r.Model = name
	}
}

// WithGenerationConfig sets the [*genai.GenerateContentConfig] for the [LLMRequestOption].
func WithGenerationConfig(config *genai.GenerateContentConfig) LLMRequestOption {
	return func(r *LLMRequest) {
		r.Config = config
	}
}

// WithLiveConnectConfig sets the [*genai.LiveConnectConfig] for the [LLMRequestOption].
func WithLiveConnectConfig(config *genai.LiveConnectConfig) LLMRequestOption {
	return func(r *LLMRequest) {
		r.LiveConnectConfig = config
	}
}

// WithSafetySettings sets the [*genai.SafetySetting] for the [LLMRequestOption].
func WithSafetySettings(settings ...*genai.SafetySetting) LLMRequestOption {
	return func(r *LLMRequest) {
		if r.Config == nil {
			r.Config = &genai.GenerateContentConfig{}
		}
		r.Config.SafetySettings = append(r.Config.SafetySettings, settings...)
	}
}

// NewLLMRequest creates a new [LLMRequest].
func NewLLMRequest(contents []*genai.Content, opts ...LLMRequestOption) *LLMRequest {
	r := &LLMRequest{
		Contents: contents,
		ToolMap:  make(map[string]Tool),
	}
	for _, opt := range opts {
		opt(r)
	}

	return r
}

// AppendInstructions appends instructions to the system instruction.
func (r *LLMRequest) AppendInstructions(instructions ...string) {
	if r.Config == nil {
		r.Config = &genai.GenerateContentConfig{}
	}

	if r.Config.SystemInstruction == nil {
		r.Config.SystemInstruction = &genai.Content{
			Parts: []*genai.Part{
				{
					Text: "\n\n" + strings.Join(instructions, "\n\n"),
				},
			},
		}
		return
	}

	r.Config.SystemInstruction.Parts = append(r.Config.SystemInstruction.Parts, &genai.Part{
		Text: "\n\n" + strings.Join(instructions, "\n\n"),
	})
}

// AppendTools adds tools to the request.
func (r *LLMRequest) AppendTools(tools ...Tool) *LLMRequest {
	if r.Config == nil {
		r.Config = &genai.GenerateContentConfig{}
	}

	var declarations []*genai.FunctionDeclaration
	for _, tool := range tools {
		declarations = append(declarations, tool.FunctionDeclarations()...)
		r.ToolMap[tool.Name()] = tool
	}
	r.Config.Tools = append(r.Config.Tools, &genai.Tool{
		FunctionDeclarations: declarations,
	})

	return r
}

// SetOutputSchema configures the expected response format.
func (r *LLMRequest) SetOutputSchema(schema *genai.Schema) *LLMRequest {
	if r.Config == nil {
		r.Config = &genai.GenerateContentConfig{}
	}

	r.Config.ResponseSchema = schema
	r.Config.ResponseMIMEType = "application/json"

	return r
}

// ToJSON converts the request to a JSON string.
func (r *LLMRequest) ToJSON() (string, error) {
	s, err := sonic.ConfigFastest.MarshalToString(r)
	if err != nil {
		return "", fmt.Errorf("failed to marshal LLMRequest to JSON: %w", err)
	}
	return s, nil
}

// ToGenaiContents converts the LLMRequest contents to genai.Content slice.
func (r *LLMRequest) ToGenaiContents() []*genai.Content {
	genaiContents := make([]*genai.Content, len(r.Contents))
	for i, content := range r.Contents {
		// Create a genai.Content with text parts
		genContent := &genai.Content{
			Role:  content.Role,
			Parts: []*genai.Part{},
		}
		// Add text parts
		for _, part := range content.Parts {
			if part.Text != "" {
				genContent.Parts = append(genContent.Parts, genai.NewPartFromText(part.Text))
			}
			// Note: For simplicity, we're only handling text parts for now
		}
		genaiContents[i] = genContent
	}

	return genaiContents
}
