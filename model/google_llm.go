// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"fmt"
	"iter"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"

	"google.golang.org/genai"

	adk "github.com/go-a2a/adk-go"
)

const (
	// GeminiLLMDefaultModel is the default model name for [Gemini].
	GeminiLLMDefaultModel = "gemini-1.5-pro"

	// EnvGoogleAPIKey is the environment variable name for the Google AI API key.
	EnvGoogleAPIKey = "GOOGLE_API_KEY"
)

// Gemini represents a Google Gemini Large Language Model.
type Gemini struct {
	*Config

	genAIClient *genai.Client
}

var _ Model = (*Gemini)(nil)

// NewGemini creates a new [Gemini] instance.
func NewGemini(ctx context.Context, apiKey string, modelName string, opts ...Option) (*Gemini, error) {
	// Use default model if none provided
	if modelName == "" {
		modelName = GeminiLLMDefaultModel
	}

	// Check API key and use [EnvGoogleAPIKey] environment variable if not provided
	if apiKey == "" {
		envApiKey := os.Getenv(EnvGoogleAPIKey)
		if envApiKey == "" {
			return nil, fmt.Errorf("either apiKey arg or %q environment variable must bu set", EnvGoogleAPIKey)
		}
		apiKey = envApiKey
	}

	clintConfig := &genai.ClientConfig{
		APIKey: apiKey,
		HTTPOptions: genai.HTTPOptions{
			Headers: make(http.Header),
		},
	}

	frameworkLabel := fmt.Sprintf("go-a2a/adk-go/%s", adk.Version)
	languageLabel := fmt.Sprintf("go/%s", runtime.Version())
	versionHeaderValue := frameworkLabel + " " + languageLabel
	clintConfig.HTTPOptions.Headers.Set(`x-goog-api-client`, versionHeaderValue)
	clintConfig.HTTPOptions.Headers.Set(`user-agent`, versionHeaderValue)

	// Create GenAI client
	genAIClient, err := genai.NewClient(ctx, clintConfig)
	if err != nil {
		return nil, fmt.Errorf("create genai client: %w", err)
	}

	gemini := &Gemini{
		Config: &Config{
			model: modelName,
		},
		genAIClient: genAIClient,
	}
	for _, opt := range opts {
		gemini.Config = opt.apply(gemini.Config)
	}

	return gemini, nil
}

// Name returns the name of the model.
func (m *Gemini) Name() string {
	return m.model
}

// SupportedModels returns a list of supported Gemini models.
//
// See https://ai.google.dev/gemini-api/docs/models.
func (m *Gemini) SupportedModels() []string {
	return []string{
		"gemini-2.5-flash-preview-04-17",
		"gemini-2.5-pro-preview-03-25",
		"gemini-2.0-flash",
		"gemini-2.0-flash-lite",
		"gemini-1.5-flash,",
		"gemini-1.5-flash-8b",
		"gemini-1.5-pro",
	}
}

// Connect creates a live connection to the Gemini LLM.
func (m *Gemini) Connect() (BaseConnection, error) {
	// Create and return a new connection
	return newGeminiConnection(m.model, m.genAIClient), nil
}

// appendUserContent checks if the last message is from the user and if not, appends an empty user message.
func (m *Gemini) appendUserContent(contents []*genai.Content) []*genai.Content {
	switch {
	case len(contents) == 0:
		return append(contents, &genai.Content{
			Role: genai.RoleUser,
			Parts: []*genai.Part{
				genai.NewPartFromText(`Handle the requests as specified in the System Instruction.`),
			},
		})

	case strings.ToLower(contents[len(contents)-1].Role) != genai.RoleUser:
		return append(contents, &genai.Content{
			Role: genai.RoleUser,
			Parts: []*genai.Part{
				genai.NewPartFromText(`Continue processing previous requests as instructed. Exit or provide a summary if no more outputs are needed.`),
			},
		})

	default:
		return contents
	}
}

// GenerateContent generates content from the model.
func (m *Gemini) GenerateContent(ctx context.Context, request *LLMRequest) (*LLMResponse, error) {
	// Ensure the last message is from the user
	request.Contents = m.appendUserContent(request.Contents)

	// Generate content
	response, err := m.genAIClient.Models.GenerateContent(ctx, m.model, request.Contents, request.Config)
	if err != nil {
		return nil, fmt.Errorf("gemini API error: %w", err)
	}
	m.logger.DebugContext(ctx, "response", buildResponseLog(response))

	return CreateLLMResponse(response), nil
}

// StreamGenerateContent streams generated content from the model.
func (m *Gemini) StreamGenerateContent(ctx context.Context, request *LLMRequest) iter.Seq2[*LLMResponse, error] {
	return func(yield func(*LLMResponse, error) bool) {
		// Ensure the last message is from the user
		contents := m.appendUserContent(request.Contents)

		// Stream generate content
		stream := m.genAIClient.Models.GenerateContentStream(ctx, m.model, contents, request.Config)

		var (
			buf      strings.Builder
			lastResp *genai.GenerateContentResponse
		)
		for resp, err := range stream {
			// catch error first
			if err != nil {
				if !yield(nil, err) {
					return
				}
			}

			if ctx.Err() != nil || resp == nil {
				return
			}

			lastResp = resp
			llmResp := CreateLLMResponse(resp)

			switch {
			case containsText(llmResp):
				buf.WriteString(llmResp.Content.Parts[0].Text)
				llmResp.WithPartial(true)

			case buf.Len() > 0 && !isAudio(llmResp):
				if !yield(newAggregateText(buf.String()), nil) {
					return
				}
				buf.Reset()
			}

			if !yield(llmResp, nil) {
				return
			}
		}

		if buf.Len() > 0 && lastResp != nil && finishStop(lastResp) {
			yield(newAggregateText(buf.String()), nil)
		}
	}
}

func newAggregateText(s string) *LLMResponse {
	return &LLMResponse{
		Content: &genai.Content{
			Role:  RoleModel,
			Parts: []*genai.Part{genai.NewPartFromText(s)},
		},
	}
}

// containsText returns true when the first part has a non-empty Text field.
func containsText(r *LLMResponse) bool {
	return r.Content != nil && len(r.Content.Parts) > 0 && r.Content.Parts[0].Text != ""
}

// isAudio returns true when InlineData is present (optionally mime-typed audio/*).
func isAudio(r *LLMResponse) bool {
	if r.Content == nil || len(r.Content.Parts) == 0 {
		return false
	}
	if data := r.Content.Parts[0].InlineData; data != nil {
		if data.MIMEType == "" {
			return true
		}
		return strings.HasPrefix(data.MIMEType, "audio/")
	}
	return false
}

// finishStop reports whether the first candidate finished with STOP.
func finishStop(r *genai.GenerateContentResponse) bool {
	return r != nil && len(r.Candidates) > 0 && r.Candidates[0].FinishReason == genai.FinishReasonStop
}

const repponseLogFmt = `
LLM Response:
-----------------------------------------------------------
Text:
%s
-----------------------------------------------------------
Function calls:
%s
-----------------------------------------------------------
`

func buildResponseLog(resp *genai.GenerateContentResponse) slog.Attr {
	functionCalls := resp.FunctionCalls()
	functionCallsText := make([]string, len(functionCalls))
	for i, funcCall := range functionCalls {
		functionCallsText[i] = fmt.Sprintf("name: %s, args: %s", funcCall.Name, funcCall.Args)
	}

	return slog.String("response", fmt.Sprintf(repponseLogFmt, resp.Text(), strings.Join(functionCallsText, "\n")))
}
