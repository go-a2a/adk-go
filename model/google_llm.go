// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"cmp"
	"context"
	"fmt"
	"iter"
	"log/slog"
	"net/http"
	"os"
	"runtime"
	"strings"

	aiplatform "cloud.google.com/go/aiplatform/apiv1beta1"
	"cloud.google.com/go/auth/credentials"
	backoff "github.com/cenkalti/backoff/v5"
	"google.golang.org/genai"

	adk "github.com/go-a2a/adk-go"
	"github.com/go-a2a/adk-go/types"
)

const (
	// GeminiLLMDefaultModel is the default model name for [Gemini].
	GeminiLLMDefaultModel = "gemini-2.5-flash"

	// EnvGoogleAPIKey is the environment variable name that specifies the API key for the Gemini API.
	// If both GOOGLE_API_KEY and GEMINI_API_KEY are set, GOOGLE_API_KEY will be used.
	EnvGoogleAPIKey = "GOOGLE_API_KEY"

	// EnvGeminiAPIKey is the environment variable name that specifies the API key for the Gemini API.
	EnvGeminiAPIKey = "GEMINI_API_KEY"

	// EnvGoogleCloudProject is the environment variable name that specifies the GCP project ID.
	EnvGoogleCloudProject = "GOOGLE_CLOUD_PROJECT"

	// EnvGoogleCloudProject is the environment variable name that specifies the GCP location.
	EnvGoogleCloudLocation = "GOOGLE_CLOUD_LOCATION"

	// EnvGoogleCloudRegion is the environment variable name that specifies the GCP region.
	EnvGoogleCloudRegion = "GOOGLE_CLOUD_REGION"
)

// Gemini represents a Google Gemini Large Language Model.
type Gemini struct {
	genAIClient *genai.Client
	// modelName represents the specific LLM model name.
	modelName string
	// logger is the logger used for logging.
	logger *slog.Logger

	// optional [*http.Client] to use.
	hc *http.Client
	// allow Gemini to retry failed responses.
	retry *backoff.ExponentialBackOff
}

var _ types.Model = (*Gemini)(nil)

// WithRetry sets the [*backoff.ExponentialBackOff] for the [Gemini] model.
func WithRetry(retry *backoff.ExponentialBackOff) Option[Gemini] {
	return func(m *Gemini) {
		m.retry = retry
	}
}

// NewGemini creates a new [Gemini] instance.
func NewGemini(ctx context.Context, modelName string, opts ...Option[Gemini]) (*Gemini, error) {
	// Use default model if none provided
	if modelName == "" {
		modelName = GeminiLLMDefaultModel
	}

	gemini := &Gemini{
		modelName: modelName,
		logger:    slog.Default(),
		hc:        &http.Client{},
		retry:     &backoff.ExponentialBackOff{},
	}
	for _, opt := range opts {
		opt(gemini)
	}

	frameworkLabel := fmt.Sprintf("go-a2a/adk-go/%s", adk.Version)
	languageLabel := fmt.Sprintf("go/%s", runtime.Version())
	versionHeaderValue := frameworkLabel + " " + languageLabel

	clientConfig := &genai.ClientConfig{
		APIKey:     cmp.Or(os.Getenv(EnvGoogleAPIKey), os.Getenv(EnvGeminiAPIKey)),
		Project:    os.Getenv(EnvGoogleCloudProject),
		Location:   cmp.Or(os.Getenv(EnvGoogleCloudLocation), os.Getenv(EnvGoogleCloudRegion)),
		HTTPClient: gemini.hc,
		HTTPOptions: genai.HTTPOptions{
			Headers: http.Header{
				`x-goog-api-client`: {versionHeaderValue},
				`user-agent`:        {versionHeaderValue},
			},
		},
	}

	switch {
	case clientConfig.APIKey != "":
		clientConfig.Backend = genai.BackendGeminiAPI

	case clientConfig.Project != "" && clientConfig.Location != "":
		clientConfig.Backend = genai.BackendVertexAI
		creds, err := credentials.DetectDefault(&credentials.DetectOptions{
			Scopes: aiplatform.DefaultAuthScopes(),
		})
		if err != nil {
			return nil, fmt.Errorf("detect default GCP credentials: %w", err)
		}
		clientConfig.Credentials = creds
	}

	// Create GenAI client
	genAIClient, err := genai.NewClient(ctx, clientConfig)
	if err != nil {
		return nil, fmt.Errorf("create genai client: %w", err)
	}
	gemini.genAIClient = genAIClient

	return gemini, nil
}

// Name returns the name of the [Gemini] model.
//
// Name implements [types.Model].
func (m *Gemini) Name() string {
	return m.modelName
}

// SupportedModels returns a list of supported models in the [Gemini].
//
// See https://cloud.google.com/vertex-ai/generative-ai/docs/models and https://ai.google.dev/gemini-api/docs/models.
//
// SupportedModels implements [types.Model].
func (m *Gemini) SupportedModels() []string {
	return []string{
		"gemini-2.5-pro",
		"gemini-2.5-flash",
		"gemini-2.5-flash-preview-05-20",
		"gemini-2.5-flash-lite",
		"gemini-2.5-flash-lite-06-17",
		"gemini-live-2.5-flash-preview",
		"gemini-2.5-flash-preview-05-20",
		"gemini-2.5-flash-exp-native-audio-thinking-dialog",
		"gemini-2.5-flash-preview-tts",
		"gemini-2.5-pro-preview-tts",
		"gemini-2.0-flash",
		"gemini-2.0-flash-001",
		"gemini-2.0-flash-exp",
		"gemini-2.0-flash-preview-image-generation",
		"gemini-2.0-flash-lite",
		"gemini-2.0-flash-lite-001",
		"gemini-2.0-flash-live-001",
		"model-optimizer-exp-04-09",
	}
}

// Connect creates a live connection to the Gemini LLM.
//
// Connect implements [types.Model].
func (m *Gemini) Connect(ctx context.Context, request *types.LLMRequest) (types.ModelConnection, error) {
	request.LiveConnectConfig.Tools = request.Config.Tools
	// Create and return a new connection
	return newGeminiConnection(ctx, m.modelName, m.genAIClient, request)
}

// GenerateContent generates content from the model.
//
// GenerateContent implements [types.Model].
func (m *Gemini) GenerateContent(ctx context.Context, request *types.LLMRequest) (*types.LLMResponse, error) {
	// TODO(zchee): support _preprocess_request

	// Ensure the last message is from the user
	request.Contents = m.appendUserContent(request.Contents)

	// Generate content
	response, err := m.genAIClient.Models.GenerateContent(ctx, m.modelName, request.Contents, request.Config)
	if err != nil {
		return nil, fmt.Errorf("gemini API error: %w", err)
	}
	m.logger.DebugContext(ctx, "response", buildResponseLog(response))

	return types.CreateLLMResponse(response), nil
}

// StreamGenerateContent streams generated content from the model.
//
// StreamGenerateContent implements [types.Model].
func (m *Gemini) StreamGenerateContent(ctx context.Context, request *types.LLMRequest) iter.Seq2[*types.LLMResponse, error] {
	return func(yield func(*types.LLMResponse, error) bool) {
		// Ensure the last message is from the user
		contents := m.appendUserContent(request.Contents)

		// Stream generate content
		stream := m.genAIClient.Models.GenerateContentStream(ctx, m.modelName, contents, request.Config)

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
			llmResp := types.CreateLLMResponse(resp)

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

func newAggregateText(s string) *types.LLMResponse {
	return &types.LLMResponse{
		Content: &genai.Content{
			Role:  RoleModel,
			Parts: []*genai.Part{genai.NewPartFromText(s)},
		},
	}
}

// containsText returns true when the first part has a non-empty Text field.
func containsText(r *types.LLMResponse) bool {
	return r.Content != nil && len(r.Content.Parts) > 0 && r.Content.Parts[0].Text != ""
}

// isAudio returns true when InlineData is present (optionally mime-typed audio/*).
func isAudio(r *types.LLMResponse) bool {
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
