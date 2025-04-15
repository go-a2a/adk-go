// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package models

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"

	"github.com/bytedance/sonic"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/message"
	"github.com/go-a2a/adk-go/model"
	"github.com/go-a2a/adk-go/observability"
)

func init() {
	// Register Gemini model with the registry
	Register("gemini-.*", func(modelID string) (model.Model, error) {
		// Get API key from environment
		apiKey := os.Getenv("GOOGLE_API_KEY")
		if apiKey == "" {
			// Try alternative env var
			apiKey = os.Getenv("GEMINI_API_KEY")
		}

		return NewGoogleModel(context.Background(), modelID, apiKey, "")
	})
}

const (
	// DefaultGeminiModel is the default Gemini model ID.
	DefaultGeminiModel = "gemini-1.5-flash"
)

// GoogleModel represents the Gemini language model.
type GoogleModel struct {
	*Model

	client  any // *genai.Client
	modelID string
}

// NewGoogleModel creates a new Gemini model instance.
func NewGoogleModel(ctx context.Context, modelID string, apiKey string, apiEndpoint string) (*GoogleModel, error) {
	if modelID == "" {
		modelID = DefaultGeminiModel
	}

	m := &GoogleModel{
		modelID: modelID,
	}

	cc := &genai.ClientConfig{}
	// Initialize options for client creation
	// var clientOpts []option.ClientOption
	if apiKey != "" {
		cc.APIKey = apiKey
	}
	if apiEndpoint != "" {
		cc.HTTPOptions.BaseURL = apiEndpoint
	}

	var err error
	m.client, err = genai.NewClient(ctx, cc)
	if err != nil {
		return nil, err
	}

	capabilities := []model.ModelCapability{
		model.ModelCapabilityToolCalling,
		model.ModelCapabilityVision,
		model.ModelCapabilityJSON,
		model.ModelCapabilityStreaming,
		model.ModelCapabilityFunctionCalling,
	}

	// Create the base model with a generator function
	m.Model = NewBaseModel(modelID, model.ModelProviderGoogle, capabilities, m.generateContent)

	return m, nil
}

// generateContent is the generator function for the Gemini model.
func (m *GoogleModel) generateContent(ctx context.Context, modelID string, messages []message.Message, opts model.GenerateOptions) (message.Message, error) {
	tracer := observability.Tracer("github.com/go-a2a/adk-go")
	ctx, span := tracer.Start(ctx, "GoogleModel.generateContent",
		trace.WithAttributes(
			attribute.String("model_id", modelID),
			attribute.Float64("temperature", opts.Temperature),
		),
	)
	defer span.End()

	logger := observability.Logger(ctx)
	logger.Debug("Generating content with Gemini model",
		slog.String("model", modelID),
		slog.Int("numMessages", len(messages)),
		slog.Float64("temperature", opts.Temperature),
	)

	// In a real implementation, we would:
	// 1. Convert messages to genai format
	// 2. Set generation config with temperature, topP, etc.
	// 3. Call the genai client's GenerateContent method
	// 4. Process the response

	// For now, return a placeholder response
	if len(messages) > 0 && messages[len(messages)-1].Role == message.RoleUser {
		userMsg := messages[len(messages)-1].Content
		responseContent := fmt.Sprintf("Response to: %s", userMsg)
		return message.NewAssistantMessage(responseContent), nil
	}

	return message.NewAssistantMessage("Generated response from Gemini model"), nil
}

// GenerateWithTools overrides the base implementation to handle tools.
func (m *GoogleModel) GenerateWithTools(ctx context.Context, messages []message.Message, tools []model.ToolDefinition) (message.Message, error) {
	if !m.HasCapability(model.ModelCapabilityToolCalling) && !m.HasCapability(model.ModelCapabilityFunctionCalling) {
		return message.Message{}, fmt.Errorf("tool calling not supported by model %s", m.ModelID())
	}

	tracer := observability.Tracer("github.com/go-a2a/adk-go")
	ctx, span := tracer.Start(ctx, "GoogleModel.GenerateWithTools",
		trace.WithAttributes(
			attribute.String("model_id", m.ModelID()),
			attribute.Int("num_tools", len(tools)),
		),
	)
	defer span.End()

	logger := observability.Logger(ctx)
	logger.Debug("Generating content with tools using Gemini model",
		slog.String("model", m.ModelID()),
		slog.Int("numMessages", len(messages)),
		slog.Int("numTools", len(tools)),
	)

	// In a real implementation, we would:
	// 1. Convert messages to genai format
	// 2. Convert tools to genai format
	// 3. Call the genai client's GenerateContent method with tools
	// 4. Process the response

	// For testing, create a mock response with a tool call
	// If there are tools, simulate a tool call
	if len(tools) > 0 {
		firstTool := tools[0]
		argsJSON, _ := json.Marshal(map[string]any{"param": "value"})
		toolCalls := []message.ToolCall{
			{
				ID:   "call_1",
				Name: firstTool.Name,
				Args: argsJSON,
			},
		}
		return message.NewAssistantToolCallMessage(toolCalls), nil
	}

	return message.NewAssistantMessage("Generated response from Gemini model"), nil
}

// GenerateStream overrides the base implementation to handle streaming.
func (m *GoogleModel) GenerateStream(ctx context.Context, messages []message.Message, handler model.ResponseHandler) error {
	if !m.HasCapability(model.ModelCapabilityStreaming) {
		return fmt.Errorf("streaming not supported by model %s", m.ModelID())
	}

	tracer := observability.Tracer("github.com/go-a2a/adk-go")
	ctx, span := tracer.Start(ctx, "GoogleModel.GenerateStream",
		trace.WithAttributes(
			attribute.String("model_id", m.ModelID()),
		),
	)
	defer span.End()

	logger := observability.Logger(ctx)
	logger.Debug("Streaming content from Gemini model",
		slog.String("model", m.ModelID()),
		slog.Int("numMessages", len(messages)),
	)

	// For testing purposes, simulate streaming by sending multiple chunks
	chunks := []string{
		"This is the first chunk of the response.",
		" Here is the second chunk.",
		" And finally, the last chunk.",
	}

	for _, chunk := range chunks {
		// Create and send delta message
		deltaMsg := message.NewAssistantMessage(chunk)

		// For debugging
		if logger.Enabled(ctx, slog.LevelDebug) {
			jsonText, _ := sonic.MarshalString(deltaMsg)
			logger.Debug("Streaming chunk", slog.String("chunk", jsonText))
		}

		handler(deltaMsg)
	}

	return nil
}

// GenerateStreamWithTools overrides the base implementation to handle streaming with tools.
func (m *GoogleModel) GenerateStreamWithTools(ctx context.Context, messages []message.Message, tools []model.ToolDefinition, handler model.ResponseHandler) error {
	if !m.HasCapability(model.ModelCapabilityStreaming) ||
		(!m.HasCapability(model.ModelCapabilityToolCalling) && !m.HasCapability(model.ModelCapabilityFunctionCalling)) {
		return fmt.Errorf("streaming with tools not supported by model %s", m.ModelID())
	}

	tracer := observability.Tracer("github.com/go-a2a/adk-go")
	ctx, span := tracer.Start(ctx, "GoogleModel.GenerateStreamWithTools",
		trace.WithAttributes(
			attribute.String("model_id", m.ModelID()),
			attribute.Int("num_tools", len(tools)),
		),
	)
	defer span.End()

	logger := observability.Logger(ctx)
	logger.Debug("Streaming content with tools from Gemini model",
		slog.String("model", m.ModelID()),
		slog.Int("numMessages", len(messages)),
		slog.Int("numTools", len(tools)),
	)

	// For testing, simulate streaming text followed by a tool call
	chunks := []string{
		"Let me think about this...",
		" I need to get some information",
	}

	for _, chunk := range chunks {
		deltaMsg := message.NewAssistantMessage(chunk)
		handler(deltaMsg)
	}

	// If there are tools, simulate a tool call at the end
	if len(tools) > 0 {
		firstTool := tools[0]
		argsJSON, _ := json.Marshal(map[string]any{"param": "value"})
		toolCalls := []message.ToolCall{
			{
				ID:   "call_1",
				Name: firstTool.Name,
				Args: argsJSON,
			},
		}
		toolCallMsg := message.NewAssistantToolCallMessage(toolCalls)
		handler(toolCallMsg)
	}

	return nil
}

// Close closes any resources used by the model
func (m *GoogleModel) Close() error {
	// In a real implementation, this might close the genai client
	return nil
}
