// Copyright 2024 The ADK Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package models

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/bytedance/sonic"
	"github.com/google/generative-ai-go/genai"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/api/option"

	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/observability"
)

// GeminiModel represents a Gemini model integration using Google's official SDK.
type GeminiModel struct {
	modelID      string
	client       *genai.Client
	model        *genai.GenerativeModel
	apiKey       string
	capabilities map[model.ModelCapability]bool
}

// NewGeminiModel creates a new Gemini model with the specified API key.
func NewGeminiModel(modelID, apiKey string, options ...option.ClientOption) (*GeminiModel, error) {
	ctx := context.Background()

	// Set up telemetry
	ctx, span := observability.StartSpan(ctx, "create_gemini_model")
	defer span.End()

	span.SetAttributes(
		attribute.String("model.id", modelID),
		attribute.String("model.provider", string(model.ModelProviderGoogle)),
	)

	// Create client options with API key
	opts := []option.ClientOption{
		option.WithAPIKey(apiKey),
	}
	opts = append(opts, options...)

	// Create genai client
	client, err := genai.NewClient(ctx, opts...)
	if err != nil {
		observability.Error(ctx, err, "Failed to create Gemini client")
		return nil, fmt.Errorf("failed to create Gemini client: %w", err)
	}

	// Create generative model
	genModel := client.GenerativeModel(modelID)

	// Configure capabilities based on model ID
	capabilities := map[model.ModelCapability]bool{
		model.ModelCapabilityStreaming: true,
	}

	if modelID == "gemini-1.5-pro" ||
		modelID == "gemini-1.5-flash" ||
		modelID == "gemini-2.0-pro" ||
		modelID == "gemini-2.0-flash" {
		capabilities[model.ModelCapabilityToolCalling] = true
		capabilities[model.ModelCapabilityVision] = true
		capabilities[model.ModelCapabilityJSON] = true
		capabilities[model.ModelCapabilityFunctionCalling] = true
	}

	observability.Logger(ctx).Info("Created Gemini model",
		slog.String("model_id", modelID),
		slog.String("provider", string(model.ModelProviderGoogle)),
	)

	return &GeminiModel{
		modelID:      modelID,
		client:       client,
		model:        genModel,
		apiKey:       apiKey,
		capabilities: capabilities,
	}, nil
}

// ModelID returns the identifier for this model.
func (g *GeminiModel) ModelID() string {
	return g.modelID
}

// Provider returns the provider of this model.
func (g *GeminiModel) Provider() model.ModelProvider {
	return model.ModelProviderGoogle
}

// HasCapability returns whether the model has the specified capability.
func (g *GeminiModel) HasCapability(capability model.ModelCapability) bool {
	return g.capabilities[capability]
}

// createGenaiContent converts ADK messages to genai content parts.
func (g *GeminiModel) createGenaiContent(messages []message.Message) []genai.Part {
	var parts []genai.Part

	for _, msg := range messages {
		// Convert ADK message role to genai role
		var role string
		switch msg.Role {
		case message.RoleUser:
			role = "user"
		case message.RoleAssistant:
			role = "model"
		case message.RoleSystem:
			parts = append(parts, genai.Text(msg.Content))
			continue
		case message.RoleTool:
			role = "tool"
			// Construct tool response format
			if len(msg.ToolResults) > 0 {
				toolResult := msg.ToolResults[0]
				// Format as tool response
				toolResp := map[string]any{
					"tool_call_id": toolResult.CallID,
					"content":      toolResult.Content,
				}
				parts = append(parts, &genai.FunctionResponse{
					Name:     "tool_response",
					Response: toolResp,
				})
			}
			continue
		}

		// Add content part
		if msg.Content != "" {
			parts = append(parts, genai.Text(msg.Content))
		}

		// Add tool calls if present
		if len(msg.ToolCalls) > 0 {
			for _, tc := range msg.ToolCalls {
				// Convert to function call format
				var m map[string]any
				if err := sonic.ConfigDefault.Unmarshal(tc.Args, m); err != nil {
					continue
				}
				parts = append(parts, &genai.FunctionCall{
					Name: tc.Name,
					Args: m,
				})
			}
		}
	}

	return parts
}

// convertGenaiResponseToMessage converts a genai response to an ADK message.
func (g *GeminiModel) convertGenaiResponseToMessage(resp *genai.GenerateContentResponse) message.Message {
	if resp == nil || len(resp.Candidates) == 0 || len(resp.Candidates[0].Content.Parts) == 0 {
		return message.NewAssistantMessage("")
	}

	// Create a response message
	msg := message.Message{
		Role:      message.RoleAssistant,
		ID:        "", // Fill with a UUID in practice
		Timestamp: time.Now(),
	}

	candidate := resp.Candidates[0]
	content := candidate.Content

	// Process text content
	var textParts []string
	for _, part := range content.Parts {
		switch part := part.(type) {
		case genai.Text:
			textParts = append(textParts, string(part))
		case *genai.FunctionCall:
			fc := part
			data, err := sonic.ConfigFastest.Marshal(fc.Args)
			if err != nil {
				continue
			}
			toolCall := message.ToolCall{
				ID:   fmt.Sprintf("call_%d", time.Now().UnixNano()),
				Name: part.Name,
				Args: json.RawMessage(data),
			}
			msg.ToolCalls = append(msg.ToolCalls, toolCall)
		}
	}

	// Combine text parts
	if len(textParts) > 0 {
		msg.Content = textParts[0]
	}

	return msg
}

// Generate generates a completion based on the provided messages.
func (g *GeminiModel) Generate(ctx context.Context, messages []message.Message) (message.Message, error) {
	return g.GenerateWithOptions(ctx, messages, model.DefaultGenerateOptions())
}

// GenerateWithOptions generates a completion with the specified options.
func (g *GeminiModel) GenerateWithOptions(ctx context.Context, messages []message.Message, opts model.GenerateOptions) (message.Message, error) {
	// Set up telemetry
	ctx, span := observability.StartSpan(ctx, "gemini_generate")
	defer span.End()

	span.SetAttributes(
		attribute.String("model.id", g.modelID),
		attribute.String("model.provider", string(model.ModelProviderGoogle)),
		attribute.Float64("model.temperature", opts.Temperature),
		attribute.Int("model.max_tokens", opts.MaxTokens),
	)

	// Add count of messages as attribute
	span.SetAttributes(attribute.Int("messages.count", len(messages)))

	// Record metrics
	latencyRecorder := observability.MeasureLatency(ctx, "model_generate",
		attribute.String("model.id", g.modelID),
	)
	defer latencyRecorder()
	observability.IncrementRequests(ctx,
		attribute.String("model.id", g.modelID),
		attribute.String("operation", "generate"),
	)

	// Configure generation options
	g.model.Temperature = opts.Temperature
	g.model.TopP = opts.TopP
	g.model.MaxOutputTokens = opts.MaxTokens

	// Create content
	parts := g.createGenaiContent(messages)

	// Generate content
	resp, err := g.model.GenerateContent(ctx, parts...)
	if err != nil {
		observability.Error(ctx, err, "Failed to generate content with Gemini",
			slog.String("model_id", g.modelID),
		)
		observability.IncrementFailures(ctx,
			attribute.String("model.id", g.modelID),
			attribute.String("operation", "generate"),
		)
		return message.Message{}, fmt.Errorf("failed to generate content: %w", err)
	}

	// Convert to message
	result := g.convertGenaiResponseToMessage(resp)

	// Estimate and record token counts
	if result.Content != "" {
		outputTokens := len(result.Content) / 4 // Very rough estimation
		observability.RecordTokens(ctx, int64(outputTokens),
			attribute.String("model.id", g.modelID),
			attribute.String("token_type", "output"),
		)
	}

	return result, nil
}

// convertToolDefinitions converts ADK tool definitions to genai function declarations.
func (g *GeminiModel) convertToolDefinitions(tools []model.ToolDefinition) []genai.FunctionDeclaration {
	functions := make([]genai.FunctionDeclaration, 0, len(tools))

	for _, tool := range tools {
		// Convert parameters to JSON schema
		paramSchema, _ := sonic.MarshalString(tool.Parameters)

		functions = append(functions, genai.FunctionDeclaration{
			Name:        tool.Name,
			Description: tool.Description,
			Parameters:  paramSchema,
		})
	}

	return functions
}

// GenerateWithTools generates a response that can include tool calls.
func (g *GeminiModel) GenerateWithTools(ctx context.Context, messages []message.Message, tools []model.ToolDefinition) (message.Message, error) {
	// Set up telemetry
	ctx, span := observability.StartSpan(ctx, "gemini_generate_with_tools")
	defer span.End()

	span.SetAttributes(
		attribute.String("model.id", g.modelID),
		attribute.String("model.provider", string(model.ModelProviderGoogle)),
		attribute.Int("tools.count", len(tools)),
	)

	// Record metrics
	latencyRecorder := observability.MeasureLatency(ctx, "model_generate_with_tools",
		attribute.String("model.id", g.modelID),
	)
	defer latencyRecorder()
	observability.IncrementRequests(ctx,
		attribute.String("model.id", g.modelID),
		attribute.String("operation", "generate_with_tools"),
	)

	// Check if tools are supported
	if !g.HasCapability(model.ModelCapabilityToolCalling) {
		err := fmt.Errorf("model %s does not support tool calling", g.modelID)
		observability.Error(ctx, err, "Model does not support tool calling")
		return message.Message{}, err
	}

	// Get generative options
	genOpts := model.DefaultGenerateOptions()

	// Configure model
	g.model.Temperature = genOpts.Temperature
	g.model.TopP = genOpts.TopP
	g.model.MaxOutputTokens = genOpts.MaxTokens

	// Convert tools to function declarations
	functionDeclarations := g.convertToolDefinitions(tools)
	g.model.Tools = []genai.Tool{
		{
			FunctionDeclarations: functionDeclarations,
		},
	}

	// Create content
	parts := g.createGenaiContent(messages)

	// Generate content
	resp, err := g.model.GenerateContent(ctx, parts...)
	if err != nil {
		observability.Error(ctx, err, "Failed to generate content with tools",
			slog.String("model_id", g.modelID),
			slog.Int("tools_count", len(tools)),
		)
		observability.IncrementFailures(ctx,
			attribute.String("model.id", g.modelID),
			attribute.String("operation", "generate_with_tools"),
		)
		return message.Message{}, fmt.Errorf("failed to generate content with tools: %w", err)
	}

	// Convert to message
	result := g.convertGenaiResponseToMessage(resp)

	// Log and trace tool calls
	if len(result.ToolCalls) > 0 {
		observability.Logger(ctx).Debug("Model generated tool calls",
			slog.String("model_id", g.modelID),
			slog.Int("tool_calls_count", len(result.ToolCalls)),
		)

		for i, tc := range result.ToolCalls {
			span.AddEvent("tool_call", trace.WithAttributes(
				attribute.String("tool.name", tc.Name),
				attribute.String("tool.id", tc.ID),
				attribute.Int("tool.index", i),
			))
		}
	}

	return result, nil
}

// GenerateStream generates a streaming response and invokes the handler for each chunk.
func (g *GeminiModel) GenerateStream(ctx context.Context, messages []message.Message, handler model.ResponseHandler) error {
	// Set up telemetry
	ctx, span := observability.StartSpan(ctx, "gemini_generate_stream")
	defer span.End()

	span.SetAttributes(
		attribute.String("model.id", g.modelID),
		attribute.String("model.provider", string(model.ModelProviderGoogle)),
	)

	// Record metrics
	latencyRecorder := observability.MeasureLatency(ctx, "model_generate_stream",
		attribute.String("model.id", g.modelID),
	)
	defer latencyRecorder()
	observability.IncrementRequests(ctx,
		attribute.String("model.id", g.modelID),
		attribute.String("operation", "generate_stream"),
	)

	// Check if streaming is supported
	if !g.HasCapability(model.ModelCapabilityStreaming) {
		err := fmt.Errorf("model %s does not support streaming", g.modelID)
		observability.Error(ctx, err, "Model does not support streaming")
		return err
	}

	// Configure model with default options
	genOpts := model.DefaultGenerateOptions()
	g.model.Temperature = genOpts.Temperature
	g.model.TopP = genOpts.TopP
	g.model.MaxOutputTokens = genOpts.MaxTokens

	// Create content
	parts := g.createGenaiContent(messages)

	// Generate streaming content
	iter := g.model.GenerateContentStream(ctx, parts...)

	// Process stream
	var totalTokens int64
	for {
		resp, err := iter.Next()
		if err != nil {
			// Check if it's the end of the stream
			if err.Error() == "no more items in iterator" {
				break
			}

			observability.Error(ctx, err, "Error in streaming generation",
				slog.String("model_id", g.modelID),
			)
			observability.IncrementFailures(ctx,
				attribute.String("model.id", g.modelID),
				attribute.String("operation", "generate_stream"),
			)
			return fmt.Errorf("error in streaming generation: %w", err)
		}

		// Convert chunk to message
		msgChunk := g.convertGenaiResponseToMessage(resp)

		// Estimate tokens in this chunk
		if msgChunk.Content != "" {
			chunkTokens := int64(len(msgChunk.Content) / 4) // Very rough estimation
			totalTokens += chunkTokens
		}

		// Invoke handler with chunk
		handler(msgChunk)
	}

	// Record total token count
	observability.RecordTokens(ctx, totalTokens,
		attribute.String("model.id", g.modelID),
		attribute.String("token_type", "output"),
		attribute.String("operation", "generate_stream"),
	)

	return nil
}

// Close cleans up resources used by the model.
func (g *GeminiModel) Close() {
	if g.client != nil {
		g.client.Close()
	}
}
