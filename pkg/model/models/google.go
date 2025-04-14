// Copyright 2025 The go-a2a Authors
// SPDX-License-Identifier: Apache-2.0

package models

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"

	"github.com/bytedance/sonic"
	"github.com/go-a2a/adk-go/pkg/message"
	"github.com/go-a2a/adk-go/pkg/model"
	"github.com/go-a2a/adk-go/pkg/observability"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/api/option"
	"google.golang.org/genai"
)

const (
	// DefaultGeminiModel is the default Gemini model ID.
	DefaultGeminiModel = "gemini-1.5-flash"
)

// GoogleModel represents the Gemini language model.
type GoogleModel struct {
	*Model

	client      *genai.Client
	geminiModel *genai.GenerativeModel
	apiKey      string
	apiEndpoint string
	modelID     string
}

// NewGoogleModel creates a new Gemini model instance.
func NewGoogleModel(modelID string, apiKey string, apiEndpoint string) (*GoogleModel, error) {
	if modelID == "" {
		modelID = DefaultGeminiModel
	}

	capabilities := []model.ModelCapability{
		model.ModelCapabilityToolCalling,
		model.ModelCapabilityVision,
		model.ModelCapabilityJSON,
		model.ModelCapabilityStreaming,
		model.ModelCapabilityFunctionCalling,
	}

	m := &GoogleModel{
		apiKey:      apiKey,
		apiEndpoint: apiEndpoint,
		modelID:     modelID,
	}

	// Initialize the genai client
	var clientOpts []option.ClientOption
	if apiKey != "" {
		clientOpts = append(clientOpts, option.WithAPIKey(apiKey))
	}
	if apiEndpoint != "" {
		clientOpts = append(clientOpts, option.WithEndpoint(apiEndpoint))
	}

	var err error
	m.client, err = genai.NewClient(context.Background(), clientOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create genai client: %w", err)
	}

	// Create the generative model with the specified model ID
	m.geminiModel = m.client.GenerativeModel(modelID)

	// Configure default safety settings
	m.geminiModel.SafetySettings = []*genai.SafetySetting{
		{
			Category:  genai.HarmCategoryHateSpeech,
			Threshold: genai.HarmBlockThresholdBlockMediumAndAbove,
		},
		{
			Category:  genai.HarmCategoryDangerousContent,
			Threshold: genai.HarmBlockThresholdBlockMediumAndAbove,
		},
		{
			Category:  genai.HarmCategoryHarassment,
			Threshold: genai.HarmBlockThresholdBlockMediumAndAbove,
		},
		{
			Category:  genai.HarmCategorySexuallyExplicit,
			Threshold: genai.HarmBlockThresholdBlockMediumAndAbove,
		},
		{
			Category:  genai.HarmCategoryCivicIntegrity,
			Threshold: genai.HarmBlockThresholdBlockMediumAndAbove,
		},
	}

	// Set reasonable defaults for generation
	m.geminiModel.Temperature = 0.7
	m.geminiModel.TopP = 1.0
	m.geminiModel.TopK = 40
	m.geminiModel.MaxOutputTokens = 2048

	// Create the base model with a generator function
	m.Model = NewBaseModel(modelID, model.ModelProviderGoogle, capabilities, m.generateContent)

	return m, nil
}

// convertMessagesToGenAI converts ADK messages to genai.Content format
func convertMessagesToGenAI(messages []message.Message) ([]*genai.Content, error) {
	var contents []*genai.Content

	for _, msg := range messages {
		var content *genai.Content

		switch msg.Role {
		case message.RoleUser:
			content = &genai.Content{
				Role:  "user",
				Parts: []genai.Part{genai.Text(msg.Content)},
			}

		case message.RoleAssistant:
			content = &genai.Content{
				Role: "model",
			}
			// Add text content if available
			if msg.Content != "" {
				content.Parts = append(content.Parts, genai.Text(msg.Content))
			}
			// Add tool calls if available
			if len(msg.ToolCalls) > 0 {
				functionCalls := make([]*genai.FunctionCall, 0, len(msg.ToolCalls))
				for _, tc := range msg.ToolCalls {
					functionCalls = append(functionCalls, &genai.FunctionCall{
						Name:      tc.Name,
						Arguments: string(tc.Args),
					})
				}
				for _, fc := range functionCalls {
					content.Parts = append(content.Parts, genai.FunctionCall{
						Name:      fc.Name,
						Arguments: fc.Arguments,
					})
				}
			}

		case message.RoleSystem:
			// Gemini doesn't have a direct system role, so we convert it to a user message
			// with a prefix indicating it's system instructions
			systemText := fmt.Sprintf("System instructions: %s", msg.Content)
			content = &genai.Content{
				Role:  "user",
				Parts: []genai.Part{genai.Text(systemText)},
			}

		case message.RoleTool:
			// Tool responses are added as function responses
			if len(msg.ToolResults) > 0 {
				content = &genai.Content{
					Role: "user",
				}
				for _, tr := range msg.ToolResults {
					content.Parts = append(content.Parts, genai.FunctionResponse{
						Name:     "", // Could be set with extended info
						Response: tr.Content,
					})
				}
			}

		default:
			return nil, fmt.Errorf("unsupported message role: %s", msg.Role)
		}

		if content != nil {
			contents = append(contents, content)
		}
	}

	return contents, nil
}

// convertToolDefinitionsToGenAI converts the ADK ToolDefinition format to genai.Tool format
func convertToolDefinitionsToGenAI(tools []model.ToolDefinition) ([]*genai.Tool, error) {
	var genaiTools []*genai.Tool

	for _, tool := range tools {
		// Convert parameters to a valid JSON schema
		parametersJSON, err := json.Marshal(tool.Parameters)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal tool parameters: %w", err)
		}

		// Create the function declaration
		functionDecl := &genai.FunctionDeclaration{
			Name:        tool.Name,
			Description: tool.Description,
			Parameters:  string(parametersJSON),
		}

		// Create the tool
		genaiTool := &genai.Tool{
			FunctionDeclarations: []*genai.FunctionDeclaration{functionDecl},
		}

		genaiTools = append(genaiTools, genaiTool)
	}

	return genaiTools, nil
}

// convertGenAIResponseToMessage converts the genai response to the ADK message format
func convertGenAIResponseToMessage(response *genai.GenerateContentResponse) (message.Message, error) {
	if response == nil || len(response.Candidates) == 0 {
		return message.Message{}, errors.New("empty response from Gemini")
	}

	// Get the first candidate
	candidate := response.Candidates[0]
	if candidate.Content == nil {
		return message.Message{}, errors.New("empty content from Gemini")
	}

	// Check for finish reason errors
	if candidate.FinishReason == genai.FinishReasonSafety {
		return message.Message{}, errors.New("response blocked due to safety concerns")
	} else if candidate.FinishReason == genai.FinishReasonRecitation {
		return message.Message{}, errors.New("response blocked due to potential recitation")
	}

	// Process text parts and function calls
	var msgContent string
	var toolCalls []message.ToolCall

	for _, part := range candidate.Content.Parts {
		// Handle text parts
		if textPart, ok := part.(genai.Text); ok {
			if msgContent != "" {
				msgContent += "\n"
			}
			msgContent += string(textPart)
		}

		// Handle function calls
		if functionCall, ok := part.(genai.FunctionCall); ok {
			// Generate a unique ID for the tool call
			id := fmt.Sprintf("call_%d", len(toolCalls)+1)
			argsRaw := json.RawMessage(functionCall.Arguments)
			toolCalls = append(toolCalls, message.ToolCall{
				ID:   id,
				Name: functionCall.Name,
				Args: argsRaw,
			})
		}
	}

	// Create the appropriate message type based on content
	if len(toolCalls) > 0 {
		// If there are tool calls, create a tool call message
		if msgContent != "" {
			// Message with both content and tool calls (handle combined response)
			msg := message.NewAssistantToolCallMessage(toolCalls)
			msg.Content = msgContent
			return msg, nil
		}
		return message.NewAssistantToolCallMessage(toolCalls), nil
	}

	// Regular text response
	return message.NewAssistantMessage(msgContent), nil
}

// generateContent is the generator function for the Gemini model.
func (m *GoogleModel) generateContent(modelID string, messages []message.Message, opts model.GenerateOptions) (message.Message, error) {
	ctx := context.Background()
	ctx, span := observability.Tracer().Start(ctx, "GoogleModel.generateContent",
		trace.WithAttributes(
			observability.KeyString("model_id", modelID),
			observability.KeyFloat64("temperature", opts.Temperature),
		),
	)
	defer span.End()

	logger := observability.Logger(ctx)
	logger.Debug("Generating content with Gemini model",
		slog.String("model", modelID),
		slog.Int("numMessages", len(messages)),
		slog.Float64("temperature", opts.Temperature),
	)

	// Apply generation options
	geminiModel := m.geminiModel.Clone()
	geminiModel.Temperature = opts.Temperature
	geminiModel.TopP = opts.TopP
	if opts.MaxTokens > 0 {
		geminiModel.MaxOutputTokens = opts.MaxTokens
	}

	// Convert the messages to genai format
	contents, err := convertMessagesToGenAI(messages)
	if err != nil {
		return message.Message{}, fmt.Errorf("failed to convert messages to genai format: %w", err)
	}

	// Generate content
	resp, err := geminiModel.GenerateContent(ctx, contents...)
	if err != nil {
		return message.Message{}, fmt.Errorf("genai generation failed: %w", err)
	}

	// Convert the response to an ADK message
	responseMsg, err := convertGenAIResponseToMessage(resp)
	if err != nil {
		return message.Message{}, fmt.Errorf("failed to convert genai response: %w", err)
	}

	return responseMsg, nil
}

// GenerateWithTools overrides the base implementation to handle tools.
func (m *GoogleModel) GenerateWithTools(ctx context.Context, messages []message.Message, tools []model.ToolDefinition) (message.Message, error) {
	if !m.HasCapability(model.ModelCapabilityToolCalling) && !m.HasCapability(model.ModelCapabilityFunctionCalling) {
		return message.Message{}, fmt.Errorf("tool calling not supported by model %s", m.ModelID())
	}

	ctx, span := observability.Tracer().Start(ctx, "GoogleModel.GenerateWithTools",
		trace.WithAttributes(
			observability.KeyString("model_id", m.ModelID()),
			observability.KeyInt("num_tools", len(tools)),
		),
	)
	defer span.End()

	logger := observability.Logger(ctx)
	logger.Debug("Generating content with tools using Gemini model",
		slog.String("model", m.ModelID()),
		slog.Int("numMessages", len(messages)),
		slog.Int("numTools", len(tools)),
	)

	// Convert messages to genai format
	contents, err := convertMessagesToGenAI(messages)
	if err != nil {
		return message.Message{}, fmt.Errorf("failed to convert messages to genai format: %w", err)
	}

	// Convert tool definitions to genai format
	genaiTools, err := convertToolDefinitionsToGenAI(tools)
	if err != nil {
		return message.Message{}, fmt.Errorf("failed to convert tool definitions to genai format: %w", err)
	}

	// Create a clone of the model with tools
	geminiModel := m.geminiModel.Clone()
	geminiModel.Tools = genaiTools

	// Generate the content
	resp, err := geminiModel.GenerateContent(ctx, contents...)
	if err != nil {
		return message.Message{}, fmt.Errorf("genai generation with tools failed: %w", err)
	}

	// Convert the response to an ADK message
	responseMsg, err := convertGenAIResponseToMessage(resp)
	if err != nil {
		return message.Message{}, fmt.Errorf("failed to convert genai response: %w", err)
	}

	return responseMsg, nil
}

// GenerateStream overrides the base implementation to handle streaming.
func (m *GoogleModel) GenerateStream(ctx context.Context, messages []message.Message, handler model.ResponseHandler) error {
	if !m.HasCapability(model.ModelCapabilityStreaming) {
		return fmt.Errorf("streaming not supported by model %s", m.ModelID())
	}

	ctx, span := observability.Tracer().Start(ctx, "GoogleModel.GenerateStream",
		trace.WithAttributes(
			observability.KeyString("model_id", m.ModelID()),
		),
	)
	defer span.End()

	logger := observability.Logger(ctx)
	logger.Debug("Streaming content from Gemini model",
		slog.String("model", m.ModelID()),
		slog.Int("numMessages", len(messages)),
	)

	// Convert messages to genai format
	contents, err := convertMessagesToGenAI(messages)
	if err != nil {
		return fmt.Errorf("failed to convert messages to genai format: %w", err)
	}

	// Create a streaming request
	iter := m.geminiModel.GenerateContentStream(ctx, contents...)

	// Process streaming responses
	var lastResponseChunk string

	for {
		resp, err := iter.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("error during streaming: %w", err)
		}

		// Skip empty responses
		if len(resp.Candidates) == 0 || len(resp.Candidates[0].Content.Parts) == 0 {
			continue
		}

		// Extract text chunks from response
		var textChunk string
		for _, part := range resp.Candidates[0].Content.Parts {
			if text, ok := part.(genai.Text); ok {
				textChunk += string(text)
			}
		}

		// Skip empty chunks
		if textChunk == "" {
			continue
		}

		// Create and send delta message
		deltaMsg := message.NewAssistantMessage(textChunk)

		// For debugging (can be removed in production)
		if logger.Enabled(ctx, slog.LevelDebug) {
			jsonText, _ := sonic.MarshalString(deltaMsg)
			logger.Debug("Streaming chunk", slog.String("chunk", jsonText))
		}

		handler(deltaMsg)
		lastResponseChunk = textChunk
	}

	// If we didn't send anything, send an empty message to signal completion
	if lastResponseChunk == "" {
		handler(message.NewAssistantMessage(""))
	}

	return nil
}

// Close closes the client connection
func (m *GoogleModel) Close() error {
	if m.client != nil {
		return m.client.Close()
	}
	return nil
}

func init() {
	// Register Gemini model with the registry
	Register("gemini-.*", func(modelID string) (model.Model, error) {
		// Note: In a real implementation, API key would be configured through environment variables
		apiKey := "" // Should be obtained from environment or configuration
		return NewGoogleModel(modelID, apiKey, "")
	})
}

