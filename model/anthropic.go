// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"

	anthropic "github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/packages/ssestream"
	"google.golang.org/genai"
)

// ClaudeRequest contains the request parameters for Claude models.
type ClaudeRequest struct {
	SystemInstruction string
	Messages          []*genai.Content
	Tools             []*genai.Tool
}

// ClaudeLLM represents a Claude Large Language Model.
type ClaudeLLM struct {
	*BaseLLM
	client         anthropic.Client
	clientOnce     sync.Once
	defaultModel   string
	anthropicError error
}

var _ GenerativeModel = (*ClaudeLLM)(nil)

// NewClaudeLLM creates a new Claude LLM instance.
func NewClaudeLLM(ctx context.Context, apiKey string, modelName string) (*ClaudeLLM, error) {
	// Use default model if none provided
	if modelName == "" {
		modelName = string(anthropic.ModelClaude3_5SonnetLatest)
	}

	// Create genai client for BaseLLM
	genaiClient, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey: apiKey,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create genai client: %w", err)
	}

	return &ClaudeLLM{
		BaseLLM:      NewBaseLLM(modelName, genaiClient),
		defaultModel: modelName,
	}, nil
}

// anthropicClient returns a cached Anthropic client.
func (m *ClaudeLLM) anthropicClient() (anthropic.Client, error) {
	m.clientOnce.Do(func() {
		apiKey := os.Getenv("ANTHROPIC_API_KEY")
		if apiKey == "" {
			m.anthropicError = fmt.Errorf("ANTHROPIC_API_KEY environment variable not set")
			return
		}

		m.client = anthropic.NewClient(option.WithAPIKey(apiKey))
	})

	return m.client, m.anthropicError
}

// SupportedModels returns a list of supported Claude models.
func (m *ClaudeLLM) SupportedModels() []string {
	return []string{
		string(anthropic.ModelClaude3OpusLatest),
		string(anthropic.ModelClaude3_5SonnetLatest),
		string(anthropic.ModelClaude3_7SonnetLatest),
		"claude-3-opus-20240229",
		"claude-3-sonnet-20240229",
		"claude-3-haiku-20240307",
	}
}

// Connect creates a live connection to the Claude LLM.
func (m *ClaudeLLM) Connect() (BaseLLMConnection, error) {
	// Ensure we can get an Anthropic client
	_, err := m.anthropicClient()
	if err != nil {
		return nil, err
	}

	// For now, this is a placeholder as we haven't implemented ClaudeLLMConnection yet
	// In a real implementation, we would return a proper ClaudeLLMConnection
	return nil, fmt.Errorf("ClaudeLLMConnection not implemented yet")
}

// extractSystemPrompt extracts system prompt text from the first message if it's a system message
func extractSystemPrompt(messages []*genai.Content) (string, bool) {
	if len(messages) == 0 || messages[0].Role != "system" {
		return "", false
	}

	systemText := ""
	for _, part := range messages[0].Parts {
		if part != nil && part.Text != "" {
			systemText += part.Text
		}
	}
	return systemText, systemText != ""
}

// extractFunctionDeclarations extracts function declarations from content parts
func extractFunctionDeclarations(contents []*genai.Content) []anthropic.ToolUnionParam {
	var tools []anthropic.ToolUnionParam

	for _, content := range contents {
		if content.Parts == nil {
			continue
		}

		for _, part := range content.Parts {
			if part != nil && part.FunctionCall != nil {
				toolSchema := anthropic.ToolInputSchemaParam{
					Type:       "object",
					Properties: make(map[string]any),
				}

				// Create a tool from function
				tool := anthropic.ToolUnionParamOfTool(toolSchema, part.FunctionCall.Name)
				tools = append(tools, tool)
			}
		}
	}

	return tools
}

// Generate generates content from the model.
func (m *ClaudeLLM) Generate(ctx context.Context, request GenerateRequest) (*GenerateResponse, error) {
	anthropicClient, err := m.anthropicClient()
	if err != nil {
		return nil, err
	}

	// Convert messages to Anthropic format
	messageParams := contentToMessageParam(request.Content)

	// Prepare parameters
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(m.model),
		Messages:  messageParams,
		MaxTokens: 4096,
	}

	// Apply generation config if provided
	if request.GenerationConfig != nil {
		if request.GenerationConfig.Temperature != nil {
			params.Temperature = anthropic.Float(float64(*request.GenerationConfig.Temperature))
		}

		// MaxOutputTokens is an int32 directly, not a pointer
		if request.GenerationConfig.MaxOutputTokens > 0 {
			params.MaxTokens = int64(request.GenerationConfig.MaxOutputTokens)
		}

		if request.GenerationConfig.TopP != nil {
			params.TopP = anthropic.Float(float64(*request.GenerationConfig.TopP))
		}
	}

	// Apply system prompt if it exists in first content
	systemText, hasSystem := extractSystemPrompt(request.Content)
	if hasSystem {
		// For System, we need to create TextBlockParam
		var systemTextBlocks []anthropic.TextBlockParam
		systemTextBlocks = append(systemTextBlocks, anthropic.TextBlockParam{
			Text: systemText,
			Type: "text",
		})
		params.System = systemTextBlocks

		// Remove system message from the message list since it's set separately
		// Only if there are more than one message, otherwise we keep the empty list
		if len(messageParams) > 1 {
			messageParams = messageParams[1:]
			params.Messages = messageParams
		}
	}

	// Add tools if provided
	toolDeclarations := extractFunctionDeclarations(request.Content)
	if len(toolDeclarations) > 0 {
		params.Tools = toolDeclarations
	}

	// Make API call
	message, err := anthropicClient.Messages.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("claude API error: %w", err)
	}

	// Convert response to GenAI format
	content := anthropicMessageToGenAIContent(message)

	// Create response
	response := &genai.GenerateContentResponse{
		Candidates: []*genai.Candidate{
			{
				Content: content,
			},
		},
	}

	return &GenerateResponse{
		Content: response,
	}, nil
}

// anthropicMessageToGenAIContent converts an Anthropic message to GenAI content
func anthropicMessageToGenAIContent(message *anthropic.Message) *genai.Content {
	var parts []*genai.Part

	// Convert content blocks to parts
	for _, block := range message.Content {
		if block.Type == "text" {
			// Handle text content - Text is a string
			parts = append(parts, genai.NewPartFromText(block.Text))
		}
	}

	// Create a new content with assistant role
	return &genai.Content{
		Role:  "assistant",
		Parts: parts,
	}
}

// GenerateContent generates content from the model.
func (m *ClaudeLLM) GenerateContent(ctx context.Context, contents []*genai.Content, config *genai.GenerateContentConfig) (*genai.GenerateContentResponse, error) {
	request := GenerateRequest{
		Content: contents,
	}

	if config != nil {
		genConfig := &genai.GenerationConfig{}
		if config.Temperature != nil {
			genConfig.Temperature = config.Temperature
		}

		// MaxOutputTokens is an int32 directly, not a pointer
		genConfig.MaxOutputTokens = config.MaxOutputTokens

		if config.TopP != nil {
			genConfig.TopP = config.TopP
		}
		if config.TopK != nil {
			genConfig.TopK = config.TopK
		}
		request.GenerationConfig = genConfig
		request.SafetySettings = config.SafetySettings
	}

	resp, err := m.Generate(ctx, request)
	if err != nil {
		return nil, err
	}
	return resp.Content, nil
}

// StreamGenerate streams generated content from the model.
func (m *ClaudeLLM) StreamGenerate(ctx context.Context, request GenerateRequest) (GenerateStreamResponse, error) {
	anthropicClient, err := m.anthropicClient()
	if err != nil {
		return nil, err
	}

	// Convert to Anthropic format
	messageParams := contentToMessageParam(request.Content)

	// Prepare parameters
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(m.model),
		Messages:  messageParams,
		MaxTokens: 4096,
	}

	// Apply generation config if provided
	if request.GenerationConfig != nil {
		if request.GenerationConfig.Temperature != nil {
			params.Temperature = anthropic.Float(float64(*request.GenerationConfig.Temperature))
		}

		// MaxOutputTokens is an int32 directly, not a pointer
		if request.GenerationConfig.MaxOutputTokens > 0 {
			params.MaxTokens = int64(request.GenerationConfig.MaxOutputTokens)
		}

		if request.GenerationConfig.TopP != nil {
			params.TopP = anthropic.Float(float64(*request.GenerationConfig.TopP))
		}
	}

	// Apply system prompt if it exists in first content
	systemText, hasSystem := extractSystemPrompt(request.Content)
	if hasSystem {
		// For System, we need to create TextBlockParam
		var systemTextBlocks []anthropic.TextBlockParam
		systemTextBlocks = append(systemTextBlocks, anthropic.TextBlockParam{
			Text: systemText,
			Type: "text",
		})
		params.System = systemTextBlocks

		// Remove system message from the message list since it's set separately
		// Only if there are more than one message, otherwise we keep the empty list
		if len(messageParams) > 1 {
			messageParams = messageParams[1:]
			params.Messages = messageParams
		}
	}

	// Add tools if provided
	toolDeclarations := extractFunctionDeclarations(request.Content)
	if len(toolDeclarations) > 0 {
		params.Tools = toolDeclarations
	}

	// Make streaming API call - stream parameter is added by the method
	stream := anthropicClient.Messages.NewStreaming(ctx, params)

	return &claudeStreamResponse{
		stream: stream,
		ctx:    ctx,
	}, nil
}

// StreamGenerateContent streams generated content from the model.
func (m *ClaudeLLM) StreamGenerateContent(ctx context.Context, contents []*genai.Content, config *genai.GenerateContentConfig) (GenerateStreamResponse, error) {
	request := GenerateRequest{
		Content: contents,
	}

	if config != nil {
		genConfig := &genai.GenerationConfig{}
		if config.Temperature != nil {
			genConfig.Temperature = config.Temperature
		}

		// MaxOutputTokens is an int32 directly, not a pointer
		genConfig.MaxOutputTokens = config.MaxOutputTokens

		if config.TopP != nil {
			genConfig.TopP = config.TopP
		}
		if config.TopK != nil {
			genConfig.TopK = config.TopK
		}
		request.GenerationConfig = genConfig
		request.SafetySettings = config.SafetySettings
	}

	return m.StreamGenerate(ctx, request)
}

// WithGenerationConfig returns a new model with the specified generation config.
func (m *ClaudeLLM) WithGenerationConfig(config *genai.GenerationConfig) GenerativeModel {
	// Create a new instance to avoid copying sync.Once
	clone := &ClaudeLLM{
		BaseLLM:        m.BaseLLM.WithGenerationConfig(config),
		client:         m.client,
		defaultModel:   m.defaultModel,
		anthropicError: m.anthropicError,
	}
	return clone
}

// WithSafetySettings returns a new model with the specified safety settings.
func (m *ClaudeLLM) WithSafetySettings(settings []*genai.SafetySetting) GenerativeModel {
	// Create a new instance to avoid copying sync.Once
	clone := &ClaudeLLM{
		BaseLLM:        m.BaseLLM.WithSafetySettings(settings),
		client:         m.client,
		defaultModel:   m.defaultModel,
		anthropicError: m.anthropicError,
	}
	return clone
}

// claudeStreamResponse implements GenerateStreamResponse for Claude models.
type claudeStreamResponse struct {
	stream  *ssestream.Stream[anthropic.MessageStreamEventUnion]
	ctx     context.Context
	message anthropic.Message
	done    bool
	nextErr error
}

// Next returns the next response in the stream.
func (s *claudeStreamResponse) Next() (*genai.GenerateContentResponse, error) {
	if s.done {
		return nil, s.nextErr
	}

	if !s.stream.Next() {
		s.done = true
		if err := s.stream.Err(); err != nil {
			s.nextErr = err
			return nil, err
		}
		// End of stream
		return nil, nil
	}

	// Get the current event
	event := s.stream.Current()

	// Accumulate the response
	if err := s.message.Accumulate(event); err != nil {
		log.Printf("Error accumulating message: %v", err)
	}

	// Create partial response
	var parts []*genai.Part

	// Process based on event type
	switch event.Type {
	case "content_block_delta":
		// Extract delta text from content block delta
		blockDeltaEvent := event.AsContentBlockDeltaEvent()
		if blockDeltaEvent.Delta.Type == "text_delta" {
			parts = append(parts, genai.NewPartFromText(blockDeltaEvent.Delta.Text))
		}
	}

	// Only return a response if we have parts
	if len(parts) > 0 {
		response := &genai.GenerateContentResponse{
			Candidates: []*genai.Candidate{
				{
					Content: &genai.Content{
						Role:  "assistant",
						Parts: parts,
					},
				},
			},
		}
		return response, nil
	}

	// If no content, get the next chunk
	return s.Next()
}

// Helper functions for conversion between GenAI and Anthropic formats

// contentToMessageParam converts GenAI content to Anthropic message parameters.
func contentToMessageParam(contents []*genai.Content) []anthropic.MessageParam {
	var messageParams []anthropic.MessageParam

	for _, content := range contents {
		// Skip system messages (handled separately in Generate/StreamGenerate)
		if content.Role == "system" {
			continue
		}

		var contentBlocks []anthropic.ContentBlockParamUnion
		for _, part := range content.Parts {
			if part != nil && part.Text != "" {
				// Create text block
				contentBlocks = append(contentBlocks, anthropic.NewTextBlock(part.Text))
			}
		}

		// Create a message parameter with the role and content blocks
		var messageParam anthropic.MessageParam
		switch content.Role {
		case "user":
			messageParam = anthropic.NewUserMessage(contentBlocks...)
		case "assistant":
			messageParam = anthropic.NewAssistantMessage(contentBlocks...)
		default:
			log.Printf("Unsupported role: %s, using 'user'", content.Role)
			messageParam = anthropic.NewUserMessage(contentBlocks...)
		}

		messageParams = append(messageParams, messageParam)
	}

	return messageParams
}
