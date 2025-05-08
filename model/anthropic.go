// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"os"
	"slices"

	anthropic "github.com/anthropics/anthropic-sdk-go"
	anthropic_bedrock "github.com/anthropics/anthropic-sdk-go/bedrock"
	anthropic_option "github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/packages/param"
	"github.com/anthropics/anthropic-sdk-go/shared/constant"
	anthropic_vertex "github.com/anthropics/anthropic-sdk-go/vertex"
	"github.com/bytedance/sonic"
	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/types"
)

// ClaudeMode represents the mode of the Claude model.
type ClaudeMode int

const (
	// ClaudeModeAnthropic is the mode for Anthropic's official models.
	ClaudeModeAnthropic ClaudeMode = iota

	// ClaudeModeVertexAI is the mode for Google Cloud Platform (GCP) Vertex AI models.
	ClaudeModeVertexAI

	// ClaudeModeBedrock is the mode for Amazon Web Services (AWS) Bedrock models.
	ClaudeModeBedrock
)

// detectClaudeDefaultModel returns the default model name based on the mode.
func detectClaudeDefaultModel(mode ClaudeMode) string {
	switch mode {
	case ClaudeModeAnthropic:
		return anthropic.ModelClaude3_5Sonnet20241022
	case ClaudeModeVertexAI:
		return "claude-3-5-sonnet-v2@20241022"
	case ClaudeModeBedrock:
		return "anthropic.claude-3-5-sonnet-20241022-v2:0"
	default:
		return ""
	}
}

// Claude represents a Claude Large Language Model.
type Claude struct {
	*Config

	anthropicClient anthropic.Client
}

var _ Model = (*Claude)(nil)

// NewClaude creates a new Claude LLM instance.
func NewClaude(ctx context.Context, modelName string, mode ClaudeMode, opts ...Option) (*Claude, error) {
	// Use default model if none provided
	if modelName == "" {
		modelName = detectClaudeDefaultModel(mode)
	}

	var ropts []anthropic_option.RequestOption
	switch mode {
	case ClaudeModeAnthropic:
		ropts = append(ropts, anthropic.DefaultClientOptions()...)

	case ClaudeModeVertexAI:
		region := cmp.Or(os.Getenv("GOOGLE_CLOUD_LOCATION"), os.Getenv("GOOGLE_CLOUD_REGION"))
		if region == "" {
			return nil, fmt.Errorf("%q or %q is required", "GOOGLE_CLOUD_LOCATION", "GOOGLE_CLOUD_REGION")
		}
		projectID := os.Getenv("GOOGLE_CLOUD_PROJECT")
		if projectID == "" {
			return nil, fmt.Errorf("%q is required", "GOOGLE_CLOUD_PROJECT")
		}
		// https://pkg.go.dev/cloud.google.com/go/aiplatform/apiv1#DefaultAuthScopes
		scopes := []string{
			"https://www.googleapis.com/auth/cloud-platform",
			"https://www.googleapis.com/auth/cloud-platform.read-only",
		}
		ropts = append(ropts, anthropic_vertex.WithGoogleAuth(ctx, region, projectID, scopes...))

	case ClaudeModeBedrock:
		ropts = append(ropts, anthropic_bedrock.WithLoadDefaultConfig(ctx))
	}

	anthropicClient := anthropic.NewClient(ropts...)

	claude := &Claude{
		Config: &Config{
			model: modelName,
		},
		anthropicClient: anthropicClient,
	}
	for _, opt := range opts {
		claude.Config = opt.apply(claude.Config)
	}

	return claude, nil
}

// Name returns the name of the model.
func (m *Claude) Name() string {
	return m.model
}

// SupportedModels returns a list of supported Claude models.
//
// See https://docs.anthropic.com/en/docs/about-claude/models/all-models.
func (m *Claude) SupportedModels() []string {
	return []string{
		// Anthropic API
		anthropic.ModelClaude3_7SonnetLatest,
		anthropic.ModelClaude3_7Sonnet20250219,
		anthropic.ModelClaude3_5HaikuLatest,
		anthropic.ModelClaude3_5Haiku20241022,
		anthropic.ModelClaude3_5SonnetLatest,
		anthropic.ModelClaude3_5Sonnet20241022,
		anthropic.ModelClaude_3_5_Sonnet_20240620,
		anthropic.ModelClaude3OpusLatest,
		anthropic.ModelClaude_3_Opus_20240229,

		// GCP Vertex AI
		"claude-3-7-sonnet@20250219",
		"claude-3-5-haiku@20241022",
		"claude-3-5-sonnet-v2@20241022",
		"claude-3-opus@20240229",
		"claude-3-sonnet@20240229",
		"claude-3-haiku@20240307",

		// AWS Bedrock
		"anthropic.claude-3-7-sonnet-20250219-v1:0",
		"anthropic.claude-3-5-haiku-20241022-v1:0",
		"anthropic.claude-3-5-sonnet-20241022-v2:0",
		"anthropic.claude-3-5-sonnet-20240620-v1:0",
		"anthropic.claude-3-opus-20240229-v1:0",
		"anthropic.claude-3-sonnet-20240229-v1:0",
		"anthropic.claude-3-haiku-20240307-v1:0",
	}
}

// Connect creates a live connection to the Claude LLM.
//
// TODO(zchee): implements.
func (m *Claude) Connect() (BaseConnection, error) {
	// Ensure we can get an Anthropic client
	_ = m.anthropicClient

	// For now, this is a placeholder as we haven't implemented ClaudeConnection yet
	// In a real implementation, we would return a proper ClaudeConnection
	return nil, fmt.Errorf("ClaudeConnection not implemented yet")
}

// GenerateContent generates content from the model.
func (m *Claude) GenerateContent(ctx context.Context, request *types.LLMRequest) (*types.LLMResponse, error) {
	// Convert messages to Anthropic format
	messages := make([]anthropic.MessageParam, len(request.Contents))
	for i, content := range request.Contents {
		messages[i] = m.contentToMessageParam(content)
	}

	// Prepare parameters
	params := anthropic.MessageNewParams{
		Model:     anthropic.Model(m.model),
		Messages:  messages,
		MaxTokens: 4096,
	}

	// Apply generation config if provided
	if config := request.Config; config != nil {
		// MaxOutputTokens is an int32 directly, not a pointer
		if config.MaxOutputTokens > 0 {
			params.MaxTokens = int64(config.MaxOutputTokens)
		}

		if config.Temperature != nil {
			params.Temperature = anthropic.Float(float64(*config.Temperature))
		}

		if config.TopK != nil {
			params.TopK = anthropic.Int(int64(*config.TopK))
		}

		if config.TopP != nil {
			params.TopP = anthropic.Float(float64(*config.TopP))
		}

		if config.SystemInstruction != nil {
			for _, instruction := range config.SystemInstruction.Parts {
				params.System = append(params.System, anthropic.TextBlockParam{
					Text: instruction.Text,
				})
			}
		}

		// Add tools if provided
		if len(config.Tools) > 0 && config.Tools[0].FunctionDeclarations != nil {
			tools := make([]anthropic.ToolUnionParam, 0, len(config.Tools[0].FunctionDeclarations))
			for _, funcDeclarations := range config.Tools[0].FunctionDeclarations {
				toolUnion, err := m.funcDeclarationToToolParam(funcDeclarations)
				if err != nil {
					return nil, err
				}
				tools = append(tools, toolUnion)
			}
			params.Tools = tools
		}
	}

	if len(request.ToolMap) > 0 {
		toolchoice := anthropic.ToolChoiceUnionParam{
			OfAuto: &anthropic.ToolChoiceAutoParam{
				Type:                   constant.ValueOf[constant.Auto]().Default(),
				DisableParallelToolUse: anthropic.Bool(false),
			},
		}
		params.ToolChoice = toolchoice
	}

	// Make API call
	resp, err := m.anthropicClient.Messages.New(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("claude API error: %w", err)
	}

	return m.messageToLLMResponse(resp), nil
}

// StreamGenerateContent streams generated content from the model.
func (m *Claude) StreamGenerateContent(ctx context.Context, request *types.LLMRequest) iter.Seq2[*types.LLMResponse, error] {
	return func(yield func(*types.LLMResponse, error) bool) {
		// Convert to Anthropic format
		messages := make([]anthropic.MessageParam, len(request.Contents))
		for i, content := range request.Contents {
			messages[i] = m.contentToMessageParam(content)
		}

		// Prepare parameters
		params := anthropic.MessageNewParams{
			Model:     anthropic.Model(m.model),
			Messages:  messages,
			MaxTokens: 4096,
		}

		// Apply generation config if provided
		if config := request.Config; config != nil {
			// MaxOutputTokens is an int32 directly, not a pointer
			if config.MaxOutputTokens > 0 {
				params.MaxTokens = int64(config.MaxOutputTokens)
			}

			if config.Temperature != nil {
				params.Temperature = anthropic.Float(float64(*config.Temperature))
			}

			if config.TopK != nil {
				params.TopK = anthropic.Int(int64(*config.TopK))
			}

			if config.TopP != nil {
				params.TopP = anthropic.Float(float64(*config.TopP))
			}

			if config.SystemInstruction != nil {
				for _, instruction := range config.SystemInstruction.Parts {
					params.System = append(params.System, anthropic.TextBlockParam{
						Text: instruction.Text,
					})
				}
			}

			// Add tools if provided
			if len(config.Tools) > 0 && config.Tools[0].FunctionDeclarations != nil {
				tools := make([]anthropic.ToolUnionParam, 0, len(config.Tools[0].FunctionDeclarations))
				for _, funcDeclarations := range config.Tools[0].FunctionDeclarations {
					toolUnion, err := m.funcDeclarationToToolParam(funcDeclarations)
					if err != nil {
						if !yield(nil, err) {
							return
						}
					}
					tools = append(tools, toolUnion)
				}
				params.Tools = tools
			}
		}

		if len(request.ToolMap) > 0 {
			toolchoice := anthropic.ToolChoiceUnionParam{
				OfAuto: &anthropic.ToolChoiceAutoParam{
					Type:                   constant.ValueOf[constant.Auto]().Default(),
					DisableParallelToolUse: anthropic.Bool(false),
				},
			}
			params.ToolChoice = toolchoice
		}

		// Make streaming API call - stream parameter is added by the method
		stream := m.anthropicClient.Messages.NewStreaming(ctx, params)

		if ctx.Err() != nil || stream == nil {
			return
		}

		message := anthropic.Message{}
		for stream.Next() {
			// Accumulate the response
			llmResp := stream.Current()
			if err := message.Accumulate(llmResp); err != nil {
				m.logger.ErrorContext(ctx, "accumulating message", slog.Any("err", err))
				if !yield(nil, err) {
					return
				}
			}

			if message.StopReason == anthropic.StopReasonEndTurn {
				return
			}

			// Create partial response
			var parts []*genai.Part
			partial := true

			// Process based on event type
			switch messageStreamEvent := llmResp.AsAny().(type) {
			case anthropic.MessageStartEvent:
				// no-op
			case anthropic.ContentBlockStartEvent:
				// no-op
			case anthropic.ContentBlockDeltaEvent:
				// Extract delta from content block delta
				switch delta := messageStreamEvent.Delta.AsAny().(type) {
				case anthropic.TextDelta:
					parts = append(parts, genai.NewPartFromText(delta.Text))
				}
			case anthropic.ContentBlockStopEvent:
				// no-op
			}

			for _, mcontent := range message.Content {
				part, err := m.contentBlockToPart(mcontent)
				if err != nil {
					if !yield(nil, err) {
						return
					}
				}
				if part.Text != "" {
					parts = append(parts, genai.NewPartFromText(part.Text))
					partial = false
				}
			}

			// Only return a response if we have parts
			if len(parts) > 0 {
				response := &genai.GenerateContentResponse{
					Candidates: []*genai.Candidate{
						{
							Content: &genai.Content{
								Role:  RoleAssistant,
								Parts: parts,
							},
						},
					},
				}
				resp := types.CreateLLMResponse(response)
				if partial {
					resp.WithPartial(true)
				}
				if !yield(resp, nil) {
					return
				}
			}
		}
		if err := stream.Err(); err != nil {
			if !yield(nil, err) {
				return
			}
		}
	}
}

var genAIRoles = []Role{
	RoleModel,
	RoleAssistant,
}

// asClaudeRole converts [genai.Role] to [anthropic.MessageParamRole].
func (m *Claude) asClaudeRole(role string) anthropic.MessageParamRole {
	if slices.Contains(genAIRoles, role) {
		return anthropic.MessageParamRoleAssistant
	}
	return anthropic.MessageParamRoleUser
}

var claudeStopReasons = []anthropic.StopReason{
	anthropic.StopReasonEndTurn,
	anthropic.StopReasonStopSequence,
	anthropic.StopReasonToolUse,
}

// asGenAIFinishReason converts [anthropic.StopReason] to [genai.FinishReason].
func (m *Claude) asGenAIFinishReason(stopReason anthropic.StopReason) genai.FinishReason {
	if slices.Contains(claudeStopReasons, stopReason) {
		return genai.FinishReasonStop
	}

	if stopReason == anthropic.StopReasonMaxTokens {
		return genai.FinishReasonMaxTokens
	}

	return genai.FinishReasonUnspecified
}

// partToMessageBlock converts [*genai.Part] to [anthropic.ContentBlockParamUnion].
func (m *Claude) partToMessageBlock(part *genai.Part) (anthropic.ContentBlockParamUnion, error) {
	if part.Text != "" {
		params := anthropic.NewTextBlock(part.Text)
		params.OfText.Type = constant.ValueOf[constant.Text]().Default()
		return params, nil
	}

	if part.FunctionCall != nil {
		funcCall := part.FunctionCall
		// Assert function call name if [genai.Part.FunctionCall] is non-nil
		if funcCall.Name != "" {
			return anthropic.ContentBlockParamUnion{}, errors.New("FunctionCall name is empty")
		}

		params := anthropic.ContentBlockParamOfToolUse(funcCall.ID, funcCall.Args, funcCall.Name)
		params.OfToolUse.Type = constant.ValueOf[constant.ToolUse]().Default()
		return params, nil
	}

	if part.FunctionResponse != nil {
		funcResp := part.FunctionResponse
		if result, ok := funcResp.Response["result"]; ok {
			params := anthropic.NewToolResultBlock(funcResp.ID, fmt.Sprintf("%s", result), false)
			params.OfToolResult.Type = constant.ValueOf[constant.ToolResult]().Default()
			return params, nil
		}
	}

	return anthropic.ContentBlockParamUnion{}, fmt.Errorf("not supported yet %T part type", part)
}

// contentToMessageParam converts [*genai.Content] to [anthropic.MessageParam].
func (m *Claude) contentToMessageParam(content *genai.Content) (msgParam anthropic.MessageParam) {
	// Skip system messages (handled separately in Generate/StreamGenerate)
	if content.Role == RoleSystem {
		return
	}
	msgParam.Role = m.asClaudeRole(content.Role)

	msgParam.Content = make([]anthropic.ContentBlockParamUnion, 0, len(content.Parts))
	for _, part := range content.Parts {
		msgBlock, err := m.partToMessageBlock(part)
		if err != nil {
			continue
		}
		msgParam.Content = append(msgParam.Content, msgBlock)
	}

	return msgParam
}

// contentBlockToPart converts [anthropic.ContentBlockUnion] to [*genai.Part].
func (m *Claude) contentBlockToPart(contentBlock anthropic.ContentBlockUnion) (*genai.Part, error) {
	switch cBlock := contentBlock.AsAny().(type) {
	case anthropic.TextBlock:
		return genai.NewPartFromText(cBlock.Text), nil

	case anthropic.ToolUseBlock:
		if cBlock.Input == nil {
			return nil, fmt.Errorf("input field must be non-nil: %#v", cBlock)
		}
		var args map[string]any
		if err := sonic.ConfigFastest.Unmarshal(cBlock.Input, &args); err != nil {
			return nil, fmt.Errorf("unmarshal ToolUseBlock input: %w", err)
		}
		part := genai.NewPartFromFunctionCall(cBlock.Name, args)
		part.FunctionCall.ID = cBlock.ID
		return part, nil

	case anthropic.ThinkingBlock, anthropic.RedactedThinkingBlock:
		return nil, fmt.Errorf("not supported yet converts %T content block", cBlock)
	}

	return nil, fmt.Errorf("unreachable: no variant present")
}

// messageToLLMResponse converts [*anthropic.Message] to [*LLMResponse].
func (m *Claude) messageToLLMResponse(message *anthropic.Message) *types.LLMResponse {
	parts := make([]*genai.Part, 0, len(message.Content))
	for _, mcontent := range message.Content {
		part, err := m.contentBlockToPart(mcontent)
		if err != nil {
			continue
		}
		parts = append(parts, part)
	}

	usageMetadata := &genai.GenerateContentResponseUsageMetadata{
		PromptTokenCount:     int32(message.Usage.InputTokens),
		CandidatesTokenCount: int32(message.Usage.OutputTokens),
		TotalTokenCount:      int32(message.Usage.InputTokens + message.Usage.OutputTokens),
	}

	return &types.LLMResponse{
		Content: &genai.Content{
			Role:  RoleModel,
			Parts: parts,
		},
		FinishReason:  m.asGenAIFinishReason(message.StopReason),
		UsageMetadata: usageMetadata,
	}
}

// funcDeclarationToToolParam converts [*genai.FunctionDeclaration] to [anthropic.ToolUnionParam].
func (m *Claude) funcDeclarationToToolParam(funcDeclaration *genai.FunctionDeclaration) (toolUnion anthropic.ToolUnionParam, err error) {
	if funcDeclaration.Name == "" {
		return toolUnion, errors.New("functionDeclaration name is empty")
	}

	inputSchemaProps := make(map[string]*genai.Schema)
	if params := funcDeclaration.Parameters; params != nil && params.Properties != nil {
		maps.Insert(inputSchemaProps, maps.All(params.Properties))
	}
	inputSchema := anthropic.ToolInputSchemaParam{
		Type:       constant.ValueOf[constant.Object]().Default(),
		Properties: inputSchemaProps,
	}

	toolUnion = anthropic.ToolUnionParamOfTool(inputSchema, funcDeclaration.Name)
	toolUnion.OfTool.Description = param.NewOpt(funcDeclaration.Description)

	return toolUnion, nil
}
