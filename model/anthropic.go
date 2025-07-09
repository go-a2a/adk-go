// Copyright 2025 The Go A2A Authors
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"maps"
	"os"
	"slices"
	"strings"

	aiplatform "cloud.google.com/go/aiplatform/apiv1beta1"
	anthropic "github.com/anthropics/anthropic-sdk-go"
	anthropic_bedrock "github.com/anthropics/anthropic-sdk-go/bedrock"
	anthropic_option "github.com/anthropics/anthropic-sdk-go/option"
	"github.com/anthropics/anthropic-sdk-go/packages/param"
	"github.com/anthropics/anthropic-sdk-go/shared/constant"
	anthropic_vertex "github.com/anthropics/anthropic-sdk-go/vertex"
	"github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"google.golang.org/genai"

	"github.com/go-a2a/adk-go/internal/pool"
	"github.com/go-a2a/adk-go/types"
)

// ClaudeMode represents a mode of the Claude model.
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
		return string(anthropic.ModelClaude3_5Sonnet20241022)
	case ClaudeModeVertexAI:
		return "claude-3-5-sonnet-v2@20241022"
	case ClaudeModeBedrock:
		return "anthropic.claude-3-5-sonnet-20241022-v2:0"
	default:
		return ""
	}
}

var genAIRoles = []Role{
	RoleModel,
	RoleAssistant,
}

// toClaudeRole converts [genai.Role] to [anthropic.MessageParamRole].
func (m *Claude) toClaudeRole(role string) anthropic.MessageParamRole {
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

// toGenAIFinishReason converts [anthropic.StopReason] to [genai.FinishReason].
func (m *Claude) toGenAIFinishReason(stopReason anthropic.StopReason) genai.FinishReason {
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
	switch {
	case part.Text != "":
		params := anthropic.NewTextBlock(part.Text)
		params.OfText.Type = constant.ValueOf[constant.Text]().Default()
		return params, nil

	case part.FunctionCall != nil:
		funcCall := part.FunctionCall
		// Assert function call name if [genai.Part.FunctionCall] is non-nil
		if funcCall.Name != "" {
			return anthropic.ContentBlockParamUnion{}, errors.New("FunctionCall name is empty")
		}
		params := anthropic.NewToolUseBlock(funcCall.ID, funcCall.Args, funcCall.Name)
		params.OfToolUse.Type = constant.ValueOf[constant.ToolUse]().Default()
		return params, nil

	case part.FunctionResponse != nil:
		funcResp := part.FunctionResponse
		if content, ok := funcResp.Response["result"]; ok {
			params := anthropic.NewToolResultBlock(funcResp.ID)
			params.OfToolResult.Type = constant.ValueOf[constant.ToolResult]().Default()
			params.OfToolResult.Content = append(params.OfToolResult.Content, anthropic.ToolResultBlockParamContentUnion{
				OfText: anthropic.NewTextBlock(content.(string)).OfText,
			})
			return params, nil
		}
	}

	return anthropic.ContentBlockParamUnion{}, fmt.Errorf("not supported yet %T part type", part)
}

// contentToMessageParam converts [*genai.Content] to [anthropic.MessageParam].
func (m *Claude) contentToMessageParam(content *genai.Content) anthropic.MessageParam {
	// Skip system messages (handled separately in Generate/StreamGenerate)
	if content.Role == RoleSystem {
		return anthropic.MessageParam{}
	}

	msgParam := anthropic.MessageParam{
		Role:    m.toClaudeRole(content.Role),
		Content: make([]anthropic.ContentBlockParamUnion, 0, len(content.Parts)),
	}
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
		if err := json.UnmarshalRead(bytes.NewReader(cBlock.Input), args, json.DefaultOptionsV2()); err != nil {
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

// messageToGenerateContentResponse converts [*anthropic.Message] to [*LLMResponse].
func (m *Claude) messageToGenerateContentResponse(ctx context.Context, message *anthropic.Message) *types.LLMResponse {
	sb := pool.String.Get() // for log output
	enc := jsontext.NewEncoder(sb, jsontext.WithIndentPrefix("\t"), jsontext.WithIndent("  "))
	if err := json.MarshalEncode(enc, message); err == nil {
		m.logger.InfoContext(ctx, "Claude response", slog.String("response", sb.String()))
	}
	pool.String.Put(sb)

	parts := make([]*genai.Part, 0, len(message.Content))
	for _, content := range message.Content {
		part, err := m.contentBlockToPart(content)
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
		UsageMetadata: usageMetadata,
		FinishReason:  m.toGenAIFinishReason(message.StopReason),
	}
}

// updateTypeString updates 'type' field to expected JSON schema format.
func (m *Claude) updateTypeString(dict map[string]any) {
	if v, ok := dict["type"]; ok {
		dict["type"] = strings.ToLower(v.(string))
	}

	if v, ok := dict["items"]; ok {
		// 'type' field could exist for items as well, this would be the case if
		// items represent primitive types.
		m.updateTypeString(v.(map[string]any))

		if vv, ok := v.(map[string]any)["properties"]; ok {
			// There could be properties as well on the items, especially if the items
			// are complex object themselves. We recursively traverse each individual
			// property as well and fix the "type" value.
			for _, value := range vv.(map[string]any) {
				m.updateTypeString(value.(map[string]any))
			}
		}
	}
}

// funcDeclarationToToolParam converts [*genai.FunctionDeclaration] to [anthropic.ToolUnionParam].
func (m *Claude) funcDeclarationToToolParam(funcDeclaration *genai.FunctionDeclaration) (toolUnion anthropic.ToolUnionParam, err error) {
	if funcDeclaration.Name == "" {
		return toolUnion, errors.New("functionDeclaration name is empty")
	}

	properties := make(map[string]*genai.Schema)
	if params := funcDeclaration.Parameters; params != nil && params.Properties != nil {
		maps.Insert(properties, maps.All(params.Properties))
	}
	inputSchema := anthropic.ToolInputSchemaParam{
		Type:       constant.ValueOf[constant.Object]().Default(),
		Properties: properties,
	}

	toolUnion = anthropic.ToolUnionParamOfTool(inputSchema, funcDeclaration.Name)
	toolUnion.OfTool.Description = param.NewOpt(funcDeclaration.Description)

	return toolUnion, nil
}

// Claude represents an integration with Claude models served from Vertex AI.
type Claude struct {
	*BaseLLM

	anthropicClient anthropic.Client
}

var _ types.Model = (*Claude)(nil)

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
		scopes := aiplatform.DefaultAuthScopes()
		ropts = append(ropts, anthropic_vertex.WithGoogleAuth(ctx, region, projectID, scopes...))

	case ClaudeModeBedrock:
		ropts = append(ropts, anthropic_bedrock.WithLoadDefaultConfig(ctx))
	}

	anthropicClient := anthropic.NewClient(ropts...)

	claude := &Claude{
		BaseLLM:         NewBaseLLM(modelName),
		anthropicClient: anthropicClient,
	}
	for _, opt := range opts {
		claude.Config = opt.apply(claude.Config)
	}

	return claude, nil
}

// Name returns the name of the [Claude] model.
func (m *Claude) Name() string {
	return m.modelName
}

// SupportedModels returns a list of supported models in the [Claude].
//
// See https://docs.anthropic.com/en/docs/about-claude/models/all-models.
func (m *Claude) SupportedModels() []string {
	return []string{
		// Anthropic API
		string(anthropic.ModelClaude3_7SonnetLatest),
		string(anthropic.ModelClaude3_7Sonnet20250219),
		string(anthropic.ModelClaude3_5HaikuLatest),
		string(anthropic.ModelClaude3_5Haiku20241022),
		string(anthropic.ModelClaudeSonnet4_20250514),
		string(anthropic.ModelClaudeSonnet4_0),
		string(anthropic.ModelClaude4Sonnet20250514),
		string(anthropic.ModelClaude3_5SonnetLatest),
		string(anthropic.ModelClaude3_5Sonnet20241022),
		string(anthropic.ModelClaude_3_5_Sonnet_20240620),
		string(anthropic.ModelClaudeOpus4_0),
		string(anthropic.ModelClaudeOpus4_20250514),
		string(anthropic.ModelClaude4Opus20250514),

		// GCP Vertex AI
		"claude-3-7-sonnet@20250219",
		"claude-3-5-haiku@20241022",
		"claude-sonnet-4@20250514",
		"claude-3-5-sonnet-v2@20241022",
		"claude-opus-4@20250514",

		// AWS Bedrock
		"anthropic.claude-3-7-sonnet-20250219-v1:0",
		"anthropic.claude-3-5-haiku-20241022-v1:0",
		"anthropic.claude-sonnet-4-20250514-v1:0",
		"anthropic.claude-3-5-sonnet-20241022-v2:0",
		"anthropic.claude-opus-4-20250514-v1:0",
	}
}

// Connect creates a live connection to the Claude LLM.
//
// TODO(zchee): implements.
func (m *Claude) Connect(context.Context, *types.LLMRequest) (types.ModelConnection, error) {
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
		Model:     anthropic.Model(m.modelName),
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

	return m.messageToGenerateContentResponse(ctx, resp), nil
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
			Model:     anthropic.Model(m.modelName),
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
